package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"runtime"
	"syscall"
)

const argonTime = 1
const argonMemory = 64 * 1024
const argonSaltLen = 16
const chunkSize = 16 * 1024

var errUsage = errors.New("Invalid usage")
var errPasswordMismatch = errors.New("Passwords don't match")

func emitChunk(chunk []byte) error {
	n := uint16(len(chunk))
	if int(n) != len(chunk) {
		panic("chunk too big")
	}

	header := make([]byte, 4)
	binary.LittleEndian.PutUint16(header, n)

	if _, err := os.Stdout.Write(header); err != nil {
		return err
	}

	_, err := os.Stdout.Write(chunk)
	return err
}

// TODO If no code takes advantage of the appending feature, probably best to remove it.
// TODO this doesn't actually do any appending; and maybe it shouldn't
func readChunk(chunk []byte) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(os.Stdin, header); err != nil {
		return nil, err
	}

	n := int(binary.LittleEndian.Uint16(header))

	if n > 0 {
		originalLen := len(chunk)
		chunk = chunk[:originalLen+n]

		if _, err := io.ReadFull(os.Stdin, chunk[originalLen:]); err != nil {
			return nil, err
		}
	}

	return chunk, nil
}

type lockFile *os.File

type config struct {
	Version    int `json:"version"`
	Identities map[string]struct {
		Ed25519SecretKey []byte `json:"ed25519_secret_key"`
		Ed25519PublicKey []byte `json:"ed25519_public_key"`
		BoxSecretKey     []byte `json:"box_secret_key"`
		BoxPublicKey     []byte `json:"box_public_key"`
	} `json:"identities"`
	Contacts map[string]struct {
		Ed25519PublicKey []byte `json:"ed25519_public_key"`
		BoxPublicKey     []byte `json:"box_public_key"`
	} `json:"contacts"`
}

func loadConfig() (*config, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}

	// TODO make sure locking is correct in scenario where file doesn't originally exist.

	var config config

	configFile, err := os.Open(path.Join(currentUser.HomeDir, ".box"))
	if os.IsNotExist(err) {
		return &config, nil
	} else if err != nil {
		return nil, err
	}
	defer configFile.Close()

	if err := syscall.Flock(int(configFile.Fd()), syscall.LOCK_SH); err != nil {
		return nil, err
	}
	defer func() {
		if err := syscall.Flock(int(configFile.Fd()), syscall.LOCK_UN); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func doMain(args []string) error {
	if len(args) < 2 {
		return errUsage
	}

	switch args[1] {
	case "seal":
		var askPassword bool
		var passwordFile, from, to string
		f := flag.NewFlagSet("seal", flag.ExitOnError)
		f.BoolVar(&askPassword, "password", false, "Ask for a password")
		f.StringVar(&passwordFile, "password-file", "", "Use the contents of this file as a password")
		f.StringVar(&from, "from", "", "Box can only be opened by this receiver")
		f.StringVar(&to, "to", "", "Box can only be opened by this receiver")
		f.Parse(args[2:])

		if (askPassword || passwordFile != "") && !(askPassword && passwordFile != "") && from == "" && to == "" {
			var password []byte

			if askPassword && passwordFile == "" {
				fmt.Printf("Password: ")
				// TODO will probably fail to read password if piping into stdin
				password1, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return err
				}
				fmt.Printf("\n")

				fmt.Printf("Confirm password: ")
				// TODO will probably fail to read password if piping into stdin
				password2, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return err
				}
				fmt.Printf("\n")

				if !bytes.Equal(password1, password2) {
					return errPasswordMismatch
				}

				password = []byte(password1)
			} else if !askPassword && passwordFile != "" {
				var err error
				password, err = ioutil.ReadFile(passwordFile)
				if err != nil {
					return err
				}
			} else {
				return errUsage
			}

			salt := make([]byte, argonSaltLen)
			if _, err := rand.Read(salt); err != nil {
				return err
			}

			keySlice := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, uint8(runtime.NumCPU()), 32)

			var key [32]byte
			copy(key[:], keySlice)

			if err := emitChunk([]byte("password")); err != nil {
				return err
			}

			paramChunk := make([]byte, argonSaltLen+4+4)
			copy(paramChunk[0:argonSaltLen], salt)
			binary.LittleEndian.PutUint32(paramChunk[argonSaltLen+0:argonSaltLen+4], argonTime)
			binary.LittleEndian.PutUint32(paramChunk[argonSaltLen+4:argonSaltLen+8], argonMemory)
			if err := emitChunk(paramChunk); err != nil {
				return err
			}

			message := make([]byte, chunkSize)
			out := make([]byte, argonSaltLen+chunkSize+secretbox.Overhead)

			var nonce [24]byte

			for {
				n, err := os.Stdin.Read(message)
				if n == 0 && err == io.EOF {
					break
				} else if err != nil && err != io.EOF {
					return err
				}

				if _, err := rand.Read(nonce[:]); err != nil {
					return err
				}

				out = out[:24]
				copy(out, nonce[:])
				out = secretbox.Seal(out, message[:n], &nonce, &key)

				if err := emitChunk(out); err != nil {
					return err
				}
			}
		} else if !askPassword && passwordFile == "" && from != "" && to == "" {
			panic("unsupported")
		} else if !askPassword && passwordFile == "" && from == "" && to != "" {
			panic("unsupported")
		} else if !askPassword && passwordFile == "" && from != "" && to != "" {
			panic("unsupported")
		} else {
			return errUsage
		}
	case "open":
		var askPassword bool
		var passwordFile string
		f := flag.NewFlagSet("seal", flag.ExitOnError)
		f.BoolVar(&askPassword, "password", false, "Ask for a password")
		f.StringVar(&passwordFile, "password-file", "", "Use the contents of this file as a password")
		f.Parse(args[2:])

		chunk := make([]byte, 0, argonSaltLen+chunkSize+secretbox.Overhead)
		chunk, err := readChunk(chunk)
		if err != nil {
			return err
		}

		switch string(chunk) {
		case "password":
			var password []byte

			if askPassword && passwordFile == "" {
				fmt.Printf("Password: ")
				// TODO will probably fail to read password if piping into stdin
				passwordString, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return err
				}
				fmt.Printf("\n")

				password = []byte(passwordString)
			} else if !askPassword && passwordFile != "" {
				var err error
				password, err = ioutil.ReadFile(passwordFile)
				if err != nil {
					return err
				}
			} else {
				return errUsage
			}

			chunk, err := readChunk(chunk[:0])
			if err != nil {
				return err
			}

			if len(chunk) != argonSaltLen+4+4 {
				return fmt.Errorf("Expected parameter chunk to be 24 bytes")
			}

			salt := chunk[0:argonSaltLen]
			time := binary.LittleEndian.Uint32(chunk[argonSaltLen+0 : argonSaltLen+4])
			memory := binary.LittleEndian.Uint32(chunk[argonSaltLen+4 : argonSaltLen+8])

			keySlice := argon2.IDKey(password, salt, time, memory, uint8(runtime.NumCPU()), 32)

			var key [32]byte
			copy(key[:], keySlice)

			payload := make([]byte, 0, 16*1024)

			for {
				chunk, err := readChunk(chunk[:0])
				if err == io.EOF {
					break
				} else if err != nil {
					return err
				}

				var nonce [24]byte
				copy(nonce[:], chunk[:24])

				encryptedPayload := chunk[24:]

				payload, ok := secretbox.Open(payload[:0], encryptedPayload, &nonce, &key)
				if !ok {
					return fmt.Errorf("Decryption failed")
				}

				if _, err := os.Stdout.Write(payload); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("Unsupported box type: %q", chunk)
		}
	case "new-identity":
		panic("unsupported")
	case "list-identities":
		panic("unsupported")
	case "list-contacts":
		panic("unsupported")
	default:
		return errUsage
	}

	return nil
}

func main() {
	if err := doMain(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
