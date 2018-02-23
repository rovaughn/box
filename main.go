package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
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

func emitChunk(w io.Writer, chunk []byte) error {
	n := uint16(len(chunk))
	if int(n) != len(chunk) {
		panic("chunk too big")
	}

	header := make([]byte, 4)
	binary.LittleEndian.PutUint16(header, n)

	if _, err := w.Write(header); err != nil {
		return err
	}

	_, err := w.Write(chunk)
	return err
}

// TODO If no code takes advantage of the appending feature, probably best to remove it.
// TODO this doesn't actually do any appending; and maybe it shouldn't
func readChunk(r io.Reader, chunk []byte) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	n := int(binary.LittleEndian.Uint16(header))

	if n > 0 {
		originalLen := len(chunk)
		chunk = chunk[:originalLen+n]

		if _, err := io.ReadFull(r, chunk[originalLen:]); err != nil {
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

func newPasswordReader(f *os.File) func(string) ([]byte, error) {
	fd := int(f.Fd())
	if terminal.IsTerminal(fd) {
		return func(prompt string) ([]byte, error) {
			if _, err := fmt.Fprint(f, prompt); err != nil {
				return nil, err
			}

			password, err := terminal.ReadPassword(fd)
			if err != nil {
				return nil, err
			}

			if _, err := fmt.Fprint(f, "\n"); err != nil {
				return nil, err
			}

			return password, err
		}
	} else {
		scanner := bufio.NewScanner(f)
		return func(prompt string) ([]byte, error) {
			if _, err := fmt.Fprint(f, prompt); err != nil {
				return nil, err
			}

			if scanner.Scan() {
				if _, err := fmt.Fprint(f, "\n"); err != nil {
					return nil, err
				}

				return scanner.Bytes(), nil
			} else {
				return nil, scanner.Err()
			}
		}
	}
}

func doMain(args []string, in io.Reader, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("Usage: no command given")
	}

	switch args[1] {
	case "seal":
		var askPassword bool
		var passwordFile, from, to, ttyFilename string
		f := flag.NewFlagSet("seal", flag.ExitOnError)
		f.BoolVar(&askPassword, "password", false, "Ask for a password")
		f.StringVar(&passwordFile, "password-file", "", "Use the contents of this file as a password")
		f.StringVar(&from, "from", "", "Box can only be opened by this receiver")
		f.StringVar(&to, "to", "", "Box can only be opened by this receiver")
		f.StringVar(&ttyFilename, "tty", "/dev/tty", "Terminal to read passwords on")
		f.Parse(args[2:])

		if (askPassword || passwordFile != "") && from == "" && to == "" {
			var password []byte

			if askPassword && passwordFile == "" {
				tty, err := os.Open(ttyFilename)
				if err != nil {
					return fmt.Errorf("Opening TTY: %s", err)
				}
				defer tty.Close()

				readPassword := newPasswordReader(tty)

				password1, err := readPassword("Password: ")
				if err != nil {
					return fmt.Errorf("Reading password: %s", err)
				}

				password2, err := readPassword("Confirm password: ")
				if err != nil {
					return fmt.Errorf("Reading password confirmation: %s", err)
				}

				if !bytes.Equal(password1, password2) {
					return fmt.Errorf("Passwords don't match")
				}

				password = []byte(password1)
			} else if !askPassword && passwordFile != "" {
				var err error
				password, err = ioutil.ReadFile(passwordFile)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("Usage: one of -password or -password-file must be given, but not both")
			}

			salt := make([]byte, argonSaltLen)
			if _, err := rand.Read(salt); err != nil {
				return fmt.Errorf("Generating salt: %s", err)
			}

			keySlice := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, uint8(runtime.NumCPU()), 32)

			var key [32]byte
			copy(key[:], keySlice)

			if err := emitChunk(out, []byte("password")); err != nil {
				return fmt.Errorf("Writing box: %s", err)
			}

			paramChunk := make([]byte, argonSaltLen+4+4)
			copy(paramChunk[0:argonSaltLen], salt)
			binary.LittleEndian.PutUint32(paramChunk[argonSaltLen+0:argonSaltLen+4], argonTime)
			binary.LittleEndian.PutUint32(paramChunk[argonSaltLen+4:argonSaltLen+8], argonMemory)
			if err := emitChunk(out, paramChunk); err != nil {
				return fmt.Errorf("Writing box: %s", err)
			}

			message := make([]byte, chunkSize)
			chunk := make([]byte, argonSaltLen+chunkSize+secretbox.Overhead)

			var nonce [24]byte

			for {
				n, err := in.Read(message)
				if n == 0 && err == io.EOF {
					break
				} else if err != nil && err != io.EOF {
					return fmt.Errorf("Reading payload: %s", err)
				}

				if _, err := rand.Read(nonce[:]); err != nil {
					return fmt.Errorf("Generating nonce: %s", err)
				}

				chunk = chunk[:24]
				copy(chunk, nonce[:])
				chunk = secretbox.Seal(chunk, message[:n], &nonce, &key)

				if err := emitChunk(out, chunk); err != nil {
					return fmt.Errorf("Writing box: %s", err)
				}
			}
		} else if !askPassword && passwordFile == "" && from != "" && to == "" {
			panic("unsupported")
		} else if !askPassword && passwordFile == "" && from == "" && to != "" {
			panic("unsupported")
		} else if !askPassword && passwordFile == "" && from != "" && to != "" {
			panic("unsupported")
		} else {
			return fmt.Errorf("-password, -password-file, -from, -to, or -from and -to must be specified")
		}
	case "open":
		var askPassword bool
		var passwordFile, ttyFilename string
		f := flag.NewFlagSet("seal", flag.ExitOnError)
		f.BoolVar(&askPassword, "password", false, "Ask for a password")
		f.StringVar(&passwordFile, "password-file", "", "Use the contents of this file as a password")
		f.StringVar(&ttyFilename, "tty", "/dev/tty", "Terminal to read passwords on")
		f.Parse(args[2:])

		chunk := make([]byte, 0, argonSaltLen+chunkSize+secretbox.Overhead)
		chunk, err := readChunk(in, chunk)
		if err != nil {
			return fmt.Errorf("Reading box: %s", err)
		}

		switch string(chunk) {
		case "password":
			var password []byte

			if askPassword && passwordFile == "" {
				tty, err := os.Open(ttyFilename)
				if err != nil {
					return fmt.Errorf("Opening TTY: %s", err)
				}

				readPassword := newPasswordReader(tty)

				passwordString, err := readPassword("Password: ")
				if err != nil {
					return fmt.Errorf("Reading password: %s", err)
				}

				password = []byte(passwordString)
			} else if !askPassword && passwordFile != "" {
				var err error
				password, err = ioutil.ReadFile(passwordFile)
				if err != nil {
					return fmt.Errorf("Reading password file: %s", err)
				}
			} else if !askPassword && passwordFile == "" {
				return fmt.Errorf("-password or -password-file is needed to decode a password box")
			} else {
				return fmt.Errorf("-password and -password-file cannot be used together")
			}

			chunk, err := readChunk(in, chunk[:0])
			if err != nil {
				return fmt.Errorf("Reading box: %s", err)
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
				chunk, err := readChunk(in, chunk[:0])
				if err == io.EOF {
					break
				} else if err != nil {
					return fmt.Errorf("Reading box: %s", err)
				}

				var nonce [24]byte
				copy(nonce[:], chunk[:24])

				encryptedPayload := chunk[24:]

				payload, ok := secretbox.Open(payload[:0], encryptedPayload, &nonce, &key)
				if !ok {
					return fmt.Errorf("Decryption failed")
				}

				if _, err := out.Write(payload); err != nil {
					return fmt.Errorf("Reading box: %s", err)
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
		return fmt.Errorf("Unknown command %s", args[1])
	}

	return nil
}

func main() {
	if err := doMain(os.Args, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
