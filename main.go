package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path"
)

const maxChunkSize = 16 * 1024

func emitChunk(w io.Writer, chunk []byte) error {
	n := uint16(len(chunk))
	if n > maxChunkSize {
		panic("chunk too big")
	}

	var header [4]byte
	binary.LittleEndian.PutUint16(header[:], n)

	if _, err := w.Write(header[:]); err != nil {
		return err
	}

	_, err := w.Write(chunk)
	return err
}

func readChunk(r io.Reader, chunk []byte) (int, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	n := int(binary.LittleEndian.Uint16(header[:]))

	if n > maxChunkSize {
		return 0, fmt.Errorf("Chunk is too big")
	}

	return io.ReadFull(r, chunk[:n])
}

func loadPeer(name string) (*[32]byte, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("Did not find PEM data")
	}

	if block.Type == "BOX SECRET SEED" {
		publicKey, _, err := box.GenerateKey(bytes.NewReader(block.Bytes))
		return publicKey, err
	} else if block.Type == "BOX PUBLIC KEY" {
		var publicKey [32]byte
		copy(publicKey[:], block.Bytes)
		return &publicKey, nil
	} else {
		return nil, fmt.Errorf("Expected peer to have BOX SECRET SEED or BOX PUBLIC KEY blocks")
	}
}

func loadIdentity(name string) (*[32]byte, *[32]byte, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("Did not find PEM data")
	}

	if block.Type != "BOX SECRET SEED" {
		return nil, nil, fmt.Errorf("Expected identity file to contain BOX SECRET SEED")
	}

	return box.GenerateKey(bytes.NewReader(block.Bytes))
}

func doMain(args []string, in io.Reader, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("Usage: no command given")
	}

	boxdir := os.Getenv("BOXDIR")
	if boxdir == "" {
		current, err := user.Current()
		if err != nil {
			return fmt.Errorf("Getting current user: %s", err)
		}

		boxdir = path.Join(current.HomeDir, ".box")
	}

	switch args[1] {
	case "seal":
		var from, to string
		f := flag.NewFlagSet("seal", flag.ExitOnError)
		f.StringVar(&from, "from", "self", "Box is authenticated as coming from this identity")
		f.StringVar(&to, "to", "", "Box can only be opened by this peer")
		f.Parse(args[2:])

		if from == "" {
			return fmt.Errorf("-from required")
		}

		if to == "" {
			return fmt.Errorf("-to required")
		}

		_, senderSecretKey, err := loadIdentity(path.Join(boxdir, from))
		if err != nil {
			return fmt.Errorf("Loading identity: %s", err)
		}

		receiverPublicKey, err := loadPeer(path.Join(boxdir, to))
		if err != nil {
			return fmt.Errorf("Loading peer: %s", err)
		}

		var sharedKey [32]byte
		box.Precompute(&sharedKey, receiverPublicKey, senderSecretKey)

		buf := make([]byte, maxChunkSize-24-box.Overhead)
		chunk := make([]byte, maxChunkSize)

		for {
			n, err := in.Read(buf)
			if n == 0 && err == io.EOF {
				break
			} else if err != nil && err != io.EOF {
				return fmt.Errorf("Reading chunk: %s", err)
			}

			var nonce [24]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return fmt.Errorf("Creating nonce: %s", err)
			}

			chunk = chunk[:0]
			chunk = append(chunk, nonce[:]...)
			chunk = box.SealAfterPrecomputation(chunk, buf[:n], &nonce, &sharedKey)

			if err := emitChunk(out, chunk); err != nil {
				return fmt.Errorf("Emitting chunk: %s", err)
			}
		}
	case "open":
		var from, to string
		f := flag.NewFlagSet("open", flag.ExitOnError)
		f.StringVar(&from, "from", "", "Box originates from this peer")
		f.StringVar(&to, "to", "self", "Box is intended to be received by this identity.")
		f.Parse(args[2:])

		if from == "" {
			return fmt.Errorf("-from required")
		}

		if to == "" {
			return fmt.Errorf("-to required")
		}

		senderPublicKey, err := loadPeer(path.Join(boxdir, from))
		if err != nil {
			return fmt.Errorf("Loading peer: %s", err)
		}

		_, receiverSecretKey, err := loadIdentity(path.Join(boxdir, to))
		if err != nil {
			return fmt.Errorf("Loading identity: %s", err)
		}

		var sharedKey [32]byte
		box.Precompute(&sharedKey, senderPublicKey, receiverSecretKey)

		chunk := make([]byte, maxChunkSize)
		buf := make([]byte, maxChunkSize-24-box.Overhead)

		for {
			n, err := readChunk(in, chunk)
			if err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("Reading sealed chunk: %s", err)
			}

			if n < 24 {
				return fmt.Errorf("Chunk is too small")
			}

			var nonce [24]byte
			copy(nonce[:], chunk[:24])

			buf, ok := box.OpenAfterPrecomputation(buf[:0], chunk[24:n], &nonce, &sharedKey)
			if !ok {
				return fmt.Errorf("Failed to unseal chunk")
			}

			if _, err := out.Write(buf); err != nil {
				return fmt.Errorf("Writing out message: %s", err)
			}
		}
	case "new-identity":
		var name string
		f := flag.NewFlagSet("new-identity", flag.ExitOnError)
		f.StringVar(&name, "name", "self", "Name of identity to create.")
		f.Parse(args[2:])

		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return err
		}

		if err := os.MkdirAll(boxdir, 0700); err != nil {
			return err
		}

		out, err := os.OpenFile(path.Join(boxdir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			return err
		}
		defer out.Close()

		if err := pem.Encode(out, &pem.Block{
			Type:  "BOX SECRET SEED",
			Bytes: seed,
		}); err != nil {
			return err
		}
	case "add-peer":
		var name, publicKeyHex string
		f := flag.NewFlagSet("add-peer", flag.ExitOnError)
		f.StringVar(&name, "name", "self", "Name of peer to add")
		f.StringVar(&publicKeyHex, "key", "", "Public key of peer")
		f.Parse(args[2:])

		publicKey, err := hex.DecodeString(publicKeyHex)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(boxdir, 0700); err != nil {
			return err
		}

		out, err := os.OpenFile(path.Join(boxdir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			return err
		}
		defer out.Close()

		if err := pem.Encode(out, &pem.Block{
			Type:  "BOX PUBLIC KEY",
			Bytes: publicKey,
		}); err != nil {
			return err
		}
	case "list":
		names := args[2:]

		if len(names) == 0 {
			dir, err := os.Open(boxdir)
			if os.IsNotExist(err) {
				return nil
			} else if err != nil {
				return fmt.Errorf("Opening %s: %s", boxdir, err)
			}

			names, err = dir.Readdirnames(-1)
			if err != nil {
				return fmt.Errorf("Reading entries in %s: %s", boxdir, err)
			}
		}

		for _, name := range names {
			publicKey, err := loadPeer(path.Join(boxdir, name))
			if err != nil {
				return fmt.Errorf("Loading peer %s: %s", name, err)
			}

			fmt.Printf("%s %x\n", name, publicKey[:])
		}
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
