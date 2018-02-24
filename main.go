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
	"golang.org/x/crypto/ssh/terminal"
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

type entity struct {
	publicKey *[32]byte
	secretKey *[32]byte
}

func loadEntity(name string) (*entity, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	var entity entity

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "BOX SECRET KEY" {
			var key [32]byte
			copy(key[:], block.Bytes)
			entity.secretKey = &key
		} else if block.Type == "BOX PUBLIC KEY" {
			var key [32]byte
			copy(key[:], block.Bytes)
			entity.publicKey = &key
		}

		data = rest
	}

	return &entity, nil
}

func doMain(args []string) error {
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
		if terminal.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintln(os.Stderr, "Note: reading from stdin")
		}

		if terminal.IsTerminal(int(os.Stdout.Fd())) {
			return fmt.Errorf("stdout is a terminal")
		}

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

		sender, err := loadEntity(path.Join(boxdir, from))
		if err != nil {
			return fmt.Errorf("Loading identity: %s", err)
		}

		if sender.publicKey == nil || sender.secretKey == nil {
			return fmt.Errorf("Sender is not an identity")
		}

		receiver, err := loadEntity(path.Join(boxdir, to))
		if err != nil {
			return fmt.Errorf("Loading peer: %s", err)
		}

		if receiver.publicKey == nil {
			return fmt.Errorf("Receiver is not a peer")
		}

		var sharedKey [32]byte
		box.Precompute(&sharedKey, receiver.publicKey, sender.secretKey)

		buf := make([]byte, maxChunkSize-24-box.Overhead)
		chunk := make([]byte, maxChunkSize)

		for {
			n, err := os.Stdin.Read(buf)
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

			if err := emitChunk(os.Stdout, chunk); err != nil {
				return fmt.Errorf("Emitting chunk: %s", err)
			}
		}
	case "open":
		if terminal.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintln(os.Stderr, "Note: reading from stdin")
		}

		if terminal.IsTerminal(int(os.Stdout.Fd())) {
			return fmt.Errorf("stdout is a terminal")
		}

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

		sender, err := loadEntity(path.Join(boxdir, from))
		if err != nil {
			return fmt.Errorf("Loading peer: %s", err)
		}

		if sender.publicKey == nil {
			return fmt.Errorf("Sender is not a peer")
		}

		receiver, err := loadEntity(path.Join(boxdir, to))
		if err != nil {
			return fmt.Errorf("Loading identity: %s", err)
		}

		if receiver.publicKey == nil || receiver.secretKey == nil {
			return fmt.Errorf("Receiver is not an identity")
		}

		var sharedKey [32]byte
		box.Precompute(&sharedKey, sender.publicKey, receiver.secretKey)

		chunk := make([]byte, maxChunkSize)
		buf := make([]byte, maxChunkSize-24-box.Overhead)

		for {
			n, err := readChunk(os.Stdin, chunk)
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

			if _, err := os.Stdout.Write(buf); err != nil {
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

		publicKey, secretKey, err := box.GenerateKey(bytes.NewReader(seed))
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
			Type:  "BOX SECRET SEED",
			Bytes: seed,
		}); err != nil {
			return err
		}

		if err := pem.Encode(out, &pem.Block{
			Type:  "BOX SECRET KEY",
			Bytes: secretKey[:],
		}); err != nil {
			return err
		}

		if err := pem.Encode(out, &pem.Block{
			Type:  "BOX PUBLIC KEY",
			Bytes: publicKey[:],
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
		var onlyKey bool
		f := flag.NewFlagSet("list", flag.ExitOnError)
		f.BoolVar(&onlyKey, "only-key", false, "Only show public key (for scripts)")
		f.Parse(args[2:])

		names := f.Args()

		type row struct {
			name      string
			kind      string
			publicKey *[32]byte
		}

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

		rows := make([]row, 0)
		longestNameLen := 0

		for _, name := range names {
			if len(name) > longestNameLen {
				longestNameLen = len(name)
			}

			entity, err := loadEntity(path.Join(boxdir, name))
			if err != nil {
				return err
			}

			kind := "none"
			if entity.publicKey != nil && entity.secretKey == nil {
				kind = "peer"
			} else if entity.publicKey != nil && entity.secretKey != nil {
				kind = "identity"
			}

			rows = append(rows, row{
				name:      name,
				kind:      kind,
				publicKey: entity.publicKey,
			})
		}

		if onlyKey {
			for _, row := range rows {
				fmt.Printf("%x\n", *row.publicKey)
			}
		} else {
			fmt.Printf("%-[1]*s  %-8s  %-64s\n", longestNameLen, "NAME", "KIND", "PUBLIC KEY")
			for _, row := range rows {
				fmt.Printf("%-[1]*s  %-8s  %-64x\n", longestNameLen, row.name, row.kind, *row.publicKey)
			}
		}
	default:
		return fmt.Errorf("Unknown command %s", args[1])
	}

	return nil
}

func main() {
	if err := doMain(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
