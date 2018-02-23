package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
)

func box(r io.Reader, w io.Writer, args ...string) error {
	newArgs := make([]string, 0, 1+len(args))
	newArgs = append(newArgs, "box")
	newArgs = append(newArgs, args...)
	return doMain(newArgs, r, w)
}

func TestPassword(t *testing.T) {
	rpass1, wpass1, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rpass1.Close()
	defer wpass1.Close()

	expectRead := func(t *testing.T, r io.Reader, s string) error {
		t.Helper()
		buf := make([]byte, len(s))
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		if !bytes.Equal(buf, []byte(s)) {
			return fmt.Errorf("Expected to read %q, not %q", s, buf)
		}
		return nil
	}

	go func() {
		if err := expectRead(t, wpass1, "Password: "); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(wpass1, "hunter2"); err != nil {
			t.Fatal(err)
		}
		if err := expectRead(t, wpass1, "\nConfirm password: "); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(wpass1, "hunter2"); err != nil {
			t.Fatal(err)
		}
		if err := expectRead(t, wpass1, "\n"); err != nil {
			t.Fatal(err)
		}
	}()

	message := []byte("attack at dawn")

	var sealed bytes.Buffer
	if err := box(bytes.NewReader(message), &sealed, "seal", "-password", "-tty", fmt.Sprintf("/dev/fd/%d", rpass1.Fd())); err != nil {
		t.Fatal(err)
	}

	rpass2, wpass2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rpass2.Close()
	defer wpass2.Close()

	go func() {
		if err := expectRead(t, wpass2, "Password: "); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(wpass2, "hunter2"); err != nil {
			t.Fatal(err)
		}
		if err := expectRead(t, wpass2, "\n"); err != nil {
			t.Fatal(err)
		}
	}()

	var unsealed bytes.Buffer
	if err := box(bytes.NewReader(sealed.Bytes()), &unsealed, "open", "-password", "-tty", fmt.Sprintf("/dev/fd/%d", rpass2.Fd())); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, unsealed.Bytes()) {
		t.Fatalf("Expected unsealed payload to be %q, not %q", message, unsealed.Bytes())
	}
}

func TestPasswordFile(t *testing.T) {
	rpass1, wpass1, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rpass1.Close()
	defer wpass1.Close()

	go func() {
		if _, err := fmt.Fprintln(wpass1, "hunter2"); err != nil {
			t.Fatal(err)
		}
		if err := wpass1.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	message := []byte("attack at dawn")

	var sealed bytes.Buffer
	if err := box(bytes.NewReader(message), &sealed, "seal", "-password-file", fmt.Sprintf("/dev/fd/%d", rpass1.Fd())); err != nil {
		t.Fatal(err)
	}

	rpass2, wpass2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rpass2.Close()
	defer wpass2.Close()

	go func() {
		if _, err := fmt.Fprintln(wpass2, "hunter2"); err != nil {
			t.Fatal(err)
		}
		if err := wpass2.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	var unsealed bytes.Buffer
	if err := box(bytes.NewReader(sealed.Bytes()), &unsealed, "open", "-password-file", fmt.Sprintf("/dev/fd/%d", rpass2.Fd())); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, unsealed.Bytes()) {
		t.Fatalf("Expected unsealed payload to be %q, not %q", message, unsealed.Bytes())
	}
}
