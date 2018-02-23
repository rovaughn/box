package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"
)

type errgroup struct {
	group sync.WaitGroup
	done  chan error
}

func newErrgroup(timeout time.Duration) *errgroup {
	group := &errgroup{
		done: make(chan error),
	}
	go func() {
		time.Sleep(timeout)
		group.done <- fmt.Errorf("Timed out")
	}()
	return group
}

func (g *errgroup) do(f func() error) {
	g.group.Add(1)
	go func() {
		defer g.group.Done()
		if err := f(); err != nil {
			g.done <- err
		}
	}()
}

func (g *errgroup) wait() error {
	go func() {
		g.group.Wait()
		g.done <- nil
	}()
	return <-g.done
}

func TestSealPasswordFile(t *testing.T) {
	testPayload := []byte("attack at dawn")
	testPassword := []byte("hunter2")

	box := func() []byte {
		rpass, wpass, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}

		rpayload, wpayload, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}

		rbox, wbox, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}

		group := newErrgroup(time.Second)
		group.do(func() error {
			if _, err := wpass.Write(testPassword); err != nil {
				return err
			}
			return wpass.Close()
		})

		group.do(func() error {
			if _, err := wpayload.Write(testPayload); err != nil {
				return err
			}
			return wpayload.Close()
		})

		group.do(func() error {
			originalStdin := os.Stdin
			defer func() { os.Stdin = originalStdin }()
			os.Stdin = rpayload

			originalStdout := os.Stdout
			defer func() { os.Stdout = originalStdout }()
			os.Stdout = wbox

			if err := doMain([]string{"box", "seal", "-password-file", fmt.Sprintf("/dev/fd/%d", rpass.Fd())}); err != nil {
				return err
			}

			return wbox.Close()
		})

		var box []byte

		group.do(func() error {
			var err error
			box, err = ioutil.ReadAll(rbox)
			return err
		})

		if err := group.wait(); err != nil {
			t.Fatal(err)
		}

		return box
	}()

	rpass, wpass, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	rpayload, wpayload, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	rbox, wbox, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	group := newErrgroup(time.Second)
	group.do(func() error {
		if _, err := wpass.Write(testPassword); err != nil {
			return err
		}
		return wpass.Close()
	})

	group.do(func() error {
		if _, err := wbox.Write(box); err != nil {
			return err
		}
		return wbox.Close()
	})

	group.do(func() error {
		originalStdin := os.Stdin
		defer func() { os.Stdin = originalStdin }()
		os.Stdin = rbox

		originalStdout := os.Stdout
		defer func() { os.Stdout = originalStdout }()
		os.Stdout = wpayload

		if err := doMain([]string{"box", "open", "-password-file", fmt.Sprintf("/dev/fd/%d", rpass.Fd())}); err != nil {
			return err
		}

		return wpayload.Close()
	})

	var payload []byte

	group.do(func() error {
		var err error
		payload, err = ioutil.ReadAll(rpayload)
		return err
	})

	if err := group.wait(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(payload, testPayload) {
		t.Fatalf("Payload is wrong; got %q, expected %q", payload, testPayload)
	}
}
