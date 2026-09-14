//go:build darwin || linux

package gatewayservice

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestInheritedCommandPipeSupportsDeadlineAndClose(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	fd, err := syscall.Dup(int(reader.Fd()))
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := OpenCommandPipe(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	if err := pipe.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := pipe.Read(make([]byte, 1)); !os.IsTimeout(err) {
		t.Fatal("inherited read deadline unavailable")
	}
	if err := pipe.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := pipe.Read(make([]byte, 1)); done <- err }()
	_ = pipe.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("close did not reject read")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock inherited reader")
	}
}

func TestOutputPipeDeadlineAndOriginalOwnership(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	pipe, err := DuplicateOutputPipe(writer)
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	if err := pipe.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := pipe.Write(make([]byte, 1<<20)); !os.IsTimeout(err) {
		t.Fatal("backpressured output did not honor deadline")
	}
	_ = pipe.Close()
	if _, err := writer.Stat(); err != nil {
		t.Fatal("duplicated output closed original owner")
	}
	file, err := os.CreateTemp(t.TempDir(), "not-a-pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if pipe, err := DuplicateOutputPipe(file); err == nil {
		_ = pipe.Close()
		t.Fatal("accepted regular output file")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("rejection closed source file")
	}
}
