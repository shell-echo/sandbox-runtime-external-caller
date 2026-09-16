//go:build darwin || linux

package gatewaybridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
)

func bridgePair(t *testing.T, ctx context.Context) (*Server, *Resolver) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if syscall.SetNonblock(fd, true) != nil {
			t.Fatal("set nonblock")
		}
	}
	server, err := NewServer(ctx, os.NewFile(uintptr(fds[0]), "bridge-server"))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewResolver(os.NewFile(uintptr(fds[1]), "bridge-resolver"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Close(); _ = server.Close() })
	return server, resolver
}

func TestBridgeCarriesExactBidirectionalBytesOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server, resolver := bridgePair(t, ctx)
	opened := 0
	if err := server.SetOpener(func(openCtx context.Context, reference string) (io.ReadWriteCloser, error) {
		opened++
		if openCtx.Err() != nil || reference != "ref:session:exact" {
			return nil, errors.New("wrong authority")
		}
		front, back := net.Pipe()
		go func() { defer back.Close(); _, _ = io.Copy(back, back) }()
		return front, nil
	}); err != nil {
		t.Fatal(err)
	}
	stream, err := resolver.Open(ctx, "ref:session:exact")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0, 1, 2, 0xff, '\n'}
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("bridge changed bytes")
	}
	if _, err := resolver.Open(ctx, "ref:session:exact"); !errors.Is(err, gateway.ErrBackendUnavailable) {
		t.Fatalf("second open = %v", err)
	}
	if opened != 1 {
		t.Fatalf("opener calls = %d", opened)
	}
	_ = stream.Close()
}

func TestBridgeFailsClosedWithoutOrAfterAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	server, resolver := bridgePair(t, ctx)
	if _, err := resolver.Open(ctx, "ref:session:missing"); !errors.Is(err, gateway.ErrBackendUnavailable) {
		t.Fatalf("missing opener = %v", err)
	}
	<-server.done
	if err := server.SetOpener(func(context.Context, string) (io.ReadWriteCloser, error) { return nil, nil }); err == nil {
		t.Fatal("closed bridge accepted late authority")
	}
}
