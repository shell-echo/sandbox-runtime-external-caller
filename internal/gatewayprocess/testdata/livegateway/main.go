package main

import (
	"context"
	"io"
	"net"
	"os"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayapp"
)

type echoResolver struct{}

func (echoResolver) Open(ctx context.Context, reference string) (io.ReadWriteCloser, error) {
	if ctx.Err() != nil || reference != "opaque-test-handoff" {
		return nil, gateway.ErrBackendUnavailable
	}
	frontend, backend := net.Pipe()
	go func() {
		defer backend.Close()
		_, _ = io.Copy(backend, backend)
	}()
	return frontend, nil
}

func main() {
	os.Exit(gatewayapp.RunWithResolver(os.Args[1:], os.Stdin, os.Stdout, echoResolver{}))
}
