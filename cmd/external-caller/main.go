package main

import (
	"context"
	"os"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerapp"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerphase"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerprovider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayprocess"
)

func main() {
	runner := gatewayprocess.NewSiblingServiceRunner()
	start := func(ctx context.Context, phase, endpoint string, bundle *credentials.Bundle) (callerphase.GatewayService, error) {
		return runner.Start(ctx, phase, endpoint, bundle)
	}
	os.Exit(callerapp.RunWithCoordinator(context.Background(), os.Args[1:], os.Stdin, os.Stdout, start, callerprovider.Run))
}
