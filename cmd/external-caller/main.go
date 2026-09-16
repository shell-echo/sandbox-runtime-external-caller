package main

import (
	"context"
	"os"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerapp"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerprovider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayprocess"
)

func main() {
	runner := gatewayprocess.NewSiblingServiceRunner()
	os.Exit(callerapp.RunWithScenarios(context.Background(), os.Args[1:], os.Stdin, os.Stdout, func(origin, endpoint string, bundle *credentials.Bundle, store *callerstate.Store) (callerapp.ScenarioExecutor, error) {
		return callerprovider.NewInitialScenarioExecutorWithGateway(origin, endpoint, bundle, store, func(ctx context.Context, phase, endpoint string, bundle *credentials.Bundle) (callerprovider.ScenarioGateway, error) {
			return runner.Start(ctx, phase, endpoint, bundle)
		})
	}))
}
