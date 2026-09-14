// Package callerapp implements the external-caller process boundary. This
// checkpoint composes caller state, Provider lifecycle work and the live
// Gateway lifecycle but does not execute Provider scenarios.
package callerapp

import (
	"context"
	"io"
	"os"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callercontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerphase"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
)

const (
	ExitSuccess  = 0
	ExitUsage    = 64
	ExitData     = 65
	ExitSoftware = 70
	ExitIO       = 74
)

func Run(arguments []string, stdin io.Reader, stdout io.Writer) int {
	return RunWithCoordinator(context.Background(), arguments, stdin, stdout, nil, nil)
}

// RunWithCoordinator executes one private phase using an injected fixed-sibling
// Gateway service starter. A nil starter fails closed after input validation.
func RunWithCoordinator(ctx context.Context, arguments []string, stdin io.Reader, stdout io.Writer, start callerphase.StartGateway, runProvider callerphase.RunProvider) int {
	if len(arguments) != 0 {
		return ExitUsage
	}
	request, err := callercontrol.DecodeRequest(stdin)
	if err != nil {
		return ExitData
	}
	bundle, err := credentials.NewReader(credentials.Requirements()).Read(request.CredentialChannelDescriptors)
	if err != nil {
		return ExitData
	}
	defer bundle.Destroy()
	if err := credentials.ValidateGatewayIdentityBundle(bundle, request.GatewayProbeEndpoint); err != nil {
		return ExitData
	}
	if err := callerphase.Coordinate(ctx, request, bundle, start, runProvider); err != nil {
		bundle.Destroy()
		return ExitSoftware
	}
	bundle.Destroy()
	result, err := callercontrol.NewResult(request.Phase, os.Getpid())
	if err != nil {
		return ExitData
	}
	if err := callercontrol.EncodeResult(stdout, result); err != nil {
		return ExitIO
	}
	return ExitSuccess
}
