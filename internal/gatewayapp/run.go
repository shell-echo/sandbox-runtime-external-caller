// Package gatewayapp implements the private caller-Gateway process boundary.
// The finite validation bootstrap and live service have distinct private IDs.
package gatewayapp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewaybridge"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewaycontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayservice"
)

const (
	ExitSuccess  = 0
	ExitUsage    = 64
	ExitData     = 65
	ExitSoftware = 70
	ExitIO       = 74
)

func Run(arguments []string, stdin io.Reader, stdout io.Writer) int {
	return RunWithResolver(arguments, stdin, stdout, gatewayservice.UnavailableResolver{})
}

// RunWithResolver is an application composition boundary, not a wire-selected
// backend. Tests may inject a resolver; production service v2 obtains only its
// Caller bridge from the separately declared inherited descriptor.
func RunWithResolver(arguments []string, stdin io.Reader, stdout io.Writer, resolver gateway.Resolver) int {
	if len(arguments) != 0 {
		return ExitUsage
	}
	if stdin == nil {
		return ExitData
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, gatewayservice.MaxBootstrapBytes+1))
	if err != nil || len(raw) > gatewayservice.MaxBootstrapBytes {
		return ExitData
	}
	var routing struct {
		ProtocolID string `json:"protocol_id"`
	}
	if json.Unmarshal(raw, &routing) != nil {
		return ExitData
	}
	if routing.ProtocolID == gatewayservice.ProtocolID || routing.ProtocolID == gatewayservice.TerminalProtocolID {
		return runService(raw, stdout, resolver)
	}
	request, err := gatewaycontrol.DecodeRequest(bytes.NewReader(raw))
	if err != nil {
		return ExitData
	}
	bundle, err := credentials.NewReader(credentials.GatewayRequirements()).Read(request.CredentialChannelDescriptors)
	if err != nil {
		return ExitData
	}
	defer bundle.Destroy()
	identity, err := credentials.BuildGatewayServerIdentityFromBundle(bundle, request.GatewayProbeEndpoint)
	if err != nil {
		return ExitData
	}
	identity.Destroy()
	bundle.Destroy()
	result, err := gatewaycontrol.NewResult(request.Phase, os.Getpid())
	if err != nil {
		return ExitData
	}
	if err := gatewaycontrol.EncodeResult(stdout, result); err != nil {
		return ExitIO
	}
	return ExitSuccess
}

func runService(raw []byte, stdout io.Writer, resolver gateway.Resolver) int {
	bootstrap, err := gatewayservice.DecodeBootstrap(raw)
	if err != nil {
		return ExitData
	}
	commands, err := gatewayservice.OpenCommandPipe(bootstrap.ControlDescriptor)
	if err != nil {
		return ExitData
	}
	defer commands.Close()
	if bootstrap.ProtocolID == gatewayservice.TerminalProtocolID {
		backend, err := gatewayservice.OpenBackendPipe(bootstrap.BackendDescriptor)
		if err != nil {
			return ExitData
		}
		if _, unavailable := resolver.(gatewayservice.UnavailableResolver); unavailable {
			bridge, err := gatewaybridge.NewResolver(backend)
			if err != nil {
				_ = backend.Close()
				return ExitData
			}
			resolver = bridge
		} else {
			// Test-only injected resolvers never receive the production bridge.
			_ = backend.Close()
		}
	}
	if file, ok := stdout.(*os.File); ok {
		pipe, err := gatewayservice.DuplicateOutputPipe(file)
		if err != nil {
			return ExitData
		}
		defer pipe.Close()
		stdout = pipe
	}
	bundle, err := credentials.NewReader(credentials.GatewayRequirements()).Read(bootstrap.Bootstrap.CredentialChannelDescriptors)
	if err != nil {
		return ExitData
	}
	defer bundle.Destroy()
	identity, err := credentials.BuildGatewayServerIdentityFromBundle(bundle, bootstrap.Bootstrap.GatewayProbeEndpoint)
	if err != nil {
		return ExitData
	}
	defer identity.Destroy()
	bundle.Destroy()
	if gatewayservice.Serve(context.Background(), bootstrap, identity, commands, stdout, resolver) != nil {
		return ExitSoftware
	}
	return ExitSuccess
}
