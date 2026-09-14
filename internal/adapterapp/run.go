// Package adapterapp implements the qualification-adapter process entrypoint.
// Scenario execution remains deliberately unavailable until the independent
// caller and Gateway process protocol is composed.
package adapterapp

import (
	"context"
	"io"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/releaseinfo"
)

type CallerRunner interface {
	Run(context.Context, protocol.Invocation, *credentials.Bundle) error
}

const (
	ExitSuccess  = 0
	ExitUsage    = 64
	ExitSoftware = 70
	ExitIO       = 74
)

// Run emits startup before reading either the invocation or credential bytes.
// A valid invocation is accepted and its credentials are drained and destroyed,
// but all scenarios are honestly reported not_executed in this skeleton.
func Run(arguments []string, stdin io.Reader, stdout io.Writer) int {
	return RunWithCaller(context.Background(), arguments, stdin, stdout, nil)
}

// RunWithCaller adds one separately supervised external-caller process. A nil
// runner retains the fail-closed component-test path.
func RunWithCaller(ctx context.Context, arguments []string, stdin io.Reader, stdout io.Writer, caller CallerRunner) int {
	if len(arguments) != 0 {
		return ExitUsage
	}
	startup, err := protocol.NewStartupIdentity(releaseinfo.Caller(), releaseinfo.Adapter(), credentials.Requirements())
	if err != nil {
		return ExitSoftware
	}
	machine, err := protocol.NewPhaseMachine(stdout, startup)
	if err != nil {
		return ExitSoftware
	}
	if err := machine.Start(); err != nil {
		return ExitIO
	}
	if err := machine.ConsumeInvocation(stdin); err != nil {
		if machine.State() == protocol.StateTerminalObserved {
			return ExitSuccess
		}
		return ExitIO
	}
	invocation, ok := machine.AcceptedInvocation()
	if !ok {
		return ExitSoftware
	}
	if err := machine.AcceptInvocation(); err != nil {
		return ExitIO
	}
	bundle, err := credentials.NewReader(credentials.Requirements()).Read(invocation.CredentialChannelDescriptors)
	if err != nil {
		if machine.Fail("credential_channel_failed") != nil {
			return ExitIO
		}
		return ExitSuccess
	}
	if caller != nil {
		if err := caller.Run(ctx, invocation, bundle); err != nil {
			bundle.Destroy()
			if machine.Fail("caller_start_failed") != nil {
				return ExitIO
			}
			return ExitSuccess
		}
	}
	bundle.Destroy()

	reason := "prerequisite_not_satisfied"
	caseIDs, ok := protocol.CaseIDs(invocation.Phase)
	if !ok {
		return ExitSoftware
	}
	for _, caseID := range caseIDs {
		if err := machine.Result(protocol.ScenarioResultData{
			CaseID: caseID, Disposition: "not_executed", Interactions: []protocol.InteractionResult{},
			Assertions: []protocol.AssertionResult{}, ObservationIDs: []string{}, ReasonCode: &reason,
		}); err != nil {
			return ExitIO
		}
	}
	if err := machine.Finish(); err != nil {
		return ExitIO
	}
	return ExitSuccess
}
