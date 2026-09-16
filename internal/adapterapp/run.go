// Package adapterapp implements the qualification-adapter process entrypoint.
// The current operational slice supervises all fifteen initial scenarios and
// all five reconstruction scenarios.
package adapterapp

import (
	"context"
	"io"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/releaseinfo"
)

type CallerRunner interface {
	Start(context.Context, protocol.Invocation, string, *credentials.Bundle) (protocol.ScenarioResultData, error)
	Run(context.Context, string) (protocol.ScenarioResultData, error)
	Close() error
}

type callerFailureCoder interface {
	FailureCode(error) string
}

const (
	ExitSuccess  = 0
	ExitUsage    = 64
	ExitSoftware = 70
	ExitIO       = 74
)

// Run emits startup before reading either the invocation or credential bytes.
// A valid invocation is accepted and its credentials are drained and destroyed.
// Without a caller, all scenarios are honestly reported not_executed.
func Run(arguments []string, stdin io.Reader, stdout io.Writer) int {
	return RunWithCaller(context.Background(), arguments, stdin, stdout, nil)
}

// RunWithCaller adds one separately supervised, fifteen-scenario external-caller
// process. A nil runner retains the fail-closed component-test path.
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
	reason := "prerequisite_not_satisfied"
	caseIDs, ok := protocol.CaseIDs(invocation.Phase)
	if !ok {
		bundle.Destroy()
		return ExitSoftware
	}
	completed := 0
	if caller != nil && (invocation.Phase == "initial" || invocation.Phase == "reconstruction") {
		caseID := caseIDs[0]
		if err := machine.StartScenario(caseID); err != nil {
			bundle.Destroy()
			return ExitIO
		}
		result, err := caller.Start(ctx, invocation, caseID, bundle)
		if err != nil {
			return failCaller(machine, caller, bundle, callerFailureCode(caller, err))
		}
		if result.CaseID != caseID || result.Disposition != "completed" || protocol.ValidateScenarioResultData(invocation.Phase, result) != nil {
			return failCaller(machine, caller, bundle, "scenario_execution_failed")
		}
		if err := machine.Result(result); err != nil {
			_ = caller.Close()
			bundle.Destroy()
			return ExitIO
		}
		limit := 15
		if invocation.Phase == "reconstruction" {
			limit = 5
		}
		for _, nextCaseID := range caseIDs[1:limit] {
			if err := machine.StartScenario(nextCaseID); err != nil {
				_ = caller.Close()
				bundle.Destroy()
				return ExitIO
			}
			result, err = caller.Run(ctx, nextCaseID)
			if err != nil {
				return failCaller(machine, caller, bundle, callerFailureCode(caller, err))
			}
			if result.CaseID != nextCaseID || result.Disposition != "completed" || protocol.ValidateScenarioResultData(invocation.Phase, result) != nil {
				return failCaller(machine, caller, bundle, "scenario_execution_failed")
			}
			if err := machine.Result(result); err != nil {
				_ = caller.Close()
				bundle.Destroy()
				return ExitIO
			}
		}
		if err := caller.Close(); err != nil {
			bundle.Destroy()
			if machine.Fail("internal_failure") != nil {
				return ExitIO
			}
			return ExitSoftware
		}
		completed = limit
	}
	bundle.Destroy()

	for _, caseID := range caseIDs[completed:] {
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

func callerFailureCode(caller CallerRunner, err error) string {
	if coder, ok := caller.(callerFailureCoder); ok {
		if code := coder.FailureCode(err); code == "caller_start_failed" || code == "scenario_execution_failed" || code == "internal_failure" {
			return code
		}
	}
	return "scenario_execution_failed"
}

func failCaller(machine *protocol.PhaseMachine, caller CallerRunner, bundle *credentials.Bundle, failureCode string) int {
	cleanupErr := caller.Close()
	bundle.Destroy()
	if cleanupErr != nil {
		failureCode = "internal_failure"
	}
	if machine.Fail(failureCode) != nil {
		return ExitIO
	}
	if cleanupErr != nil {
		return ExitSoftware
	}
	return ExitSuccess
}
