package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestInitialPhaseMachineCompletesExactMaximumRecordPath(t *testing.T) {
	machine, output := testBoundMachine(t, "initial")
	for _, caseID := range initialCaseIDs {
		if err := machine.StartScenario(caseID); err != nil {
			t.Fatalf("StartScenario(%q) error = %v", caseID, err)
		}
		if err := machine.Result(completedResult(caseID)); err != nil {
			t.Fatalf("Result(%q) error = %v", caseID, err)
		}
	}
	if err := machine.Finish(); err != nil {
		t.Fatal(err)
	}
	if machine.State() != StateTerminalObserved {
		t.Fatalf("state after Finish = %q", machine.State())
	}
	if stats := machine.Stats(); stats.CompleteRecords != MaxAdapterOutputRecords || stats.WireBytes != output.Len() {
		t.Fatalf("maximum path stats = %#v, output bytes = %d", stats, output.Len())
	}
	if bytes.Count(output.Bytes(), []byte{'\n'}) != MaxAdapterOutputRecords {
		t.Fatalf("record delimiter count = %d", bytes.Count(output.Bytes(), []byte{'\n'}))
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	for index, line := range lines {
		var envelope struct {
			MessageType string `json:"message_type"`
			Sequence    int    `json:"sequence"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatalf("decode output record %d: %v", index, err)
		}
		if envelope.Sequence != index {
			t.Fatalf("output record %d sequence = %d", index, envelope.Sequence)
		}
		wantType := "scenario_started"
		switch {
		case index == 0:
			wantType = "startup_identity"
		case index == 1:
			wantType = "invocation_accepted"
		case index == len(lines)-1:
			wantType = "invocation_finished"
		case index%2 == 1:
			wantType = "scenario_result"
		}
		if envelope.MessageType != wantType {
			t.Fatalf("output record %d message type = %q, want %q", index, envelope.MessageType, wantType)
		}
	}
	if err := machine.ObserveEOF(); err != nil {
		t.Fatal(err)
	}
	if err := machine.ObserveCleanProcessExit(true); err != nil {
		t.Fatal(err)
	}
	if machine.State() != StateComplete {
		t.Fatalf("final state = %q", machine.State())
	}
}

func TestReconstructionNotExecutedPathDerivesStoppedCompletion(t *testing.T) {
	machine, output := testBoundMachine(t, "reconstruction")
	reason := "prerequisite_not_satisfied"
	for _, caseID := range reconstructionCaseIDs {
		if err := machine.Result(ScenarioResultData{CaseID: caseID, Disposition: "not_executed", Interactions: []InteractionResult{}, Assertions: []AssertionResult{}, ObservationIDs: []string{}, ReasonCode: &reason}); err != nil {
			t.Fatalf("Result(%q) error = %v", caseID, err)
		}
	}
	if err := machine.Finish(); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	var terminal InvocationFinished
	if err := json.Unmarshal(lines[len(lines)-1], &terminal); err != nil {
		t.Fatal(err)
	}
	if terminal.Completion != "stopped" || terminal.Sequence != 7 {
		t.Fatalf("terminal = %#v", terminal)
	}
}

func TestUnboundMachineEmitsStartupBeforeLearningPhase(t *testing.T) {
	var output bytes.Buffer
	machine, err := NewPhaseMachine(&output, testStartup(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.Start(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"message_type":"startup_identity"`) {
		t.Fatal("unbound machine did not emit startup before invocation")
	}
	invocation := testInvocation()
	invocation.Phase = "reconstruction"
	invocation.InvocationID = "run.reconstruction"
	if err := machine.ConsumeInvocation(bytes.NewReader(testInvocationJSON(t, invocation))); err != nil {
		t.Fatal(err)
	}
	accepted, ok := machine.AcceptedInvocation()
	if !ok || accepted.Phase != "reconstruction" || accepted.InvocationID != "run.reconstruction" {
		t.Fatalf("accepted invocation = %#v, %v", accepted, ok)
	}
	accepted.CredentialChannelDescriptors[0].ChannelID = "mutated"
	again, ok := machine.AcceptedInvocation()
	if !ok || again.CredentialChannelDescriptors[0].ChannelID == "mutated" {
		t.Fatal("AcceptedInvocation returned mutable machine storage")
	}
	if err := machine.AcceptInvocation(); err != nil {
		t.Fatal(err)
	}
	reason := "prerequisite_not_satisfied"
	if err := machine.Result(ScenarioResultData{
		CaseID: reconstructionCaseIDs[0], Disposition: "not_executed", Interactions: []InteractionResult{},
		Assertions: []AssertionResult{}, ObservationIDs: []string{}, ReasonCode: &reason,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMachineRejectsScenarioOrderAndDispositionMismatch(t *testing.T) {
	machine, _ := testBoundMachine(t, "initial")
	if err := machine.StartScenario(initialCaseIDs[1]); !errors.Is(err, ErrScenarioOrder) || machine.State() != StateFailed {
		t.Fatalf("out-of-order start error/state = %v/%q", err, machine.State())
	}

	machine, _ = testBoundMachine(t, "initial")
	if err := machine.Result(completedResult(initialCaseIDs[0])); !errors.Is(err, ErrInvalidTransition) || machine.State() != StateFailed {
		t.Fatalf("completed-without-start error/state = %v/%q", err, machine.State())
	}

	machine, _ = testBoundMachine(t, "initial")
	if err := machine.StartScenario(initialCaseIDs[0]); err != nil {
		t.Fatal(err)
	}
	reason := "invocation_canceled"
	if err := machine.Result(ScenarioResultData{CaseID: initialCaseIDs[0], Disposition: "not_executed", Interactions: []InteractionResult{}, Assertions: []AssertionResult{}, ObservationIDs: []string{}, ReasonCode: &reason}); !errors.Is(err, ErrInvalidTransition) || machine.State() != StateFailed {
		t.Fatalf("not-executed-after-start error/state = %v/%q", err, machine.State())
	}
}

func TestMachineProtocolErrorBranches(t *testing.T) {
	startup := testStartup(t)
	var preOutput bytes.Buffer
	pre, err := NewPhaseMachine(&preOutput, startup, "initial")
	if err != nil {
		t.Fatal(err)
	}
	if err := pre.Start(); err != nil {
		t.Fatal(err)
	}
	if err := pre.ConsumeInvocation(strings.NewReader(`{"invalid":true}`)); !errors.Is(err, ErrSchema) {
		t.Fatalf("ConsumeInvocation(invalid) error = %v", err)
	}
	if pre.State() != StateTerminalObserved || !strings.Contains(preOutput.String(), `"error_code":"invalid_invocation"`) || !strings.Contains(preOutput.String(), `"invocation_id":null`) {
		t.Fatalf("pre-binding error output/state = %q/%q", preOutput.String(), pre.State())
	}

	post, output := testBoundMachine(t, "initial")
	if err := post.Fail("caller_start_failed"); err != nil {
		t.Fatal(err)
	}
	if post.State() != StateTerminalObserved || !strings.Contains(output.String(), `"sequence":2`) || !strings.Contains(output.String(), `"error_code":"caller_start_failed"`) {
		t.Fatalf("post-binding error output/state = %q/%q", output.String(), post.State())
	}
}

func TestMachineRejectsPhaseAndCredentialBindingBeforeAcceptance(t *testing.T) {
	for _, mutate := range []func(*Invocation){
		func(invocation *Invocation) { invocation.Phase = "reconstruction" },
		func(invocation *Invocation) { invocation.CredentialChannelDescriptors[0].MaxBytes++ },
	} {
		startup := testStartup(t)
		var output bytes.Buffer
		machine, err := NewPhaseMachine(&output, startup, "initial")
		if err != nil {
			t.Fatal(err)
		}
		if err := machine.Start(); err != nil {
			t.Fatal(err)
		}
		invocation := testInvocation()
		mutate(&invocation)
		if err := machine.ConsumeInvocation(bytes.NewReader(testInvocationJSON(t, invocation))); !errors.Is(err, ErrSchema) {
			t.Fatalf("ConsumeInvocation(binding mismatch) error = %v", err)
		}
		if machine.State() != StateTerminalObserved || !strings.Contains(output.String(), `"error_code":"invalid_invocation"`) {
			t.Fatalf("binding mismatch output/state = %q/%q", output.String(), machine.State())
		}
	}
}

func TestMachineRequiresTerminalThenEOFThenCleanExit(t *testing.T) {
	machine, _ := testBoundMachine(t, "reconstruction")
	if err := machine.ObserveEOF(); !errors.Is(err, ErrInvalidTransition) || machine.State() != StateFailed {
		t.Fatalf("early EOF error/state = %v/%q", err, machine.State())
	}

	machine, _ = testBoundMachine(t, "reconstruction")
	if err := machine.Fail("internal_failure"); err != nil {
		t.Fatal(err)
	}
	if err := machine.ObserveEOF(); err != nil {
		t.Fatal(err)
	}
	if err := machine.ObserveCleanProcessExit(false); !errors.Is(err, ErrInvalidTransition) || machine.State() != StateFailed {
		t.Fatalf("non-clean exit error/state = %v/%q", err, machine.State())
	}

	machine, _ = testBoundMachine(t, "reconstruction")
	if err := machine.Fail("internal_failure"); err != nil {
		t.Fatal(err)
	}
	if err := machine.ObserveByteAfterTerminal(); !errors.Is(err, ErrInvalidTransition) || machine.State() != StateFailed {
		t.Fatalf("post-terminal byte error/state = %v/%q", err, machine.State())
	}
}

func TestMachineFailsOnOutputWriteFailure(t *testing.T) {
	machine, err := NewPhaseMachine(partialFailWriter{}, testStartup(t), "initial")
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.Start(); !errors.Is(err, ErrStreamIO) || machine.State() != StateFailed {
		t.Fatalf("Start() error/state = %v/%q", err, machine.State())
	}
	if stats := machine.Stats(); stats.CompleteRecords != 0 || stats.WireBytes != 1 {
		t.Fatalf("partial startup stats = %#v", stats)
	}
}

func testBoundMachine(t *testing.T, phase string) (*PhaseMachine, *bytes.Buffer) {
	t.Helper()
	var output bytes.Buffer
	machine, err := NewPhaseMachine(&output, testStartup(t), phase)
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.Start(); err != nil {
		t.Fatal(err)
	}
	invocation := testInvocation()
	invocation.Phase = phase
	invocation.InvocationID = "run." + phase
	document := testInvocationJSON(t, invocation)
	if err := machine.ConsumeInvocation(bytes.NewReader(document)); err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptInvocation(); err != nil {
		t.Fatal(err)
	}
	return machine, &output
}

func testStartup(t *testing.T) StartupIdentity {
	t.Helper()
	startup, err := NewStartupIdentity(testRelease("caller-v1"), testRelease("adapter-v1"), testRequirements())
	if err != nil {
		t.Fatal(err)
	}
	return startup
}

func completedResult(caseID string) ScenarioResultData {
	return ScenarioResultData{CaseID: caseID, Disposition: "completed", Interactions: []InteractionResult{testInteraction()}, Assertions: []AssertionResult{}, ObservationIDs: []string{}}
}
