//go:build darwin || linux

package adapterapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func TestRunEmitsStartupBeforeInputAndStopsWithoutScenarioClaims(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	invocation := testInvocation(descriptors)
	document, err := json.Marshal(invocation)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var writersDone sync.WaitGroup
	input := &startupOrderingReader{
		document: bytes.NewReader(document), output: &output,
		onFirstRead: func() {
			for index, writer := range writers {
				writersDone.Add(1)
				go func(index int, writer *os.File) {
					defer writersDone.Done()
					_, _ = writer.Write([]byte{byte(index + 1)})
					_ = writer.Close()
				}(index, writer)
			}
		},
	}

	if code := Run(nil, input, &output); code != ExitSuccess {
		t.Fatalf("Run() exit code = %d", code)
	}
	writersDone.Wait()

	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 18 {
		t.Fatalf("adapter record count = %d", len(lines))
	}
	for index, line := range lines {
		var envelope struct {
			MessageType string  `json:"message_type"`
			Sequence    int     `json:"sequence"`
			Disposition string  `json:"disposition"`
			ReasonCode  *string `json:"reason_code"`
			Completion  string  `json:"completion"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
		if envelope.Sequence != index {
			t.Fatalf("record %d sequence = %d", index, envelope.Sequence)
		}
		switch {
		case index == 0 && envelope.MessageType != "startup_identity":
			t.Fatalf("first record type = %q", envelope.MessageType)
		case index == 1 && envelope.MessageType != "invocation_accepted":
			t.Fatalf("second record type = %q", envelope.MessageType)
		case index >= 2 && index < len(lines)-1:
			if envelope.MessageType != "scenario_result" || envelope.Disposition != "not_executed" || envelope.ReasonCode == nil || *envelope.ReasonCode != "prerequisite_not_satisfied" {
				t.Fatalf("scenario record %d = %#v", index, envelope)
			}
		case index == len(lines)-1 && (envelope.MessageType != "invocation_finished" || envelope.Completion != "stopped"):
			t.Fatalf("terminal record = %#v", envelope)
		}
	}
}

func TestRunRejectsArgumentsBeforeAnyOutput(t *testing.T) {
	var output bytes.Buffer
	if code := Run([]string{"forbidden"}, bytes.NewReader(nil), &output); code != ExitUsage {
		t.Fatalf("Run(arguments) exit code = %d", code)
	}
	if output.Len() != 0 {
		t.Fatalf("argument rejection output = %q", output.Bytes())
	}
}

func TestRunReportsInvalidInvocationAsTerminalProtocolRecord(t *testing.T) {
	var output bytes.Buffer
	if code := Run(nil, bytes.NewReader([]byte(`{"unknown":true}`)), &output); code != ExitSuccess {
		t.Fatalf("Run(invalid invocation) exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 2 || !bytes.Contains(lines[0], []byte(`"message_type":"startup_identity"`)) || !bytes.Contains(lines[1], []byte(`"error_code":"invalid_invocation"`)) {
		t.Fatalf("invalid invocation output = %q", output.Bytes())
	}
}

func TestRunWithCallerReportsScenarioFailureAfterStartAndDestroysForwardedSecrets(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &failingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	if runner.phase != "initial" || len(runner.retainedSecret) != 1 || runner.retainedSecret[0] != 0 {
		t.Fatalf("caller invocation/secret after failure = %q / %v", runner.phase, runner.retainedSecret)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 4 || !bytes.Contains(lines[2], []byte(`"message_type":"scenario_started"`)) || !bytes.Contains(lines[3], []byte(`"error_code":"scenario_execution_failed"`)) || bytes.Contains(output.Bytes(), []byte(`"scenario_result"`)) {
		t.Fatalf("caller failure output = %q", output.Bytes())
	}
}

func TestRunWithCallerMapsStartAndCleanupFailuresWithoutPrivateDetail(t *testing.T) {
	for _, test := range []struct {
		name     string
		runner   *mappedFailureCallerRunner
		wantExit int
		wantCode string
	}{
		{name: "caller start", runner: &mappedFailureCallerRunner{failureCode: "caller_start_failed"}, wantExit: ExitSuccess, wantCode: "caller_start_failed"},
		{name: "cleanup uncertainty", runner: &mappedFailureCallerRunner{failureCode: "scenario_execution_failed", closeErr: errors.New("private cleanup detail")}, wantExit: ExitSoftware, wantCode: "internal_failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptors, writers := testCredentialPipes(t)
			document, err := json.Marshal(testInvocation(descriptors))
			if err != nil {
				t.Fatal(err)
			}
			for index, writer := range writers {
				go func(index int, writer *os.File) {
					_, _ = writer.Write([]byte{byte(index + 1)})
					_ = writer.Close()
				}(index, writer)
			}
			var output bytes.Buffer
			if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, test.runner); code != test.wantExit {
				t.Fatalf("RunWithCaller() exit code = %d, want %d", code, test.wantExit)
			}
			lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
			if !test.runner.closed || len(lines) != 4 || !bytes.Contains(lines[3], []byte(`"error_code":"`+test.wantCode+`"`)) || bytes.Contains(output.Bytes(), []byte("private cleanup detail")) {
				t.Fatalf("mapped failure = runner %#v output %q", test.runner, output.Bytes())
			}
		})
	}
}

func TestRunWithCallerEmitsEachStartBeforeAllFifteenInitialScenarios(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	var output bytes.Buffer
	runner := &successfulOrderingCallerRunner{output: &output}
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	assertCompletedAdapterTranscript(t, output.Bytes(), "initial", 15)
	if !runner.called || !runner.sawStarted || !runner.sawSecondStarted || !runner.sawThirdStarted || !runner.sawFourthStarted || !runner.sawFifthStarted || !runner.sawSixthStarted || !runner.sawSeventhStarted || !runner.sawEighthStarted || !runner.sawNinthStarted || !runner.sawTenthStarted || !runner.sawEleventhStarted || !runner.sawTwelfthStarted || !runner.sawThirteenthStarted || !runner.sawFourteenthStarted || !runner.sawFifteenthStarted || runner.runCalls != 14 {
		t.Fatalf("runner did not observe all fifteen ordered starts: %#v", runner)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 33 || !bytes.Contains(lines[28], []byte(`"case_id":"initial.provider-cross-tenant-artifact-rejection"`)) || !bytes.Contains(lines[29], []byte(`"error_code":"SANDBOX_NOT_FOUND"`)) || !bytes.Contains(lines[30], []byte(`"case_id":"initial.provider-mtls-caller-binding-rejection"`)) || !bytes.Contains(lines[31], []byte(`"error_code":"SANDBOX_FORBIDDEN"`)) || !bytes.Contains(lines[32], []byte(`"completion":"completed"`)) {
		t.Fatalf("successful caller output = %q", output.Bytes())
	}
}

func TestRunWithCallerExecutesAllAuthorizedReconstructionCases(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	invocation := testInvocation(descriptors)
	invocation.InvocationID = "run.reconstruction"
	invocation.Phase = "reconstruction"
	document, err := json.Marshal(invocation)
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	var output bytes.Buffer
	runner := &reconstructionOrderingCallerRunner{output: &output}
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	assertCompletedAdapterTranscript(t, output.Bytes(), "reconstruction", 5)
	if !runner.startedAfterRecord || !runner.secondStartedAfterRecord || !runner.thirdStartedAfterRecord || !runner.fourthStartedAfterRecord || !runner.fifthStartedAfterRecord || !runner.closed || runner.runCalls != 4 {
		t.Fatalf("reconstruction runner = %#v", runner)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 13 || !bytes.Contains(lines[2], []byte(`"case_id":"reconstruction.locked-capability-discovery"`)) || !bytes.Contains(lines[3], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[4], []byte(`"case_id":"reconstruction.durable-lifecycle"`)) || !bytes.Contains(lines[5], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[6], []byte(`"case_id":"reconstruction.retained-exec-usage-and-artifact-evidence"`)) || !bytes.Contains(lines[7], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[8], []byte(`"case_id":"reconstruction.durable-opaque-handoff"`)) || !bytes.Contains(lines[9], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[10], []byte(`"case_id":"reconstruction.same-shell-reconnect"`)) || !bytes.Contains(lines[11], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[12], []byte(`"completion":"completed"`)) {
		t.Fatalf("reconstruction output = %q", output.Bytes())
	}
}

func TestRunWithCallerClosesSessionWhenFifthScenarioFails(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &fifthFailingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if !runner.closed || runner.calls != 4 || len(lines) != 12 || !bytes.Contains(lines[10], []byte(`"case_id":"initial.exec-result-and-usage-evidence"`)) || !bytes.Contains(lines[11], []byte(`"error_code":"scenario_execution_failed"`)) {
		t.Fatalf("fifth scenario failure = closed %t, calls %d, output %q", runner.closed, runner.calls, output.Bytes())
	}
}

func TestRunWithCallerClosesSessionWhenSixthScenarioFails(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &sixthFailingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if !runner.closed || runner.calls != 5 || len(lines) != 14 || !bytes.Contains(lines[12], []byte(`"case_id":"initial.stale-fencing-rejection"`)) || !bytes.Contains(lines[13], []byte(`"error_code":"scenario_execution_failed"`)) {
		t.Fatalf("sixth scenario failure = closed %t, calls %d, output %q", runner.closed, runner.calls, output.Bytes())
	}
}

func TestRunWithCallerClosesSessionWhenSeventhScenarioFails(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &seventhFailingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if !runner.closed || runner.calls != 6 || len(lines) != 16 || !bytes.Contains(lines[14], []byte(`"case_id":"initial.exec-cancellation"`)) || !bytes.Contains(lines[15], []byte(`"error_code":"scenario_execution_failed"`)) {
		t.Fatalf("seventh scenario failure = closed %t, calls %d, output %q", runner.closed, runner.calls, output.Bytes())
	}
}

func TestRunWithCallerClosesSessionWhenEighthScenarioFails(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &eighthFailingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if !runner.closed || runner.calls != 7 || len(lines) != 18 || !bytes.Contains(lines[16], []byte(`"case_id":"initial.terminal-session-and-opaque-handoff"`)) || !bytes.Contains(lines[17], []byte(`"error_code":"scenario_execution_failed"`)) {
		t.Fatalf("eighth scenario failure = closed %t, calls %d, output %q", runner.closed, runner.calls, output.Bytes())
	}
}

func TestRunWithCallerClosesSessionWhenNinthScenarioFails(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &ninthFailingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if !runner.closed || runner.calls != 8 || len(lines) != 20 || !bytes.Contains(lines[18], []byte(`"case_id":"initial.gateway-terminal-byte-round-trip"`)) || !bytes.Contains(lines[19], []byte(`"error_code":"scenario_execution_failed"`)) {
		t.Fatalf("ninth scenario failure = closed %t, calls %d, output %q", runner.closed, runner.calls, output.Bytes())
	}
}

func TestRunWithCallerClosesSessionWhenTwelfthScenarioFails(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &twelfthFailingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if !runner.closed || runner.calls != 11 || len(lines) != 26 || !bytes.Contains(lines[24], []byte(`"case_id":"initial.gateway-revocation"`)) || !bytes.Contains(lines[25], []byte(`"error_code":"scenario_execution_failed"`)) {
		t.Fatalf("twelfth scenario failure = closed %t, calls %d, output %q", runner.closed, runner.calls, output.Bytes())
	}
}

func TestRunWithCallerClosesSessionWhenFourthScenarioFails(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &fourthFailingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if !runner.closed || runner.calls != 3 || len(lines) != 10 || !bytes.Contains(lines[8], []byte(`"case_id":"initial.lifecycle-completion-and-status"`)) || !bytes.Contains(lines[9], []byte(`"error_code":"scenario_execution_failed"`)) {
		t.Fatalf("fourth scenario failure = closed %t, calls %d, output %q", runner.closed, runner.calls, output.Bytes())
	}
}

func TestRunWithCallerClosesSessionWhenSecondScenarioFails(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &secondFailingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if !runner.closed || len(lines) != 6 || !bytes.Contains(lines[4], []byte(`"case_id":"initial.protected-lifecycle-create"`)) || !bytes.Contains(lines[5], []byte(`"error_code":"scenario_execution_failed"`)) {
		t.Fatalf("second scenario failure = closed %t, output %q", runner.closed, output.Bytes())
	}
}

func TestRunWithCallerClosesSessionWhenThirdScenarioFails(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &thirdFailingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if !runner.closed || runner.calls != 2 || len(lines) != 8 || !bytes.Contains(lines[6], []byte(`"case_id":"initial.replay-semantics"`)) || !bytes.Contains(lines[7], []byte(`"error_code":"scenario_execution_failed"`)) {
		t.Fatalf("third scenario failure = closed %t, calls %d, output %q", runner.closed, runner.calls, output.Bytes())
	}
}

type failingCallerRunner struct {
	phase          string
	retainedSecret []byte
}

type successfulOrderingCallerRunner struct {
	output               *bytes.Buffer
	called               bool
	sawStarted           bool
	sawSecondStarted     bool
	sawThirdStarted      bool
	sawFourthStarted     bool
	sawFifthStarted      bool
	sawSixthStarted      bool
	sawSeventhStarted    bool
	sawEighthStarted     bool
	sawNinthStarted      bool
	sawTenthStarted      bool
	sawEleventhStarted   bool
	sawTwelfthStarted    bool
	sawThirteenthStarted bool
	sawFourteenthStarted bool
	sawFifteenthStarted  bool
	runCalls             int
}

type reconstructionOrderingCallerRunner struct {
	output                   *bytes.Buffer
	startedAfterRecord       bool
	secondStartedAfterRecord bool
	thirdStartedAfterRecord  bool
	fourthStartedAfterRecord bool
	fifthStartedAfterRecord  bool
	closed                   bool
	runCalls                 int
}

func (runner *reconstructionOrderingCallerRunner) Start(_ context.Context, invocation protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	runner.startedAfterRecord = invocation.Phase == "reconstruction" && caseID == "reconstruction.locked-capability-discovery" && bytes.Contains(runner.output.Bytes(), []byte(`"message_type":"scenario_started"`))
	return reconstructionCapabilityScenarioData(caseID), nil
}

func (runner *reconstructionOrderingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.runCalls++
	if runner.runCalls == 1 {
		runner.secondStartedAfterRecord = caseID == "reconstruction.durable-lifecycle" && bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"reconstruction.durable-lifecycle"`))
		return reconstructionLifecycleScenarioData(caseID), nil
	}
	if runner.runCalls == 2 {
		runner.thirdStartedAfterRecord = caseID == "reconstruction.retained-exec-usage-and-artifact-evidence" && bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"reconstruction.retained-exec-usage-and-artifact-evidence"`))
		return reconstructionEvidenceScenarioData(caseID), nil
	}
	if runner.runCalls == 3 {
		runner.fourthStartedAfterRecord = caseID == "reconstruction.durable-opaque-handoff" && bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"reconstruction.durable-opaque-handoff"`))
		return reconstructionHandoffScenarioData(caseID), nil
	}
	runner.fifthStartedAfterRecord = caseID == "reconstruction.same-shell-reconnect" && bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"reconstruction.same-shell-reconnect"`))
	return reconstructionReconnectScenarioData(caseID), nil
}

func (runner *reconstructionOrderingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

func (runner *successfulOrderingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	runner.called = true
	runner.sawStarted = bytes.Contains(runner.output.Bytes(), []byte(`"message_type":"scenario_started"`))
	return completedScenarioData(caseID), nil
}

func (runner *successfulOrderingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.runCalls++
	if runner.runCalls == 1 {
		runner.sawSecondStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.protected-lifecycle-create"`))
	} else if runner.runCalls == 2 {
		runner.sawThirdStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.replay-semantics"`))
	} else if runner.runCalls == 3 {
		runner.sawFourthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.lifecycle-completion-and-status"`))
	} else if runner.runCalls == 4 {
		runner.sawFifthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.exec-result-and-usage-evidence"`))
	} else if runner.runCalls == 5 {
		runner.sawSixthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.stale-fencing-rejection"`))
	} else if runner.runCalls == 6 {
		runner.sawSeventhStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.exec-cancellation"`))
	} else if runner.runCalls == 7 {
		runner.sawEighthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.terminal-session-and-opaque-handoff"`))
	} else if runner.runCalls == 8 {
		runner.sawNinthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.gateway-terminal-byte-round-trip"`))
	} else if runner.runCalls == 9 {
		runner.sawTenthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.gateway-wrong-caller-and-cross-tenant-rejection"`))
	} else if runner.runCalls == 10 {
		runner.sawEleventhStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.gateway-grant-expiry"`))
	} else if runner.runCalls == 11 {
		runner.sawTwelfthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.gateway-revocation"`))
	} else if runner.runCalls == 12 {
		runner.sawThirteenthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.artifact-staging-and-evidence"`))
	} else if runner.runCalls == 13 {
		runner.sawFourteenthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.provider-cross-tenant-artifact-rejection"`))
	} else {
		runner.sawFifteenthStarted = bytes.Contains(runner.output.Bytes(), []byte(`"case_id":"initial.provider-mtls-caller-binding-rejection"`))
	}
	return completedScenarioData(caseID), nil
}

func (runner *successfulOrderingCallerRunner) Close() error { return nil }

func completedScenarioData(caseID string) protocol.ScenarioResultData {
	if caseID == "initial.gateway-terminal-byte-round-trip" {
		observations := []string{"grant-bound-to-controller-a", "terminal-bytes-round-tripped", "shell-continuity-challenge-established", "shell-continuity-challenge-digest-recorded", "bounded-byte-count"}
		return protocol.ScenarioResultData{
			CaseID: caseID, Disposition: "completed",
			Interactions: []protocol.InteractionResult{{InteractionID: "gateway-terminal-round-trip", Surface: "caller_gateway", Actor: "controller_a", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-terminal-round-trip", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "authorized-byte-round-trip"}, ObservationIDs: append([]string(nil), observations...)}},
			Assertions:   []protocol.AssertionResult{{AssertionID: "gateway-policy-owned-by-caller", Result: "asserted"}}, ObservationIDs: observations,
		}
	}
	if caseID == "initial.gateway-wrong-caller-and-cross-tenant-rejection" {
		return gatewayAuthorityRejectionScenarioData(caseID)
	}
	if caseID == "initial.gateway-grant-expiry" {
		return gatewayGrantExpiryScenarioData(caseID)
	}
	if caseID == "initial.gateway-revocation" {
		return gatewayRevocationScenarioData(caseID)
	}
	if caseID == "initial.artifact-staging-and-evidence" {
		return artifactStagingScenarioData(caseID)
	}
	if caseID == "initial.provider-cross-tenant-artifact-rejection" {
		return crossTenantArtifactScenarioData(caseID)
	}
	if caseID == "initial.provider-mtls-caller-binding-rejection" {
		return mtlsCallerBindingScenarioData(caseID)
	}
	status := 200
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "controller-a-capabilities", Surface: "provider_http", Actor: "controller_a", Method: "GET",
			RouteTemplate: "/v1/capabilities", LogicalRequestID: "controller-a-capabilities", WireAttempts: 1,
			TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status},
			ObservationIDs: []string{"schema-valid-capability-document"},
		}},
		Assertions: []protocol.AssertionResult{}, ObservationIDs: []string{},
	}
}

func crossTenantArtifactScenarioData(caseID string) protocol.ScenarioResultData {
	status403, status404 := 403, 404
	forbidden, notFound := "SANDBOX_FORBIDDEN", "SANDBOX_NOT_FOUND"
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "cross-tenant-stage-artifact", Surface: "provider_http", Actor: "controller_b", Method: "POST", RouteTemplate: "/v1/sandboxes/{sandbox_id}/artifacts:stage", LogicalRequestID: "cross-tenant-stage-artifact", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status403, ErrorCode: &forbidden}, MutationWriteObserved: true, ObservationIDs: []string{"controller-b-tenant-b-request", "rejected-before-artifact-dispatch", "no-backend-disclosure"}},
			{InteractionID: "cross-tenant-read-artifact-operation", Surface: "provider_http", Actor: "controller_b", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "cross-tenant-read-artifact-operation", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status404, ErrorCode: &notFound}, ObservationIDs: []string{"no-cross-tenant-operation-visible"}},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "distinct-tenant-negative-case", Result: "asserted"}},
		ObservationIDs: []string{"controller-b-tenant-b-request", "rejected-before-artifact-dispatch", "no-backend-disclosure", "no-cross-tenant-operation-visible"},
	}
}

func mtlsCallerBindingScenarioData(caseID string) protocol.ScenarioResultData {
	status := 403
	forbidden := "SANDBOX_FORBIDDEN"
	observations := []string{"admitted-controller-b-certificate", "controller-a-signed-subject", "rejected-before-state-read"}
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{InteractionID: "wrong-mtls-caller-read-sandbox", Surface: "provider_http", Actor: "controller_b", Method: "GET", RouteTemplate: "/v1/sandboxes/{sandbox_id}", LogicalRequestID: "wrong-mtls-caller-read-sandbox", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status, ErrorCode: &forbidden}, ObservationIDs: append([]string(nil), observations...)}},
		Assertions:   []protocol.AssertionResult{{AssertionID: "mtls-and-jws-caller-must-match", Result: "asserted"}}, ObservationIDs: observations,
	}
}

func reconstructionCapabilityScenarioData(caseID string) protocol.ScenarioResultData {
	status := 200
	observations := []string{"byte-identical-capability-snapshot", "new-provider-process", "new-caller-process", "new-adapter-process", "new-gateway-process"}
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{InteractionID: "reconstructed-capabilities", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/capabilities", LogicalRequestID: "reconstructed-capabilities", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: append([]string(nil), observations...)}},
		Assertions:   []protocol.AssertionResult{{AssertionID: "caller-loaded-own-durable-correlation-state", Result: "asserted"}, {AssertionID: "harness-did-not-reinject-forbidden-bindings", Result: "asserted"}}, ObservationIDs: observations,
	}
}

func reconstructionLifecycleScenarioData(caseID string) protocol.ScenarioResultData {
	status := 200
	observations := []string{"same-create-operation-correlation", "operation-succeeded", "caller-correlation-load-without-harness-reinjection-observed", "same-sandbox-correlation", "sandbox-ready", "generation-one"}
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "read-reconstructed-create-operation", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-reconstructed-create-operation", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: append([]string(nil), observations[:3]...)},
			{InteractionID: "read-reconstructed-sandbox", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/sandboxes/{sandbox_id}", LogicalRequestID: "read-reconstructed-sandbox", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: append([]string(nil), observations[3:]...)},
		},
		Assertions: []protocol.AssertionResult{{AssertionID: "correlations-originated-in-caller-durable-store", Result: "asserted"}}, ObservationIDs: observations,
	}
}

func reconstructionEvidenceScenarioData(caseID string) protocol.ScenarioResultData {
	status := 200
	observations := []string{"same-exec-result-completed", "same-usage-evidence-digest", "same-artifact-evidence-digest"}
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "read-retained-exec-result", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/exec-result", LogicalRequestID: "read-retained-exec-result", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: []string{observations[0]}},
			{InteractionID: "read-retained-usage", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/usage-evidence", LogicalRequestID: "read-retained-usage", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: []string{observations[1]}},
			{InteractionID: "read-retained-artifact-evidence", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/artifact-staging-evidence", LogicalRequestID: "read-retained-artifact-evidence", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: []string{observations[2]}},
		},
		Assertions: []protocol.AssertionResult{{AssertionID: "retained-evidence-correlations-loaded-by-caller", Result: "asserted"}}, ObservationIDs: observations,
	}
}

func reconstructionHandoffScenarioData(caseID string) protocol.ScenarioResultData {
	status := 200
	observations := []string{"same-handoff-reference-digest", "same-runtime-session", "opaque-reference"}
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{InteractionID: "read-retained-terminal-handoff", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/runtime-session", LogicalRequestID: "read-retained-terminal-handoff", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: append([]string(nil), observations...)}},
		Assertions:   []protocol.AssertionResult{{AssertionID: "raw-handoff-reference-absent-from-evidence", Result: "asserted"}}, ObservationIDs: observations,
	}
}

func reconstructionReconnectScenarioData(caseID string) protocol.ScenarioResultData {
	observations := []string{"same-runtime-session", "shell-continuity-challenge-digest-matched", "bounded-byte-count", "adapter-invocation-transcript-excludes-forbidden-correlations"}
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{InteractionID: "gateway-same-shell-reconnect", Surface: "caller_gateway", Actor: "controller_a", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-same-shell-reconnect", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "authorized-byte-round-trip"}, ObservationIDs: append([]string(nil), observations...)}},
		Assertions:   []protocol.AssertionResult{{AssertionID: "caller-loaded-handoff-from-own-durable-state", Result: "asserted"}, {AssertionID: "harness-did-not-reinject-handoff", Result: "asserted"}}, ObservationIDs: observations,
	}
}

func gatewayAuthorityRejectionScenarioData(caseID string) protocol.ScenarioResultData {
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "gateway-missing-caller-credential", Surface: "caller_gateway", Actor: "unauthenticated_client", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-missing-caller-credential", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "gateway-upgrade-rejected"}, ObservationIDs: []string{"no-runtime-connection"}},
			{InteractionID: "gateway-cross-tenant", Surface: "caller_gateway", Actor: "controller_b", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-cross-tenant", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "gateway-upgrade-rejected"}, ObservationIDs: []string{"tenant-b-cannot-use-tenant-a-session", "no-terminal-bytes-forwarded"}},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "controllers-belong-to-distinct-tenants", Result: "asserted"}},
		ObservationIDs: []string{"no-runtime-connection", "tenant-b-cannot-use-tenant-a-session", "no-terminal-bytes-forwarded"},
	}
}

func gatewayGrantExpiryScenarioData(caseID string) protocol.ScenarioResultData {
	observations := []string{"grant-initially-authorized", "connection-closed-after-expiry", "no-post-expiry-forwarding"}
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{InteractionID: "gateway-expiring-grant", Surface: "caller_gateway", Actor: "controller_a", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-expiring-grant", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "gateway-closed-at-grant-expiry"}, ObservationIDs: append([]string(nil), observations...)}},
		Assertions:   []protocol.AssertionResult{{AssertionID: "caller-enforced-grant-expiry", Result: "asserted"}}, ObservationIDs: observations,
	}
}

func gatewayRevocationScenarioData(caseID string) protocol.ScenarioResultData {
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "gateway-revocable-grant", Surface: "caller_gateway", Actor: "controller_a", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-revocable-grant", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "authorized-byte-round-trip"}, ObservationIDs: []string{"grant-initially-authorized"}},
			{InteractionID: "gateway-revoke-grant", Surface: "caller_gateway", Actor: "controller_a", Method: "CONTROL", RouteTemplate: "consumer-defined:revoke-grant", LogicalRequestID: "gateway-revoke-grant", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "revocation-acknowledged"}, MutationWriteObserved: true, ObservationIDs: []string{"connection-closed-after-revocation", "no-post-revocation-forwarding"}},
		},
		Assertions: []protocol.AssertionResult{{AssertionID: "revocation-authority-owned-by-caller", Result: "asserted"}}, ObservationIDs: []string{"grant-initially-authorized", "connection-closed-after-revocation", "no-post-revocation-forwarding"},
	}
}

func artifactStagingScenarioData(caseID string) protocol.ScenarioResultData {
	status202, status200 := 202, 200
	return protocol.ScenarioResultData{
		CaseID: caseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "stage-artifact", Surface: "provider_http", Actor: "controller_a", Method: "POST", RouteTemplate: "/v1/sandboxes/{sandbox_id}/artifacts:stage", LogicalRequestID: "stage-artifact", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status202}, MutationWriteObserved: true, ObservationIDs: []string{"artifact-operation-accepted"}},
			{InteractionID: "read-artifact-operation", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-artifact-operation", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status200}, ObservationIDs: []string{"operation-succeeded"}},
			{InteractionID: "read-artifact-evidence", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/artifact-staging-evidence", LogicalRequestID: "read-artifact-evidence", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status200}, ObservationIDs: []string{"artifact-status-staged", "content-digest-and-size-match", "opaque-staging-reference"}},
		},
		Assertions: []protocol.AssertionResult{{AssertionID: "caller-kept-aggregate-artifact-truth", Result: "asserted"}}, ObservationIDs: []string{"artifact-operation-accepted", "operation-succeeded", "artifact-status-staged", "content-digest-and-size-match", "opaque-staging-reference"},
	}
}

func (runner *failingCallerRunner) Start(_ context.Context, invocation protocol.Invocation, _ string, bundle *credentials.Bundle) (protocol.ScenarioResultData, error) {
	runner.phase = invocation.Phase
	_ = bundle.Use("provider-controller-a", func(payload []byte) error {
		runner.retainedSecret = payload
		return nil
	})
	return protocol.ScenarioResultData{}, errors.New("synthetic caller start failure")
}

func (runner *failingCallerRunner) Run(context.Context, string) (protocol.ScenarioResultData, error) {
	return protocol.ScenarioResultData{}, errors.New("unexpected second scenario")
}

func (runner *failingCallerRunner) Close() error { return nil }

type mappedFailureCallerRunner struct {
	failureCode string
	closeErr    error
	closed      bool
}

func (runner *mappedFailureCallerRunner) Start(context.Context, protocol.Invocation, string, *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return protocol.ScenarioResultData{}, errors.New("private caller failure detail")
}

func (runner *mappedFailureCallerRunner) Run(context.Context, string) (protocol.ScenarioResultData, error) {
	return protocol.ScenarioResultData{}, errors.New("unexpected continuation")
}

func (runner *mappedFailureCallerRunner) Close() error {
	runner.closed = true
	return runner.closeErr
}

func (runner *mappedFailureCallerRunner) FailureCode(error) string { return runner.failureCode }

type secondFailingCallerRunner struct{ closed bool }

func (runner *secondFailingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return completedScenarioData(caseID), nil
}

func (runner *secondFailingCallerRunner) Run(context.Context, string) (protocol.ScenarioResultData, error) {
	return protocol.ScenarioResultData{}, errors.New("synthetic second scenario failure")
}

func (runner *secondFailingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

type thirdFailingCallerRunner struct {
	calls  int
	closed bool
}

type fourthFailingCallerRunner struct {
	calls  int
	closed bool
}

type fifthFailingCallerRunner struct {
	calls  int
	closed bool
}

type sixthFailingCallerRunner struct {
	calls  int
	closed bool
}

type seventhFailingCallerRunner struct {
	calls  int
	closed bool
}

type eighthFailingCallerRunner struct {
	calls  int
	closed bool
}

type ninthFailingCallerRunner struct {
	calls  int
	closed bool
}

type twelfthFailingCallerRunner struct {
	calls  int
	closed bool
}

func (runner *twelfthFailingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return completedScenarioData(caseID), nil
}

func (runner *twelfthFailingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.calls++
	if runner.calls == 11 {
		return protocol.ScenarioResultData{}, errors.New("synthetic twelfth scenario failure")
	}
	return completedScenarioData(caseID), nil
}

func (runner *twelfthFailingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

func (runner *ninthFailingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return completedScenarioData(caseID), nil
}

func (runner *ninthFailingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.calls++
	if runner.calls == 8 {
		return protocol.ScenarioResultData{}, errors.New("synthetic ninth scenario failure")
	}
	return completedScenarioData(caseID), nil
}

func (runner *ninthFailingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

func (runner *eighthFailingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return completedScenarioData(caseID), nil
}

func (runner *eighthFailingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.calls++
	if runner.calls == 7 {
		return protocol.ScenarioResultData{}, errors.New("synthetic eighth scenario failure")
	}
	return completedScenarioData(caseID), nil
}

func (runner *eighthFailingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

func (runner *seventhFailingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return completedScenarioData(caseID), nil
}

func (runner *seventhFailingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.calls++
	if runner.calls == 6 {
		return protocol.ScenarioResultData{}, errors.New("synthetic seventh scenario failure")
	}
	return completedScenarioData(caseID), nil
}

func (runner *seventhFailingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

func (runner *sixthFailingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return completedScenarioData(caseID), nil
}

func (runner *sixthFailingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.calls++
	if runner.calls == 5 {
		return protocol.ScenarioResultData{}, errors.New("synthetic sixth scenario failure")
	}
	return completedScenarioData(caseID), nil
}

func (runner *sixthFailingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

func (runner *fifthFailingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return completedScenarioData(caseID), nil
}

func (runner *fifthFailingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.calls++
	if runner.calls == 4 {
		return protocol.ScenarioResultData{}, errors.New("synthetic fifth scenario failure")
	}
	return completedScenarioData(caseID), nil
}

func (runner *fifthFailingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

func (runner *fourthFailingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return completedScenarioData(caseID), nil
}

func (runner *fourthFailingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.calls++
	if runner.calls == 3 {
		return protocol.ScenarioResultData{}, errors.New("synthetic fourth scenario failure")
	}
	return completedScenarioData(caseID), nil
}

func (runner *fourthFailingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

func (runner *thirdFailingCallerRunner) Start(_ context.Context, _ protocol.Invocation, caseID string, _ *credentials.Bundle) (protocol.ScenarioResultData, error) {
	return completedScenarioData(caseID), nil
}

func (runner *thirdFailingCallerRunner) Run(_ context.Context, caseID string) (protocol.ScenarioResultData, error) {
	runner.calls++
	if runner.calls == 2 {
		return protocol.ScenarioResultData{}, errors.New("synthetic third scenario failure")
	}
	return completedScenarioData(caseID), nil
}

func (runner *thirdFailingCallerRunner) Close() error {
	runner.closed = true
	return nil
}

type startupOrderingReader struct {
	document    *bytes.Reader
	output      *bytes.Buffer
	onFirstRead func()
	checked     bool
}

func assertCompletedAdapterTranscript(t *testing.T, document []byte, phase string, scenarioCount int) {
	t.Helper()
	if len(document) == 0 || len(document) > protocol.MaxAdapterStdoutBytes || document[len(document)-1] != '\n' {
		t.Fatalf("adapter transcript byte framing = %d bytes", len(document))
	}
	lines := bytes.Split(bytes.TrimSuffix(document, []byte{'\n'}), []byte{'\n'})
	if want := 3 + scenarioCount*2; len(lines) != want || len(lines) > protocol.MaxAdapterOutputRecords {
		t.Fatalf("adapter transcript records = %d, want %d", len(lines), want)
	}
	for index, line := range lines {
		if len(line) == 0 || len(line) > protocol.MaxAdapterOutputRecordBytes {
			t.Fatalf("adapter transcript record %d bytes = %d", index, len(line))
		}
		var envelope struct {
			MessageType string `json:"message_type"`
			Sequence    int    `json:"sequence"`
			Phase       string `json:"phase"`
			Disposition string `json:"disposition"`
			Completion  string `json:"completion"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatalf("adapter transcript record %d = %v", index, err)
		}
		if index == 0 {
			if envelope.MessageType != "startup_identity" || envelope.Sequence != 0 {
				t.Fatalf("adapter startup = %#v", envelope)
			}
			continue
		}
		if envelope.Sequence != index || envelope.Phase != phase {
			t.Fatalf("adapter transcript binding %d = %#v", index, envelope)
		}
		switch {
		case index == 1:
			if envelope.MessageType != "invocation_accepted" {
				t.Fatalf("adapter acceptance = %#v", envelope)
			}
		case index == len(lines)-1:
			if envelope.MessageType != "invocation_finished" || envelope.Completion != "completed" {
				t.Fatalf("adapter terminal = %#v", envelope)
			}
		case index%2 == 0:
			if envelope.MessageType != "scenario_started" {
				t.Fatalf("adapter start record %d = %#v", index, envelope)
			}
		default:
			if envelope.MessageType != "scenario_result" || envelope.Disposition != "completed" {
				t.Fatalf("adapter result record %d = %#v", index, envelope)
			}
		}
	}
}

func (reader *startupOrderingReader) Read(buffer []byte) (int, error) {
	if !reader.checked {
		reader.checked = true
		if !bytes.Contains(reader.output.Bytes(), []byte(`"message_type":"startup_identity"`)) {
			return 0, io.ErrUnexpectedEOF
		}
		if reader.onFirstRead != nil {
			reader.onFirstRead()
		}
	}
	return reader.document.Read(buffer)
}

func testCredentialPipes(t *testing.T) ([]protocol.ChannelDescriptor, []*os.File) {
	t.Helper()
	requirements := credentials.Requirements()
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	writers := make([]*os.File, 0, len(requirements))
	for _, requirement := range requirements {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		ownedDescriptor, err := syscall.Dup(int(reader.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		writers = append(writers, writer)
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: ownedDescriptor,
		})
	}
	return descriptors, writers
}

func testInvocation(descriptors []protocol.ChannelDescriptor) protocol.Invocation {
	return protocol.Invocation{
		FormatVersion: protocol.FormatVersion, ProtocolID: protocol.ProtocolID, ProtocolVersion: protocol.ProtocolVersion,
		MessageType: "invocation", InvocationID: "run.initial", Phase: "initial", ProfilePath: "/qualification/profile.json",
		ProviderOrigin: "https://provider.example", GatewayProbeEndpoint: "https://gateway.example/tunnel",
		CredentialChannelDescriptors: descriptors, CallerStateRoot: "/caller/state",
	}
}
