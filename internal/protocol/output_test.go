package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestInvocationDecoderRejectsEveryValidOutputDirection(t *testing.T) {
	startup := testStartup(t)
	invocationID, phase := "run.initial", "initial"
	records := []any{
		startup,
		InvocationAccepted{FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "invocation_accepted", Sequence: 1, InvocationID: invocationID, Phase: phase},
		ScenarioStarted{FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "scenario_started", Sequence: 2, InvocationID: invocationID, Phase: phase, CaseID: initialCaseIDs[0]},
		ScenarioResult{
			FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "scenario_result", Sequence: 3,
			InvocationID: invocationID, Phase: phase, CaseID: initialCaseIDs[0], Disposition: "completed",
			Interactions: []InteractionResult{testInteraction()}, Assertions: []AssertionResult{}, ObservationIDs: []string{}, ReasonCode: nil,
		},
		InvocationFinished{FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "invocation_finished", Sequence: 4, InvocationID: invocationID, Phase: phase, Completion: "completed"},
		ProtocolError{FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "protocol_error", Sequence: 2, InvocationID: &invocationID, Phase: &phase, ErrorCode: "internal_failure", Terminal: true},
	}
	for _, record := range records {
		document, err := marshalOutputRecord(record)
		if err != nil {
			t.Fatalf("marshalOutputRecord(%T) error = %v", record, err)
		}
		if _, err := (&InvocationDecoder{}).Decode(bytes.NewReader(document)); !errors.Is(err, ErrMessageDirection) {
			t.Errorf("Decode(%T) error = %v, want message direction", record, err)
		}
	}
}

func TestInvocationDecoderAppliesOutputSchemaBeforeDirection(t *testing.T) {
	record := ScenarioResult{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "scenario_result", Sequence: 3,
		InvocationID: "run.initial", Phase: "initial", CaseID: initialCaseIDs[0], Disposition: "completed",
		Interactions: []InteractionResult{testInteraction()}, Assertions: []AssertionResult{}, ObservationIDs: []string{}, ReasonCode: nil,
	}
	document, err := marshalOutputRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(document, &object); err != nil {
		t.Fatal(err)
	}
	interaction := object["interactions"].([]any)[0].(map[string]any)
	finalOutcome := interaction["final_outcome"].(map[string]any)
	delete(finalOutcome, "retryable")
	document, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&InvocationDecoder{}).Decode(bytes.NewReader(document)); !errors.Is(err, ErrSchema) {
		t.Fatalf("Decode(malformed output) error = %v, want schema", err)
	}
}

func TestOutputEncoderWritesCompleteSingleLFRecordsAndCountsWireBytes(t *testing.T) {
	var output bytes.Buffer
	encoder := NewOutputEncoder(&output)
	startup, err := NewStartupIdentity(testRelease("caller-v1"), testRelease("adapter-v1"), testRequirements())
	if err != nil {
		t.Fatal(err)
	}
	accepted := InvocationAccepted{FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "invocation_accepted", Sequence: 1, InvocationID: "run.initial", Phase: "initial"}
	if err := encoder.Write(startup); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Write(accepted); err != nil {
		t.Fatal(err)
	}
	stats := encoder.Stats()
	if stats.CompleteRecords != 2 || stats.WireBytes != output.Len() || bytes.Count(output.Bytes(), []byte{'\n'}) != 2 || bytes.Contains(output.Bytes(), []byte{'\r'}) {
		t.Fatalf("output stats/framing = %#v, bytes %q", stats, output.Bytes())
	}
}

func TestOutputEncoderFailsClosedAfterInvalidRecord(t *testing.T) {
	var output bytes.Buffer
	encoder := NewOutputEncoder(&output)
	invalid := InvocationAccepted{FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "invocation_accepted", Sequence: 0, InvocationID: "run.initial", Phase: "initial"}
	if err := encoder.Write(invalid); !errors.Is(err, ErrSchema) {
		t.Fatalf("Write(invalid) error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("invalid record wrote %d bytes", output.Len())
	}
	invalid.Sequence = 1
	if err := encoder.Write(invalid); !errors.Is(err, ErrOutputEncoderFailed) {
		t.Fatalf("Write(after failure) error = %v", err)
	}
}

func TestOutputEncoderLimitPrecedenceAndPartialWriteAccounting(t *testing.T) {
	accepted := InvocationAccepted{FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "invocation_accepted", Sequence: 1, InvocationID: "run.initial", Phase: "initial"}

	byteLimited := NewOutputEncoder(&bytes.Buffer{})
	byteLimited.bytes = MaxAdapterStdoutBytes
	byteLimited.records = MaxAdapterOutputRecords
	if err := byteLimited.Write(accepted); !errors.Is(err, ErrOutputByteLimit) {
		t.Fatalf("byte-limit precedence error = %v", err)
	}

	recordLimited := NewOutputEncoder(&bytes.Buffer{})
	recordLimited.records = MaxAdapterOutputRecords
	if err := recordLimited.Write(accepted); !errors.Is(err, ErrOutputRecordLimit) {
		t.Fatalf("record-limit error = %v", err)
	}

	partial := NewOutputEncoder(partialFailWriter{})
	if err := partial.Write(accepted); !errors.Is(err, ErrStreamIO) {
		t.Fatalf("partial write error = %v", err)
	}
	if stats := partial.Stats(); stats.CompleteRecords != 0 || stats.WireBytes != 1 {
		t.Fatalf("partial write stats = %#v", stats)
	}
}

func TestScenarioResultSchemaBranches(t *testing.T) {
	completed := ScenarioResult{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "scenario_result", Sequence: 3,
		InvocationID: "run.initial", Phase: "initial", CaseID: initialCaseIDs[0], Disposition: "completed",
		Interactions: []InteractionResult{testInteraction()}, Assertions: []AssertionResult{}, ObservationIDs: []string{}, ReasonCode: nil,
	}
	if !validScenarioResult(completed) {
		t.Fatal("valid completed scenario result was rejected")
	}
	completed.Interactions[0].ObservationIDs = nil
	if validScenarioResult(completed) {
		t.Fatal("interaction without observation IDs was accepted")
	}

	reason := "prerequisite_not_satisfied"
	notExecuted := ScenarioResult{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "scenario_result", Sequence: 2,
		InvocationID: "run.initial", Phase: "initial", CaseID: initialCaseIDs[0], Disposition: "not_executed",
		Interactions: []InteractionResult{}, Assertions: []AssertionResult{}, ObservationIDs: []string{}, ReasonCode: &reason,
	}
	if !validScenarioResult(notExecuted) {
		t.Fatal("valid not-executed scenario result was rejected")
	}
	notExecuted.ReasonCode = nil
	if validScenarioResult(notExecuted) {
		t.Fatal("not-executed result without reason was accepted")
	}
}

func TestProtocolErrorSchemaBranches(t *testing.T) {
	preBinding := ProtocolError{FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "protocol_error", Sequence: 1, ErrorCode: "invalid_invocation", Terminal: true}
	if !validProtocolError(preBinding) {
		t.Fatal("valid pre-binding protocol error was rejected")
	}
	invocationID, phase := "run.initial", "initial"
	postBinding := ProtocolError{FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "protocol_error", Sequence: 2, InvocationID: &invocationID, Phase: &phase, ErrorCode: "internal_failure", Terminal: true}
	if !validProtocolError(postBinding) {
		t.Fatal("valid post-binding protocol error was rejected")
	}
	postBinding.Sequence = 1
	if validProtocolError(postBinding) {
		t.Fatal("post-binding protocol error with sequence one was accepted")
	}
}

func TestOutputValidationRejectsOversizedAndDuplicateCollections(t *testing.T) {
	result := ScenarioResult{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "scenario_result", Sequence: 3,
		InvocationID: "run.initial", Phase: "initial", CaseID: initialCaseIDs[0], Disposition: "completed",
		Interactions: []InteractionResult{testInteraction()}, Assertions: []AssertionResult{{AssertionID: "one", Result: "asserted"}, {AssertionID: "one", Result: "asserted"}}, ObservationIDs: []string{},
	}
	if validScenarioResult(result) {
		t.Fatal("duplicate assertion result was accepted")
	}
	result.Assertions = []AssertionResult{}
	result.Interactions[0].FinalOutcome.ErrorCode = stringPointer(strings.Repeat("A", 101))
	if validScenarioResult(result) {
		t.Fatal("oversized stable error code was accepted")
	}

	result.Interactions[0].FinalOutcome.ErrorCode = nil
	longReplay := strings.Repeat("a", 201)
	result.Interactions[0].ReplayOf = &longReplay
	if !validScenarioResult(result) {
		t.Fatal("schema-valid replay_of without a maxLength was rejected")
	}
}

type partialFailWriter struct{}

func (partialFailWriter) Write([]byte) (int, error) {
	return 1, errors.New("synthetic partial write")
}

func testInteraction() InteractionResult {
	status := 200
	return InteractionResult{
		InteractionID: "interaction", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/capabilities",
		LogicalRequestID: "request", WireAttempts: 1, TransientOutcomes: []Outcome{},
		FinalOutcome: Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: []string{"observation"},
	}
}

func stringPointer(value string) *string {
	return &value
}
