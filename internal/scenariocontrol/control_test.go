package scenariocontrol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func TestScenarioControlRoundTripAndClosedBinding(t *testing.T) {
	request := testRequest(t)
	var input bytes.Buffer
	if err := EncodeRequest(&input, request); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequest(bytes.NewReader(bytes.TrimSuffix(input.Bytes(), []byte{'\n'})))
	if err != nil || decoded.CaseID != CapabilityCaseID || decoded.InvocationID != "run.initial" {
		t.Fatalf("request roundtrip = %#v, %v", decoded, err)
	}
	result, err := NewResult(request, 123, testResultData())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := EncodeResult(&output, result); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeResult(&output)
	if err != nil || got.ProcessID != 123 || got.Data().CaseID != CapabilityCaseID {
		t.Fatalf("result roundtrip = %#v, %v", got, err)
	}

	raw, _ := json.Marshal(request)
	for name, changed := range map[string][]byte{
		"unknown":    []byte(strings.Replace(string(raw), `"case_id":`, `"unknown":true,"case_id":`, 1)),
		"wrong case": []byte(strings.Replace(string(raw), CapabilityCaseID, "initial.protected-lifecycle-create", 1)),
		"bad id":     []byte(strings.Replace(string(raw), "run.initial", "RUN INITIAL", 1)),
		"old v11":    []byte(strings.Replace(string(raw), ProtocolID, "sandbox-runtime-external-caller-private-scenario-v11", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(bytes.NewReader(changed)); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	if _, err := DecodeResult(bytes.NewReader(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}))); err == nil {
		t.Fatal("result without LF accepted")
	}
}

func TestScenarioControlStreamsExactlyFifteenAuthorizedRecords(t *testing.T) {
	request := testRequest(t)
	createCommand, err := NewCommand(request, LifecycleCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	replayCommand, err := NewCommand(request, ReplayCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	lifecycleCommand, err := NewCommand(request, LifecycleCompletionCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	execCommand, err := NewCommand(request, ExecResultUsageCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	staleCommand, err := NewCommand(request, StaleFencingCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	cancellationCommand, err := NewCommand(request, ExecCancellationCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	terminalCommand, err := NewCommand(request, TerminalSessionCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	gatewayCommand, err := NewCommand(request, GatewayRoundTripCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	rejectionCommand, err := NewCommand(request, GatewayAuthorityRejectionCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	expiryCommand, err := NewCommand(request, GatewayGrantExpiryCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	revocationCommand, err := NewCommand(request, GatewayRevocationCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	artifactCommand, err := NewCommand(request, ArtifactStagingCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	crossTenantCommand, err := NewCommand(request, CrossTenantArtifactCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	mtlsBindingCommand, err := NewCommand(request, MTLSCallerBindingCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	if err := EncodeRequest(&input, request); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, createCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, replayCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, lifecycleCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, execCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, staleCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, cancellationCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, terminalCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, gatewayCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, rejectionCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, expiryCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, revocationCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, artifactCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, crossTenantCommand); err != nil {
		t.Fatal(err)
	}
	if err := EncodeCommand(&input, mtlsBindingCommand); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(&input)
	decodedRequest, err := DecodeRequestRecord(reader)
	if err != nil || decodedRequest.CaseID != CapabilityCaseID {
		t.Fatalf("request record = %#v, %v", decodedRequest, err)
	}
	decodedCommand, err := DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != LifecycleCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != ReplayCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("replay command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != LifecycleCompletionCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("lifecycle completion command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != ExecResultUsageCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("exec result/usage command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != StaleFencingCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("stale fencing command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != ExecCancellationCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("exec cancellation command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != TerminalSessionCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("terminal session command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != GatewayRoundTripCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("Gateway round-trip command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != GatewayAuthorityRejectionCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("Gateway authority-rejection command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != GatewayGrantExpiryCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("Gateway grant-expiry command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != GatewayRevocationCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("Gateway revocation command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != ArtifactStagingCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("artifact staging command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != CrossTenantArtifactCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("cross-tenant artifact command record = %#v, %v", decodedCommand, err)
	}
	decodedCommand, err = DecodeCommandRecord(reader)
	if err != nil || decodedCommand.CaseID != MTLSCallerBindingCaseID || decodedCommand.InvocationID != request.InvocationID {
		t.Fatalf("mTLS caller-binding command record = %#v, %v", decodedCommand, err)
	}

	first, err := NewResult(request, 123, testResultData())
	if err != nil {
		t.Fatal(err)
	}
	secondData := testResultData()
	secondData.CaseID = LifecycleCaseID
	second, err := NewResult(request, 123, secondData)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := EncodeResult(&output, first); err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, second); err != nil {
		t.Fatal(err)
	}
	thirdData := testResultData()
	thirdData.CaseID = ReplayCaseID
	third, err := NewResult(request, 123, thirdData)
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, third); err != nil {
		t.Fatal(err)
	}
	fourthData := testResultData()
	fourthData.CaseID = LifecycleCompletionCaseID
	fourth, err := NewResult(request, 123, fourthData)
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, fourth); err != nil {
		t.Fatal(err)
	}
	fifthData := testResultData()
	fifthData.CaseID = ExecResultUsageCaseID
	fifth, err := NewResult(request, 123, fifthData)
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, fifth); err != nil {
		t.Fatal(err)
	}
	sixthData := staleResultData()
	sixth, err := NewResult(request, 123, sixthData)
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, sixth); err != nil {
		t.Fatal(err)
	}
	seventh, err := NewResult(request, 123, cancellationResultData())
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, seventh); err != nil {
		t.Fatal(err)
	}
	eighth, err := NewResult(request, 123, terminalResultData())
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, eighth); err != nil {
		t.Fatal(err)
	}
	ninth, err := NewResult(request, 123, gatewayRoundTripResultData())
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, ninth); err != nil {
		t.Fatal(err)
	}
	tenth, err := NewResult(request, 123, gatewayAuthorityRejectionResultData())
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, tenth); err != nil {
		t.Fatal(err)
	}
	eleventh, err := NewResult(request, 123, gatewayGrantExpiryResultData())
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, eleventh); err != nil {
		t.Fatal(err)
	}
	twelfth, err := NewResult(request, 123, gatewayRevocationResultData())
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, twelfth); err != nil {
		t.Fatal(err)
	}
	thirteenth, err := NewResult(request, 123, artifactResultData())
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, thirteenth); err != nil {
		t.Fatal(err)
	}
	fourteenth, err := NewResult(request, 123, crossTenantArtifactResultData())
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, fourteenth); err != nil {
		t.Fatal(err)
	}
	fifteenth, err := NewResult(request, 123, mtlsCallerBindingResultData())
	if err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&output, fifteenth); err != nil {
		t.Fatal(err)
	}
	resultReader := bufio.NewReader(&output)
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != CapabilityCaseID {
		t.Fatalf("first result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != LifecycleCaseID {
		t.Fatalf("second result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != ReplayCaseID {
		t.Fatalf("third result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != LifecycleCompletionCaseID {
		t.Fatalf("fourth result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != ExecResultUsageCaseID {
		t.Fatalf("fifth result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != StaleFencingCaseID {
		t.Fatalf("sixth result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != ExecCancellationCaseID {
		t.Fatalf("seventh result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != TerminalSessionCaseID {
		t.Fatalf("eighth result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != GatewayRoundTripCaseID {
		t.Fatalf("ninth result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != GatewayAuthorityRejectionCaseID {
		t.Fatalf("tenth result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != GatewayGrantExpiryCaseID {
		t.Fatalf("eleventh result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != GatewayRevocationCaseID {
		t.Fatalf("twelfth result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != ArtifactStagingCaseID {
		t.Fatalf("thirteenth result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != CrossTenantArtifactCaseID {
		t.Fatalf("fourteenth result record = %#v, %v", got, err)
	}
	if got, err := DecodeResultRecord(resultReader); err != nil || got.CaseID != MTLSCallerBindingCaseID {
		t.Fatalf("fifteenth result record = %#v, %v", got, err)
	}
}

func TestScenarioControlAcceptsAuthorizedReconstructionPrefix(t *testing.T) {
	request := testRequest(t)
	request.InvocationID = "run.reconstruction"
	request.Phase = "reconstruction"
	request.CaseID = ReconstructionCapabilityCaseID
	var input bytes.Buffer
	if err := EncodeRequest(&input, request); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sandbox_id", "operation_id", "attempt_id", "idempotency_key", "fencing_token", "runtime_session_id", "handoff"} {
		if bytes.Contains(input.Bytes(), []byte(forbidden)) {
			t.Fatalf("reconstruction request contains forbidden correlation field %q: %q", forbidden, input.Bytes())
		}
	}
	decoded, err := DecodeRequestRecord(bufio.NewReader(&input))
	if err != nil || decoded.Phase != "reconstruction" || decoded.CaseID != ReconstructionCapabilityCaseID {
		t.Fatalf("reconstruction request = %#v, %v", decoded, err)
	}
	status := 200
	observations := []string{"byte-identical-capability-snapshot", "new-provider-process", "new-caller-process", "new-adapter-process", "new-gateway-process"}
	data := protocol.ScenarioResultData{
		CaseID: ReconstructionCapabilityCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{InteractionID: "reconstructed-capabilities", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/capabilities", LogicalRequestID: "reconstructed-capabilities", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: append([]string(nil), observations...)}},
		Assertions:   []protocol.AssertionResult{{AssertionID: "caller-loaded-own-durable-correlation-state", Result: "asserted"}, {AssertionID: "harness-did-not-reinject-forbidden-bindings", Result: "asserted"}}, ObservationIDs: observations,
	}
	result, err := NewResult(request, 123, data)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := EncodeResult(&output, result); err != nil {
		t.Fatal(err)
	}
	if decodedResult, err := DecodeResultRecord(bufio.NewReader(&output)); err != nil || decodedResult.Phase != "reconstruction" || decodedResult.CaseID != ReconstructionCapabilityCaseID {
		t.Fatalf("reconstruction result = %#v, %v", decodedResult, err)
	}
	command, err := NewCommand(request, ReconstructionLifecycleCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var commandOutput bytes.Buffer
	if err := EncodeCommand(&commandOutput, command); err != nil {
		t.Fatal(err)
	}
	if decodedCommand, err := DecodeCommandRecord(bufio.NewReader(&commandOutput)); err != nil || decodedCommand.Phase != "reconstruction" || decodedCommand.CaseID != ReconstructionLifecycleCaseID {
		t.Fatalf("reconstruction lifecycle command = %#v, %v", decodedCommand, err)
	}
	lifecycleObservations := []string{"same-create-operation-correlation", "operation-succeeded", "caller-correlation-load-without-harness-reinjection-observed", "same-sandbox-correlation", "sandbox-ready", "generation-one"}
	lifecycleData := protocol.ScenarioResultData{
		CaseID: ReconstructionLifecycleCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "read-reconstructed-create-operation", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-reconstructed-create-operation", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: lifecycleObservations[:3]},
			{InteractionID: "read-reconstructed-sandbox", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/sandboxes/{sandbox_id}", LogicalRequestID: "read-reconstructed-sandbox", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: lifecycleObservations[3:]},
		},
		Assertions: []protocol.AssertionResult{{AssertionID: "correlations-originated-in-caller-durable-store", Result: "asserted"}}, ObservationIDs: lifecycleObservations,
	}
	lifecycleResult, err := NewResult(request, 123, lifecycleData)
	if err != nil {
		t.Fatal(err)
	}
	var lifecycleOutput bytes.Buffer
	if err := EncodeResult(&lifecycleOutput, lifecycleResult); err != nil {
		t.Fatal(err)
	}
	if decodedResult, err := DecodeResultRecord(bufio.NewReader(&lifecycleOutput)); err != nil || decodedResult.Phase != "reconstruction" || decodedResult.CaseID != ReconstructionLifecycleCaseID {
		t.Fatalf("reconstruction lifecycle result = %#v, %v", decodedResult, err)
	}
	evidenceCommand, err := NewCommand(request, ReconstructionEvidenceCaseID, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var evidenceCommandOutput bytes.Buffer
	if err := EncodeCommand(&evidenceCommandOutput, evidenceCommand); err != nil {
		t.Fatal(err)
	}
	if decodedCommand, err := DecodeCommandRecord(bufio.NewReader(&evidenceCommandOutput)); err != nil || decodedCommand.Phase != "reconstruction" || decodedCommand.CaseID != ReconstructionEvidenceCaseID {
		t.Fatalf("reconstruction evidence command = %#v, %v", decodedCommand, err)
	}
	evidenceObservations := []string{"same-exec-result-completed", "same-usage-evidence-digest", "same-artifact-evidence-digest"}
	evidenceData := protocol.ScenarioResultData{
		CaseID: ReconstructionEvidenceCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "read-retained-exec-result", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/exec-result", LogicalRequestID: "read-retained-exec-result", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: evidenceObservations[:1]},
			{InteractionID: "read-retained-usage", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/usage-evidence", LogicalRequestID: "read-retained-usage", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: evidenceObservations[1:2]},
			{InteractionID: "read-retained-artifact-evidence", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/artifact-staging-evidence", LogicalRequestID: "read-retained-artifact-evidence", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: evidenceObservations[2:]},
		},
		Assertions: []protocol.AssertionResult{{AssertionID: "retained-evidence-correlations-loaded-by-caller", Result: "asserted"}}, ObservationIDs: evidenceObservations,
	}
	evidenceResult, err := NewResult(request, 123, evidenceData)
	if err != nil {
		t.Fatal(err)
	}
	var evidenceOutput bytes.Buffer
	if err := EncodeResult(&evidenceOutput, evidenceResult); err != nil {
		t.Fatal(err)
	}
	if decodedResult, err := DecodeResultRecord(bufio.NewReader(&evidenceOutput)); err != nil || decodedResult.Phase != "reconstruction" || decodedResult.CaseID != ReconstructionEvidenceCaseID {
		t.Fatalf("reconstruction evidence result = %#v, %v", decodedResult, err)
	}
	for _, caseID := range []string{ReconstructionHandoffCaseID, ReconstructionReconnectCaseID} {
		command, err := NewCommand(request, caseID, time.Now().Add(time.Minute).UTC())
		if err != nil {
			t.Fatalf("NewCommand(%q) = %v", caseID, err)
		}
		var output bytes.Buffer
		if err := EncodeCommand(&output, command); err != nil {
			t.Fatal(err)
		}
		if decoded, err := DecodeCommandRecord(bufio.NewReader(&output)); err != nil || decoded.CaseID != caseID {
			t.Fatalf("reconstruction command %q = %#v, %v", caseID, decoded, err)
		}
	}
	handoffObservations := []string{"same-handoff-reference-digest", "same-runtime-session", "opaque-reference"}
	handoffData := protocol.ScenarioResultData{
		CaseID: ReconstructionHandoffCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{InteractionID: "read-retained-terminal-handoff", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/runtime-session", LogicalRequestID: "read-retained-terminal-handoff", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status}, ObservationIDs: handoffObservations}},
		Assertions:   []protocol.AssertionResult{{AssertionID: "raw-handoff-reference-absent-from-evidence", Result: "asserted"}}, ObservationIDs: handoffObservations,
	}
	if _, err := NewResult(request, 123, handoffData); err != nil {
		t.Fatalf("handoff result = %v", err)
	}
	reconnectObservations := []string{"same-runtime-session", "shell-continuity-challenge-digest-matched", "bounded-byte-count", "adapter-invocation-transcript-excludes-forbidden-correlations"}
	reconnectData := protocol.ScenarioResultData{
		CaseID: ReconstructionReconnectCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{InteractionID: "gateway-same-shell-reconnect", Surface: "caller_gateway", Actor: "controller_a", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-same-shell-reconnect", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "authorized-byte-round-trip"}, ObservationIDs: reconnectObservations}},
		Assertions:   []protocol.AssertionResult{{AssertionID: "caller-loaded-handoff-from-own-durable-state", Result: "asserted"}, {AssertionID: "harness-did-not-reinject-handoff", Result: "asserted"}}, ObservationIDs: reconnectObservations,
	}
	if _, err := NewResult(request, 123, reconnectData); err != nil {
		t.Fatalf("reconnect result = %v", err)
	}
	if _, err := NewCommand(request, "reconstruction.unknown-sixth-case", time.Now().Add(time.Minute).UTC()); err == nil {
		t.Fatal("unauthorized reconstruction case accepted")
	}
}

func TestResultOwnsNestedScenarioData(t *testing.T) {
	request := testRequest(t)
	data := testResultData()
	replay := "original-replay"
	errorCode := "TEMPORARY"
	transientStatus := 503
	data.Interactions[0].ReplayOf = &replay
	data.Interactions[0].TransientOutcomes = []protocol.Outcome{{
		Transport: "http-response", StatusCode: &transientStatus, ErrorCode: &errorCode, Retryable: true,
	}}
	result, err := NewResult(request, 123, data)
	if err != nil {
		t.Fatal(err)
	}

	*data.Interactions[0].ReplayOf = "mutated-replay"
	*data.Interactions[0].TransientOutcomes[0].StatusCode = 500
	*data.Interactions[0].TransientOutcomes[0].ErrorCode = "MUTATED"
	*data.Interactions[0].FinalOutcome.StatusCode = 204
	data.Interactions[0].ObservationIDs[0] = "mutated-observation"
	if got := result.Interactions[0]; got.ReplayOf == nil || *got.ReplayOf != "original-replay" || *got.TransientOutcomes[0].StatusCode != 503 || *got.TransientOutcomes[0].ErrorCode != "TEMPORARY" || *got.FinalOutcome.StatusCode != 200 || got.ObservationIDs[0] != "schema-valid-capability-document" {
		t.Fatalf("result retained caller aliases: %#v", got)
	}

	copy := result.Data()
	*copy.Interactions[0].ReplayOf = "second-mutation"
	*copy.Interactions[0].FinalOutcome.StatusCode = 201
	copy.Interactions[0].ObservationIDs[0] = "second-observation"
	if got := result.Interactions[0]; *got.ReplayOf != "original-replay" || *got.FinalOutcome.StatusCode != 200 || got.ObservationIDs[0] != "schema-valid-capability-document" {
		t.Fatalf("Data returned result aliases: %#v", got)
	}
}

func testRequest(t *testing.T) Request {
	t.Helper()
	var descriptors []protocol.ChannelDescriptor
	for index, requirement := range credentials.Requirements() {
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index,
		})
	}
	request, err := NewRequest(protocol.Invocation{
		InvocationID: "run.initial", Phase: "initial", ProviderOrigin: "https://provider.example",
		GatewayProbeEndpoint: "https://gateway.example/tunnel", CallerStateRoot: "/caller/state",
	}, CapabilityCaseID, descriptors, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testResultData() protocol.ScenarioResultData {
	status := 200
	return protocol.ScenarioResultData{
		CaseID: CapabilityCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "controller-a-capabilities", Surface: "provider_http", Actor: "controller_a", Method: "GET",
			RouteTemplate: "/v1/capabilities", LogicalRequestID: "controller-a-capabilities", WireAttempts: 1,
			TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status},
			ObservationIDs: []string{"schema-valid-capability-document"},
		}},
		Assertions: []protocol.AssertionResult{}, ObservationIDs: []string{},
	}
}

func staleResultData() protocol.ScenarioResultData {
	status := 409
	code := "SANDBOX_STALE_FENCING_TOKEN"
	observations := []string{"lower-fencing-token", "rejected-before-dispatch", "closed-standard-error"}
	return protocol.ScenarioResultData{
		CaseID: StaleFencingCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "start-stale-fence-exec", Surface: "provider_http", Actor: "controller_a", Method: "POST",
			RouteTemplate: "/v1/sandboxes/{sandbox_id}/exec", LogicalRequestID: "start-stale-fence-exec", WireAttempts: 1,
			TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status, ErrorCode: &code},
			MutationWriteObserved: true, ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions:     []protocol.AssertionResult{{AssertionID: "caller-did-not-retry-nonretryable-conflict", Result: "asserted"}},
		ObservationIDs: observations,
	}
}

func cancellationResultData() protocol.ScenarioResultData {
	accepted, ok := 202, 200
	interactions := []protocol.InteractionResult{
		{InteractionID: "start-cancellable-exec", Surface: "provider_http", Actor: "controller_a", Method: "POST", RouteTemplate: "/v1/sandboxes/{sandbox_id}/exec", LogicalRequestID: "start-cancellable-exec", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &accepted}, MutationWriteObserved: true, ObservationIDs: []string{"exec-operation-accepted"}},
		{InteractionID: "cancel-exec", Surface: "provider_http", Actor: "controller_a", Method: "POST", RouteTemplate: "/v1/sandboxes/{sandbox_id}/exec:cancel", LogicalRequestID: "cancel-exec", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &accepted}, MutationWriteObserved: true, ObservationIDs: []string{"cancellation-intent-accepted"}},
		{InteractionID: "read-cancel-operation", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-cancel-operation", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &ok}, ObservationIDs: []string{"cancel-operation-succeeded"}},
		{InteractionID: "read-cancelled-operation", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-cancelled-operation", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &ok}, ObservationIDs: []string{"target-exec-operation-cancelled"}},
		{InteractionID: "read-cancelled-result", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/exec-result", LogicalRequestID: "read-cancelled-result", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &ok}, ObservationIDs: []string{"exec-result-cancelled"}},
	}
	return protocol.ScenarioResultData{
		CaseID: ExecCancellationCaseID, Disposition: "completed", Interactions: interactions,
		Assertions:     []protocol.AssertionResult{{AssertionID: "acceptance-not-treated-as-final-cancellation", Result: "asserted"}, {AssertionID: "caller-reconciled-cancel-operation-and-target-exec", Result: "asserted"}},
		ObservationIDs: []string{"exec-operation-accepted", "cancellation-intent-accepted", "cancel-operation-succeeded", "target-exec-operation-cancelled", "exec-result-cancelled"},
	}
}

func terminalResultData() protocol.ScenarioResultData {
	accepted, ok := 202, 200
	return protocol.ScenarioResultData{
		CaseID: TerminalSessionCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "open-terminal-session", Surface: "provider_http", Actor: "controller_a", Method: "POST", RouteTemplate: "/v1/sandboxes/{sandbox_id}/runtime-sessions", LogicalRequestID: "open-terminal-session", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &accepted}, MutationWriteObserved: true, ObservationIDs: []string{"session-operation-accepted"}},
			{InteractionID: "read-terminal-operation", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-terminal-operation", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &ok}, ObservationIDs: []string{"operation-succeeded"}},
			{InteractionID: "read-terminal-handoff", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/runtime-session", LogicalRequestID: "read-terminal-handoff", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &ok}, ObservationIDs: []string{"websocket-protocol", "opaque-reference", "connection-generation-positive"}},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "caller-retained-session-correlation", Result: "asserted"}},
		ObservationIDs: []string{"session-operation-accepted", "operation-succeeded", "websocket-protocol", "opaque-reference", "connection-generation-positive"},
	}
}

func gatewayRoundTripResultData() protocol.ScenarioResultData {
	observations := []string{"grant-bound-to-controller-a", "terminal-bytes-round-tripped", "shell-continuity-challenge-established", "shell-continuity-challenge-digest-recorded", "bounded-byte-count"}
	return protocol.ScenarioResultData{
		CaseID: GatewayRoundTripCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "gateway-terminal-round-trip", Surface: "caller_gateway", Actor: "controller_a", Method: "CONNECT",
			RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-terminal-round-trip", WireAttempts: 1,
			TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "authorized-byte-round-trip"},
			ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions:     []protocol.AssertionResult{{AssertionID: "gateway-policy-owned-by-caller", Result: "asserted"}},
		ObservationIDs: observations,
	}
}

func gatewayAuthorityRejectionResultData() protocol.ScenarioResultData {
	return protocol.ScenarioResultData{
		CaseID: GatewayAuthorityRejectionCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "gateway-missing-caller-credential", Surface: "caller_gateway", Actor: "unauthenticated_client", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-missing-caller-credential", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "gateway-upgrade-rejected"}, ObservationIDs: []string{"no-runtime-connection"}},
			{InteractionID: "gateway-cross-tenant", Surface: "caller_gateway", Actor: "controller_b", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-cross-tenant", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "gateway-upgrade-rejected"}, ObservationIDs: []string{"tenant-b-cannot-use-tenant-a-session", "no-terminal-bytes-forwarded"}},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "controllers-belong-to-distinct-tenants", Result: "asserted"}},
		ObservationIDs: []string{"no-runtime-connection", "tenant-b-cannot-use-tenant-a-session", "no-terminal-bytes-forwarded"},
	}
}

func gatewayGrantExpiryResultData() protocol.ScenarioResultData {
	observations := []string{"grant-initially-authorized", "connection-closed-after-expiry", "no-post-expiry-forwarding"}
	return protocol.ScenarioResultData{
		CaseID: GatewayGrantExpiryCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "gateway-expiring-grant", Surface: "caller_gateway", Actor: "controller_a", Method: "CONNECT",
			RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-expiring-grant", WireAttempts: 1,
			TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "gateway-closed-at-grant-expiry"},
			ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions:     []protocol.AssertionResult{{AssertionID: "caller-enforced-grant-expiry", Result: "asserted"}},
		ObservationIDs: observations,
	}
}

func gatewayRevocationResultData() protocol.ScenarioResultData {
	return protocol.ScenarioResultData{
		CaseID: GatewayRevocationCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "gateway-revocable-grant", Surface: "caller_gateway", Actor: "controller_a", Method: "CONNECT", RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-revocable-grant", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "authorized-byte-round-trip"}, ObservationIDs: []string{"grant-initially-authorized"}},
			{InteractionID: "gateway-revoke-grant", Surface: "caller_gateway", Actor: "controller_a", Method: "CONTROL", RouteTemplate: "consumer-defined:revoke-grant", LogicalRequestID: "gateway-revoke-grant", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "revocation-acknowledged"}, MutationWriteObserved: true, ObservationIDs: []string{"connection-closed-after-revocation", "no-post-revocation-forwarding"}},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "revocation-authority-owned-by-caller", Result: "asserted"}},
		ObservationIDs: []string{"grant-initially-authorized", "connection-closed-after-revocation", "no-post-revocation-forwarding"},
	}
}

func artifactResultData() protocol.ScenarioResultData {
	status202, status200 := 202, 200
	return protocol.ScenarioResultData{
		CaseID: ArtifactStagingCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "stage-artifact", Surface: "provider_http", Actor: "controller_a", Method: "POST", RouteTemplate: "/v1/sandboxes/{sandbox_id}/artifacts:stage", LogicalRequestID: "stage-artifact", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status202}, MutationWriteObserved: true, ObservationIDs: []string{"artifact-operation-accepted"}},
			{InteractionID: "read-artifact-operation", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-artifact-operation", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status200}, ObservationIDs: []string{"operation-succeeded"}},
			{InteractionID: "read-artifact-evidence", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}/artifact-staging-evidence", LogicalRequestID: "read-artifact-evidence", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status200}, ObservationIDs: []string{"artifact-status-staged", "content-digest-and-size-match", "opaque-staging-reference"}},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "caller-kept-aggregate-artifact-truth", Result: "asserted"}},
		ObservationIDs: []string{"artifact-operation-accepted", "operation-succeeded", "artifact-status-staged", "content-digest-and-size-match", "opaque-staging-reference"},
	}
}

func crossTenantArtifactResultData() protocol.ScenarioResultData {
	status403, status404 := 403, 404
	forbidden, notFound := "SANDBOX_FORBIDDEN", "SANDBOX_NOT_FOUND"
	return protocol.ScenarioResultData{
		CaseID: CrossTenantArtifactCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "cross-tenant-stage-artifact", Surface: "provider_http", Actor: "controller_b", Method: "POST", RouteTemplate: "/v1/sandboxes/{sandbox_id}/artifacts:stage", LogicalRequestID: "cross-tenant-stage-artifact", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status403, ErrorCode: &forbidden}, MutationWriteObserved: true, ObservationIDs: []string{"controller-b-tenant-b-request", "rejected-before-artifact-dispatch", "no-backend-disclosure"}},
			{InteractionID: "cross-tenant-read-artifact-operation", Surface: "provider_http", Actor: "controller_b", Method: "GET", RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "cross-tenant-read-artifact-operation", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status404, ErrorCode: &notFound}, ObservationIDs: []string{"no-cross-tenant-operation-visible"}},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "distinct-tenant-negative-case", Result: "asserted"}},
		ObservationIDs: []string{"controller-b-tenant-b-request", "rejected-before-artifact-dispatch", "no-backend-disclosure", "no-cross-tenant-operation-visible"},
	}
}

func mtlsCallerBindingResultData() protocol.ScenarioResultData {
	status := 403
	forbidden := "SANDBOX_FORBIDDEN"
	observations := []string{"admitted-controller-b-certificate", "controller-a-signed-subject", "rejected-before-state-read"}
	return protocol.ScenarioResultData{
		CaseID: MTLSCallerBindingCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{InteractionID: "wrong-mtls-caller-read-sandbox", Surface: "provider_http", Actor: "controller_b", Method: "GET", RouteTemplate: "/v1/sandboxes/{sandbox_id}", LogicalRequestID: "wrong-mtls-caller-read-sandbox", WireAttempts: 1, TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: &status, ErrorCode: &forbidden}, ObservationIDs: append([]string(nil), observations...)}},
		Assertions:   []protocol.AssertionResult{{AssertionID: "mtls-and-jws-caller-must-match", Result: "asserted"}}, ObservationIDs: observations,
	}
}
