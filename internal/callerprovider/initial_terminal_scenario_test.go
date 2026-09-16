//go:build darwin || linux

package callerprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestTerminalSessionRetainsPrivateHandoffAndBindsCorrelation(t *testing.T) {
	executor, client, store := cancellationCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.TerminalSessionCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.TerminalSessionCaseID || result.Disposition != "completed" || len(result.Interactions) != 3 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, []string{"session-operation-accepted", "operation-succeeded", "websocket-protocol", "opaque-reference", "connection-generation-positive"}) {
		t.Fatalf("terminal result = %#v", result)
	}
	for index, status := range []int{202, 200, 200} {
		interaction := result.Interactions[index]
		if interaction.WireAttempts != 1 || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != status || interaction.MutationWriteObserved != (index == 0) {
			t.Fatalf("interaction %d = %#v", index, interaction)
		}
	}
	state := store.Snapshot()
	if state.Stage != callerstate.StageTerminalBound || state.StoreRevision != 5 || state.Terminal == nil || state.Terminal.Operation.FencingToken != terminalScenarioFencingToken || state.Terminal.RuntimeSessionID != executor.terminalHandoff.RuntimeSessionID || executor.next != 8 || len(client.sessions) != 1 || executor.terminalRequest.RequestDigest == "" || executor.terminalAdmission.BearerToken == "" || executor.terminalOperation.Status != "succeeded" || executor.terminalHandoff.InternalEndpointReference == "" {
		t.Fatalf("terminal correlation = state %#v / request %#v / operation %#v / handoff %#v", state, executor.terminalRequest, executor.terminalOperation, executor.terminalHandoff)
	}
	public, err := json.Marshal(result)
	if err != nil || string(public) == "" || containsBytes(public, []byte(executor.terminalHandoff.InternalEndpointReference)) {
		t.Fatalf("public result exposed opaque handoff: %q / %v", public, err)
	}
}

func TestTerminalSessionRejectsInvalidHandoffWithoutBindingState(t *testing.T) {
	for _, name := range []string{"wrong protocol", "wrong reference", "zero generation", "expired", "extended"} {
		t.Run(name, func(t *testing.T) {
			executor, client, store := cancellationCompletedScenarioExecutor(t)
			defer executor.Close()
			defer store.Close()
			before := store.Snapshot()
			client.handoffHook = func(handoff *provider.RuntimeSessionHandoff) {
				switch name {
				case "wrong protocol":
					handoff.Protocol = "ssh"
				case "wrong reference":
					handoff.InternalEndpointReference = "https://backend.example/private"
				case "zero generation":
					handoff.ConnectionGeneration = 0
				case "expired":
					handoff.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
				case "extended":
					handoff.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := executor.Execute(ctx, scenariocontrol.TerminalSessionCaseID); !errors.Is(err, ErrInitialScenario) {
				t.Fatalf("invalid handoff error = %v", err)
			}
			if executor.next != 7 || !reflect.DeepEqual(store.Snapshot(), before) || executor.terminalHandoff.InternalEndpointReference != "" {
				t.Fatalf("invalid handoff changed state/private authority: before %#v / after %#v", before, store.Snapshot())
			}
		})
	}
}

func TestSubmitRuntimeSessionRepeatsExactAuthorityOnlyAfterRetryable503(t *testing.T) {
	retryAfter := 1
	client := &fakeClient{}
	client.sessionHook = func(call int, _ provider.RuntimeSessionOpenRequest, _ provider.Admission) error {
		if call == 1 {
			return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}, RetryAfterSeconds: &retryAfter}
		}
		return nil
	}
	request := provider.RuntimeSessionOpenRequest{OperationID: "terminal-operation", AttemptID: "terminal-attempt", FencingToken: terminalScenarioFencingToken}
	admission := provider.Admission{BearerToken: "same-admission"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	operation, attempts, transients, err := submitRuntimeSession(ctx, client, "sandbox-1", request, admission)
	if err != nil || operation.Status != "accepted" || attempts != 2 || len(transients) != 1 || len(client.sessions) != 2 || !reflect.DeepEqual(client.sessions[0], client.sessions[1]) || len(client.admissions) != 2 || !reflect.DeepEqual(client.admissions[0], client.admissions[1]) {
		t.Fatalf("bounded session retry = operation %#v, attempts %d, transients %#v, error %v", operation, attempts, transients, err)
	}
}

func cancellationCompletedScenarioExecutor(t *testing.T) (*InitialScenarioExecutor, *fakeClient, *callerstate.Store) {
	t.Helper()
	executor, client, store := staleCompletedScenarioExecutor(t)
	var cancellable provider.ExecRequest
	client.execHook = func(call int, request provider.ExecRequest, _ provider.Admission) error {
		if call != 3 {
			t.Fatalf("unexpected cancellable exec call = %d", call)
		}
		cancellable = request
		return nil
	}
	var cancellation provider.CancelExecRequest
	client.cancelHook = func(_ int, request provider.CancelExecRequest, _ provider.Admission) error {
		cancellation = request
		return nil
	}
	client.operationHook = func(operation *provider.ProviderOperation) {
		switch operation.OperationID {
		case cancellation.OperationID:
			operation.Type, operation.Status = "cancel_exec", "succeeded"
		case cancellable.OperationID:
			operation.Type, operation.Status = "exec", "cancelled"
		}
	}
	client.resultHook = func(result *provider.ExecResult) {
		result.Status, result.ExitCode, result.StdoutReference = "cancelled", nil, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.ExecCancellationCaseID); err != nil {
		executor.Close()
		store.Close()
		t.Fatal(err)
	}
	client.execHook, client.cancelHook, client.operationHook, client.resultHook = nil, nil, nil, nil
	return executor, client, store
}

func containsBytes(document, value []byte) bool {
	if len(value) == 0 || len(value) > len(document) {
		return false
	}
	for index := 0; index+len(value) <= len(document); index++ {
		if reflect.DeepEqual(document[index:index+len(value)], value) {
			return true
		}
	}
	return false
}
