//go:build darwin || linux

package callerprovider

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestExecCancellationReconcilesIntentTargetAndResultWithoutChangingState(t *testing.T) {
	executor, client, store := staleCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	before := store.Snapshot()

	var cancellable provider.ExecRequest
	client.execHook = func(call int, request provider.ExecRequest, _ provider.Admission) error {
		if call != 3 || request.FencingToken != cancellableExecFencingToken {
			t.Fatalf("cancellable exec call = %d / %#v", call, request)
		}
		cancellable = request
		return nil
	}
	var cancellation provider.CancelExecRequest
	client.cancelHook = func(call int, request provider.CancelExecRequest, admission provider.Admission) error {
		if call != 1 || request.FencingToken != cancelExecFencingToken || request.TargetOperationID != cancellable.OperationID || request.TargetAttemptID != cancellable.AttemptID || request.Reason != "caller_requested" || admission.Context.RequestDigest != request.RequestDigest {
			t.Fatalf("cancel request/admission = %d / %#v / %#v", call, request, admission.Context)
		}
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
	result, err := executor.Execute(ctx, scenariocontrol.ExecCancellationCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.ExecCancellationCaseID || result.Disposition != "completed" || len(result.Interactions) != 5 || len(result.Assertions) != 2 || !reflect.DeepEqual(result.ObservationIDs, []string{"exec-operation-accepted", "cancellation-intent-accepted", "cancel-operation-succeeded", "target-exec-operation-cancelled", "exec-result-cancelled"}) {
		t.Fatalf("exec cancellation result = %#v", result)
	}
	for index, wantStatus := range []int{202, 202, 200, 200, 200} {
		interaction := result.Interactions[index]
		if interaction.WireAttempts != 1 || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != wantStatus || interaction.MutationWriteObserved != (index < 2) {
			t.Fatalf("interaction %d = %#v", index, interaction)
		}
	}
	if cancellable.FencingToken <= before.Exec.Operation.FencingToken || cancellation.FencingToken <= cancellable.FencingToken || len(client.execs) != 3 || len(client.cancels) != 1 || executor.next != 7 || !reflect.DeepEqual(store.Snapshot(), before) || before.Stage != callerstate.StageExecBound || before.StoreRevision != 4 {
		t.Fatalf("cancel composition/state = execs %d, cancels %d, next %d, cancellable %#v, cancel %#v, before %#v, after %#v", len(client.execs), len(client.cancels), executor.next, cancellable, cancellation, before, store.Snapshot())
	}
}

func TestExecCancellationFailsClosedWithoutCancelledTarget(t *testing.T) {
	executor, client, store := staleCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	before := store.Snapshot()
	client.operationHook = func(operation *provider.ProviderOperation) {
		if operation.Type == "create" {
			operation.Type = "cancel_exec"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.ExecCancellationCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("non-cancelled target error = %v", err)
	}
	if executor.next != 6 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("failed cancellation changed durable state/progress = next %d, before %#v, after %#v", executor.next, before, store.Snapshot())
	}
}

func TestSubmitCancelExecRepeatsExactAuthorityOnlyAfterRetryable503(t *testing.T) {
	retryAfter := 1
	client := &fakeClient{}
	client.cancelHook = func(call int, _ provider.CancelExecRequest, _ provider.Admission) error {
		if call == 1 {
			return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}, RetryAfterSeconds: &retryAfter}
		}
		return nil
	}
	request := provider.CancelExecRequest{OperationID: "cancel-operation", AttemptID: "cancel-attempt", FencingToken: 4}
	admission := provider.Admission{BearerToken: "same-admission"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	operation, attempts, transients, err := submitCancelExec(ctx, client, "sandbox-1", request, admission)
	if err != nil || operation.Status != "accepted" || attempts != 2 || len(transients) != 1 || len(client.cancels) != 2 || !reflect.DeepEqual(client.cancels[0], client.cancels[1]) || len(client.admissions) != 2 || !reflect.DeepEqual(client.admissions[0], client.admissions[1]) {
		t.Fatalf("bounded cancel retry = operation %#v, attempts %d, transients %#v, error %v, requests %#v, admissions %#v", operation, attempts, transients, err, client.cancels, client.admissions)
	}
}

func staleCompletedScenarioExecutor(t *testing.T) (*InitialScenarioExecutor, *fakeClient, *callerstate.Store) {
	t.Helper()
	executor, client, store := execBoundScenarioExecutor(t)
	client.execHook = func(call int, _ provider.ExecRequest, _ provider.Admission) error {
		if call != 2 {
			t.Fatalf("unexpected stale exec call = %d", call)
		}
		return &provider.HTTPError{StatusCode: http.StatusConflict, Document: provider.StandardError{Code: "SANDBOX_STALE_FENCING_TOKEN", Message: "stale", Retryable: false, TraceID: "test-trace"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.StaleFencingCaseID); err != nil {
		executor.Close()
		store.Close()
		t.Fatal(err)
	}
	client.execHook = nil
	return executor, client, store
}
