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

func TestStaleFencingRejectsBeforeDispatchWithoutRetryOrStateChange(t *testing.T) {
	executor, client, store := execBoundScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()

	before := store.Snapshot()
	accepted := executor.exec
	client.execHook = func(call int, request provider.ExecRequest, admission provider.Admission) error {
		if call != 2 {
			t.Fatalf("unexpected stale exec call = %d", call)
		}
		if request.FencingToken >= accepted.FencingToken || request.OperationID == accepted.OperationID || request.AttemptID == accepted.AttemptID || request.IdempotencyKey == accepted.IdempotencyKey || admission.Context.RequestDigest != request.RequestDigest {
			t.Fatalf("stale request/admission = %#v / %#v", request, admission.Context)
		}
		return &provider.HTTPError{StatusCode: http.StatusConflict, Document: provider.StandardError{
			Code: "SANDBOX_STALE_FENCING_TOKEN", Message: "stale exec fencing token", Retryable: false, TraceID: "test-trace",
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.StaleFencingCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.StaleFencingCaseID || result.Disposition != "completed" || len(result.Interactions) != 1 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, []string{"lower-fencing-token", "rejected-before-dispatch", "closed-standard-error"}) {
		t.Fatalf("stale fencing result = %#v", result)
	}
	interaction := result.Interactions[0]
	if interaction.WireAttempts != 1 || len(interaction.TransientOutcomes) != 0 || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != http.StatusConflict || interaction.FinalOutcome.ErrorCode == nil || *interaction.FinalOutcome.ErrorCode != "SANDBOX_STALE_FENCING_TOKEN" || interaction.FinalOutcome.Retryable || interaction.FinalOutcome.RetryAfterPresent || !interaction.MutationWriteObserved {
		t.Fatalf("stale fencing interaction = %#v", interaction)
	}
	if len(client.execs) != 2 || executor.next != 6 || !reflect.DeepEqual(store.Snapshot(), before) || before.Stage != callerstate.StageExecBound || before.StoreRevision != 4 {
		t.Fatalf("stale rejection changed durable state/progress = calls %d, next %d, before %#v, after %#v", len(client.execs), executor.next, before, store.Snapshot())
	}
}

func TestStaleFencingFailsClosedWhenProviderAcceptsRequest(t *testing.T) {
	executor, client, store := execBoundScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	before := store.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.StaleFencingCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("accepted stale fencing error = %v", err)
	}
	if len(client.execs) != 2 || executor.next != 5 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("accepted stale fencing changed state/progress = calls %d, next %d, before %#v, after %#v", len(client.execs), executor.next, before, store.Snapshot())
	}
}

func TestStaleFencingRejectsInvalidConflictShapes(t *testing.T) {
	retryAfter := 1
	for name, response := range map[string]*provider.HTTPError{
		"wrong code": {
			StatusCode: http.StatusConflict,
			Document:   provider.StandardError{Code: "UNRELATED_CONFLICT", Message: "wrong conflict", Retryable: false, TraceID: "test-trace"},
		},
		"retryable": {
			StatusCode: http.StatusConflict,
			Document:   provider.StandardError{Code: "SANDBOX_CONFLICT", Message: "retryable conflict", Retryable: true, TraceID: "test-trace"},
		},
		"retry after": {
			StatusCode:        http.StatusConflict,
			Document:          provider.StandardError{Code: "SANDBOX_STALE_FENCING_TOKEN", Message: "delayed conflict", Retryable: false, TraceID: "test-trace"},
			RetryAfterSeconds: &retryAfter,
		},
	} {
		t.Run(name, func(t *testing.T) {
			executor, client, store := execBoundScenarioExecutor(t)
			defer executor.Close()
			defer store.Close()
			before := store.Snapshot()
			client.execHook = func(int, provider.ExecRequest, provider.Admission) error { return response }
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := executor.Execute(ctx, scenariocontrol.StaleFencingCaseID); !errors.Is(err, ErrInitialScenario) {
				t.Fatalf("invalid conflict error = %v", err)
			}
			if len(client.execs) != 2 || executor.next != 5 || !reflect.DeepEqual(store.Snapshot(), before) {
				t.Fatalf("invalid conflict changed state/progress = calls %d, next %d, before %#v, after %#v", len(client.execs), executor.next, before, store.Snapshot())
			}
		})
	}
}

func TestSubmitRejectedExecRepeatsExactRequestOnlyAfterRetryableTransient(t *testing.T) {
	retryAfter := 1
	client := &fakeClient{}
	client.execHook = func(call int, _ provider.ExecRequest, _ provider.Admission) error {
		if call == 1 {
			return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}, RetryAfterSeconds: &retryAfter}
		}
		return &provider.HTTPError{StatusCode: http.StatusConflict, Document: provider.StandardError{Code: "SANDBOX_CONFLICT", Message: "stale", Retryable: false, TraceID: "test-trace"}}
	}
	request := provider.ExecRequest{OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1}
	admission := provider.Admission{BearerToken: "same-admission"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	attempts, transients, rejection, err := submitRejectedExec(ctx, client, "sandbox-1", request, admission)
	if err != nil || attempts != 2 || len(transients) != 1 || rejection == nil || rejection.StatusCode != http.StatusConflict || len(client.execs) != 2 || !reflect.DeepEqual(client.execs[0], client.execs[1]) || len(client.admissions) != 2 || !reflect.DeepEqual(client.admissions[0], client.admissions[1]) {
		t.Fatalf("bounded stale retry = attempts %d, transients %#v, rejection %#v, error %v, requests %#v, admissions %#v", attempts, transients, rejection, err, client.execs, client.admissions)
	}
}

func execBoundScenarioExecutor(t *testing.T) (*InitialScenarioExecutor, *fakeClient, *callerstate.Store) {
	t.Helper()
	store := initialStore(t)
	capabilities, raw := selectedCapabilities(t)
	if err := store.BindCapabilities(capabilities.ProviderRevisionID, raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		store.Close()
		t.Fatal(err)
	}
	client := &fakeClient{
		store: store, operations: []string{"succeeded", "succeeded"}, statuses: []string{"ready"},
		createHook: func(call int, _ provider.CreateSandboxRequest, _ provider.Admission) error {
			if call == 2 {
				return &provider.HTTPError{StatusCode: http.StatusConflict, Document: provider.StandardError{Code: "JTI_REPLAY", Message: "replayed", Retryable: false, TraceID: "test-trace"}}
			}
			return nil
		},
	}
	closed := 0
	controller, err := fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)(nil, "https://provider.example", "controller_a")
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	executor := &InitialScenarioExecutor{store: store, now: time.Now, next: 1, capabilities: capabilities, controllerA: controller}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, caseID := range []string{scenariocontrol.LifecycleCaseID, scenariocontrol.ReplayCaseID, scenariocontrol.LifecycleCompletionCaseID, scenariocontrol.ExecResultUsageCaseID} {
		if _, err := executor.Execute(ctx, caseID); err != nil {
			executor.Close()
			store.Close()
			t.Fatalf("advance %s: %v", caseID, err)
		}
	}
	return executor, client, store
}
