//go:build darwin || linux

package callerprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestProtectedCreateRetainsExactReplayAuthorityWithoutAdvancingState(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	if err := store.BindCapabilities(capabilities.ProviderRevisionID, raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	client := &fakeClient{store: store}
	closed := 0
	controller, err := fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)(nil, "https://provider.example", "controller_a")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	executor := &InitialScenarioExecutor{
		store: store, now: func() time.Time { return base }, next: 1,
		capabilities: capabilities, controllerA: controller,
	}
	defer executor.Close()
	before := store.Snapshot()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.LifecycleCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.LifecycleCaseID || len(client.creates) != 1 || len(client.admissions) != 1 || executor.create.RequestDigest == "" || executor.admission.BearerToken == "" || executor.operation.OperationID == "" {
		t.Fatalf("retained create authority/result = %#v / %#v", executor, result)
	}
	if !reflect.DeepEqual(executor.create, client.creates[0]) || !reflect.DeepEqual(executor.admission, client.admissions[0]) || executor.operation.OperationID != executor.create.OperationID || executor.operation.AttemptID != executor.create.AttemptID {
		t.Fatal("Caller did not retain the exact submitted create authority")
	}
	if after := store.Snapshot(); !reflect.DeepEqual(after, before) || after.Stage != callerstate.StageCapabilitiesBound || after.StoreRevision != 2 {
		t.Fatalf("protected create advanced durable state = %#v", after)
	}
	if got, want := result.Assertions, []protocol.AssertionResult{
		{AssertionID: "caller-constructed-mtls-jws-and-admission-context", Result: "asserted"},
		{AssertionID: "caller-retained-durable-correlation", Result: "asserted"},
		{AssertionID: "run-owned-sandbox-id", Result: "asserted"},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("protected create assertions = %#v, want %#v", got, want)
	}
}

func TestProtectedCreateWireRetryReusesExactRequestAndAdmission(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	if err := store.BindCapabilities(capabilities.ProviderRevisionID, raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	delay := 1
	client := &fakeClient{store: store, createHook: func(call int, _ provider.CreateSandboxRequest, _ provider.Admission) error {
		if call == 1 {
			return &provider.HTTPError{
				StatusCode: http.StatusServiceUnavailable,
				Document: provider.StandardError{
					Code: "TEST_PROVIDER_UNAVAILABLE", Message: "temporary create failure", Retryable: true, TraceID: "test-trace",
				},
				RetryAfterSeconds: &delay,
			}
		}
		return nil
	}}
	closed := 0
	controller, err := fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)(nil, "https://provider.example", "controller_a")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	executor := &InitialScenarioExecutor{
		store: store, now: func() time.Time { return base }, next: 1,
		capabilities: capabilities, controllerA: controller,
	}
	defer executor.Close()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(3*time.Second))
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.LifecycleCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.creates) != 2 || len(client.admissions) != 2 || !reflect.DeepEqual(client.creates[0], client.creates[1]) || !reflect.DeepEqual(client.admissions[0], client.admissions[1]) {
		t.Fatalf("wire retry changed request or Admission: creates=%#v admissions=%#v", client.creates, client.admissions)
	}
	interaction := result.Interactions[0]
	if interaction.WireAttempts != 2 || len(interaction.TransientOutcomes) != 1 || interaction.TransientOutcomes[0].StatusCode == nil || *interaction.TransientOutcomes[0].StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("wire retry result = %#v", interaction)
	}
}

func TestReplaySemanticsSeparateExactJTIRejectionFromFreshJTIIdempotency(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	if err := store.BindCapabilities(capabilities.ProviderRevisionID, raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	client := &fakeClient{store: store, createHook: func(call int, _ provider.CreateSandboxRequest, _ provider.Admission) error {
		if call == 2 {
			return &provider.HTTPError{
				StatusCode: http.StatusConflict,
				Document:   provider.StandardError{Code: "JTI_REPLAY", Message: "admission JTI was already consumed", Retryable: false, TraceID: "test-trace"},
			}
		}
		return nil
	}}
	closed := 0
	controller, err := fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)(nil, "https://provider.example", "controller_a")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	executor := &InitialScenarioExecutor{
		store: store, now: func() time.Time { return base }, next: 1,
		capabilities: capabilities, controllerA: controller,
	}
	defer executor.Close()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	before := store.Snapshot()
	if _, err := executor.Execute(ctx, scenariocontrol.LifecycleCaseID); err != nil {
		t.Fatal(err)
	}
	originalAdmission := executor.admission
	result, err := executor.Execute(ctx, scenariocontrol.ReplayCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.creates) != 3 || len(client.admissions) != 3 || !reflect.DeepEqual(client.creates[0], client.creates[1]) || !reflect.DeepEqual(client.creates[0], client.creates[2]) || !reflect.DeepEqual(client.admissions[0], client.admissions[1]) {
		t.Fatalf("replay request/Admission sequence = creates %#v, admissions %#v", client.creates, client.admissions)
	}
	if client.admissions[2].Claims.JTI == originalAdmission.Claims.JTI || client.admissions[2].BearerToken == originalAdmission.BearerToken || !reflect.DeepEqual(client.admissions[2].Context, originalAdmission.Context) {
		t.Fatalf("fresh replay Admission = %#v, original %#v", client.admissions[2], originalAdmission)
	}
	if got, want := result.Assertions, []protocol.AssertionResult{
		{AssertionID: "jti-replay-is-not-idempotency-replay", Result: "asserted"},
		{AssertionID: "idempotency-key-body-operation-and-fence-unchanged", Result: "asserted"},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("replay assertions = %#v, want %#v", got, want)
	}
	if len(result.Interactions) != 2 || result.Interactions[0].FinalOutcome.StatusCode == nil || *result.Interactions[0].FinalOutcome.StatusCode != http.StatusConflict || result.Interactions[1].FinalOutcome.StatusCode == nil || *result.Interactions[1].FinalOutcome.StatusCode != http.StatusAccepted {
		t.Fatalf("replay interactions = %#v", result.Interactions)
	}
	if after := store.Snapshot(); !reflect.DeepEqual(after, before) || after.Stage != callerstate.StageCapabilitiesBound || after.StoreRevision != 2 {
		t.Fatalf("replay semantics advanced durable state = %#v", after)
	}
}

func TestReplaySemanticsRejectsExactJTIAcceptedAsIdempotency(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	if err := store.BindCapabilities(capabilities.ProviderRevisionID, raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	client := &fakeClient{store: store}
	closed := 0
	controller, err := fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)(nil, "https://provider.example", "controller_a")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	executor := &InitialScenarioExecutor{
		store: store, now: func() time.Time { return base }, next: 1,
		capabilities: capabilities, controllerA: controller,
	}
	defer executor.Close()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.LifecycleCaseID); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	if _, err := executor.Execute(ctx, scenariocontrol.ReplayCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("accepted exact-JTI replay error = %v", err)
	}
	if len(client.creates) != 2 || executor.next != 2 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("rejected replay changed progress/state: calls=%d next=%d state=%#v", len(client.creates), executor.next, store.Snapshot())
	}
}

func TestReplayIdentityAllowsCurrentOperationProgressButRejectsDifferentOperation(t *testing.T) {
	original := provider.ProviderOperation{OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1", Type: "create", Status: "accepted"}
	progressed := original
	progressed.Status = "succeeded"
	if !sameCreateOperationIdentity(progressed, original) {
		t.Fatal("idempotency replay rejected the same progressed operation")
	}
	progressed.OperationID = "operation-2"
	if sameCreateOperationIdentity(progressed, original) {
		t.Fatal("idempotency replay accepted a different operation")
	}
}

func TestLifecycleCompletionPollsWithFreshAdmissionAndBindsOnlyReadyGenerationOne(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	if err := store.BindCapabilities(capabilities.ProviderRevisionID, raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	retryAfter := 1
	operationCalls := 0
	client := &fakeClient{
		store:      store,
		operations: []string{"accepted", "running", "succeeded"},
		statuses:   []string{"provisioning", "ready"},
		createHook: func(call int, _ provider.CreateSandboxRequest, _ provider.Admission) error {
			if call == 2 {
				return &provider.HTTPError{StatusCode: http.StatusConflict, Document: provider.StandardError{Code: "JTI_REPLAY", Message: "replayed", Retryable: false, TraceID: "test-trace"}}
			}
			return nil
		},
		hook: func(string) error {
			operationCalls++
			if operationCalls == 1 {
				return &provider.HTTPError{
					StatusCode:        http.StatusServiceUnavailable,
					Document:          provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"},
					RetryAfterSeconds: &retryAfter,
				}
			}
			return nil
		},
	}
	closed := 0
	controller, err := fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)(nil, "https://provider.example", "controller_a")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	executor := &InitialScenarioExecutor{store: store, now: func() time.Time { return base }, next: 1, capabilities: capabilities, controllerA: controller}
	defer executor.Close()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.LifecycleCaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(ctx, scenariocontrol.ReplayCaseID); err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(ctx, scenariocontrol.LifecycleCompletionCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Interactions) != 2 || result.Interactions[0].WireAttempts != 4 || len(result.Interactions[0].TransientOutcomes) != 1 || result.Interactions[1].WireAttempts != 2 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, []string{"operation-succeeded", "sandbox-ready", "generation-one", "tenant-a-binding"}) {
		t.Fatalf("lifecycle completion result = %#v", result)
	}
	if transient := result.Interactions[0].TransientOutcomes[0]; transient.StatusCode == nil || *transient.StatusCode != http.StatusServiceUnavailable || !transient.Retryable || !transient.RetryAfterPresent {
		t.Fatalf("operation transient = %#v", transient)
	}
	state := store.Snapshot()
	if state.Stage != callerstate.StageLifecycleBound || state.StoreRevision != 3 || state.Lifecycle == nil || state.Lifecycle.OperationID != state.Plan.Create.OperationID || executor.operation.Status != "succeeded" || executor.sandbox.ObservedState != "ready" {
		t.Fatalf("lifecycle-bound state/result = %#v / %#v / %#v", state, executor.operation, executor.sandbox)
	}
	if len(client.admissions) != 9 {
		t.Fatalf("Admission count = %d, want 9", len(client.admissions))
	}
	seen := map[string]struct{}{}
	for _, admission := range client.admissions[3:] {
		if admission.Claims.JTI == "" {
			t.Fatal("read Admission has empty JTI")
		}
		if _, duplicate := seen[admission.Claims.JTI]; duplicate {
			t.Fatalf("read Admission reused JTI %q", admission.Claims.JTI)
		}
		seen[admission.Claims.JTI] = struct{}{}
	}
}

func TestLifecycleCompletionFailurePreservesCapabilitiesBoundState(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	if err := store.BindCapabilities(capabilities.ProviderRevisionID, raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	client := &fakeClient{
		store:      store,
		operations: []string{"succeeded"},
		statuses:   []string{"failed"},
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
		t.Fatal(err)
	}
	base := time.Now().UTC()
	executor := &InitialScenarioExecutor{store: store, now: func() time.Time { return base }, next: 1, capabilities: capabilities, controllerA: controller}
	defer executor.Close()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.LifecycleCaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(ctx, scenariocontrol.ReplayCaseID); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	if _, err := executor.Execute(ctx, scenariocontrol.LifecycleCompletionCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("failed lifecycle error = %v", err)
	}
	if after := store.Snapshot(); !reflect.DeepEqual(after, before) || after.Stage != callerstate.StageCapabilitiesBound || after.StoreRevision != 2 || executor.next != 3 {
		t.Fatalf("failed lifecycle changed state/progress = %#v / %d", after, executor.next)
	}
}

func TestExecResultUsageBindsActualDocumentsAndReportsLockedInteractions(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	if err := store.BindCapabilities(capabilities.ProviderRevisionID, raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	retryAfter := 1
	execCalls := 0
	usageCalls := 0
	client := &fakeClient{
		store:      store,
		operations: []string{"succeeded", "accepted", "running", "succeeded"},
		statuses:   []string{"ready"},
		createHook: func(call int, _ provider.CreateSandboxRequest, _ provider.Admission) error {
			if call == 2 {
				return &provider.HTTPError{StatusCode: http.StatusConflict, Document: provider.StandardError{Code: "JTI_REPLAY", Message: "replayed", Retryable: false, TraceID: "test-trace"}}
			}
			return nil
		},
		hook: func(step string) error {
			if step == "exec" {
				execCalls++
				if execCalls == 1 {
					return &provider.HTTPError{
						StatusCode:        http.StatusServiceUnavailable,
						Document:          provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"},
						RetryAfterSeconds: &retryAfter,
					}
				}
			}
			if step == "usage" {
				usageCalls++
				if usageCalls == 1 {
					return &provider.HTTPError{
						StatusCode:        http.StatusServiceUnavailable,
						Document:          provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"},
						RetryAfterSeconds: &retryAfter,
					}
				}
			}
			return nil
		},
	}
	closed := 0
	controller, err := fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)(nil, "https://provider.example", "controller_a")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	executor := &InitialScenarioExecutor{store: store, now: time.Now, next: 1, capabilities: capabilities, controllerA: controller}
	defer executor.Close()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	for _, caseID := range []string{scenariocontrol.LifecycleCaseID, scenariocontrol.ReplayCaseID, scenariocontrol.LifecycleCompletionCaseID} {
		if _, err := executor.Execute(ctx, caseID); err != nil {
			t.Fatalf("advance %s: %v", caseID, err)
		}
	}
	result, err := executor.Execute(ctx, scenariocontrol.ExecResultUsageCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Interactions) != 4 || result.Interactions[0].WireAttempts != 2 || len(result.Interactions[0].TransientOutcomes) != 1 || result.Interactions[1].WireAttempts != 3 || result.Interactions[2].WireAttempts != 1 || result.Interactions[3].WireAttempts != 2 || len(result.Interactions[3].TransientOutcomes) != 1 || len(result.Assertions) != 2 || !reflect.DeepEqual(result.ObservationIDs, []string{"exec-operation-accepted", "single-exec-dispatch", "operation-succeeded", "exec-completed-zero-exit", "opaque-output-reference", "usage-entry-present", "reconciliation-status-present"}) {
		t.Fatalf("exec result/usage scenario = %#v", result)
	}
	if transient := result.Interactions[0].TransientOutcomes[0]; transient.StatusCode == nil || *transient.StatusCode != http.StatusServiceUnavailable || !transient.Retryable || !transient.RetryAfterPresent {
		t.Fatalf("exec transient = %#v", transient)
	}
	if transient := result.Interactions[3].TransientOutcomes[0]; transient.StatusCode == nil || *transient.StatusCode != http.StatusServiceUnavailable || !transient.Retryable || !transient.RetryAfterPresent {
		t.Fatalf("usage transient = %#v", transient)
	}
	if len(client.execs) != 2 || !reflect.DeepEqual(client.execs[0], client.execs[1]) {
		t.Fatalf("exec retry requests = %#v", client.execs)
	}
	state := store.Snapshot()
	resultDigest, _ := jcs.Digest(client.result)
	usageDigest, _ := jcs.Digest(client.usage)
	if state.Stage != callerstate.StageExecBound || state.StoreRevision != 4 || state.Exec == nil || state.Exec.ResultDigest != resultDigest || state.Exec.UsageEvidenceDigest != usageDigest || executor.execResult.StdoutReference == "" {
		t.Fatalf("exec-bound state/result = %#v / %#v", state, executor.execResult)
	}
	wire, err := json.Marshal(result)
	if err != nil || bytes.Contains(wire, []byte("external-caller")) || bytes.Contains(wire, []byte(executor.execResult.StdoutReference)) {
		t.Fatalf("public result exposed command output/reference: %q, %v", wire, err)
	}
	if len(client.admissions) != 13 || !reflect.DeepEqual(client.admissions[5], client.admissions[6]) {
		t.Fatalf("Admission sequence/retry = %d / %#v", len(client.admissions), client.admissions)
	}
	seen := map[string]struct{}{}
	for _, admission := range client.admissions[7:] {
		if _, duplicate := seen[admission.Claims.JTI]; duplicate {
			t.Fatalf("read Admission reused JTI %q", admission.Claims.JTI)
		}
		seen[admission.Claims.JTI] = struct{}{}
	}
}

func TestExecResultUsageRejectsMissingOutputReferenceWithoutAdvancing(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	if err := store.BindCapabilities(capabilities.ProviderRevisionID, raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	client := &fakeClient{
		store:      store,
		operations: []string{"succeeded", "succeeded"},
		statuses:   []string{"ready"},
		createHook: func(call int, _ provider.CreateSandboxRequest, _ provider.Admission) error {
			if call == 2 {
				return &provider.HTTPError{StatusCode: http.StatusConflict, Document: provider.StandardError{Code: "JTI_REPLAY", Message: "replayed", Retryable: false, TraceID: "test-trace"}}
			}
			return nil
		},
		resultHook: func(result *provider.ExecResult) { result.StdoutReference = "" },
	}
	closed := 0
	controller, err := fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)(nil, "https://provider.example", "controller_a")
	if err != nil {
		t.Fatal(err)
	}
	executor := &InitialScenarioExecutor{store: store, now: time.Now, next: 1, capabilities: capabilities, controllerA: controller}
	defer executor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, caseID := range []string{scenariocontrol.LifecycleCaseID, scenariocontrol.ReplayCaseID, scenariocontrol.LifecycleCompletionCaseID} {
		if _, err := executor.Execute(ctx, caseID); err != nil {
			t.Fatalf("advance %s: %v", caseID, err)
		}
	}
	before := store.Snapshot()
	if _, err := executor.Execute(ctx, scenariocontrol.ExecResultUsageCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("missing output reference error = %v", err)
	}
	if after := store.Snapshot(); !reflect.DeepEqual(after, before) || after.Stage != callerstate.StageLifecycleBound || after.StoreRevision != 3 || executor.next != 4 || len(client.execs) != 1 {
		t.Fatalf("failed exec evidence changed state/progress = %#v / %d", after, executor.next)
	}
}
