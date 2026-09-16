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

func TestCrossTenantArtifactRejectionUsesControllerBTenantBAndPreservesState(t *testing.T) {
	executor, controllerA, controllerB, store, closed := initialCompleteCrossTenantExecutor(t)
	defer executor.Close()
	defer store.Close()
	before := store.Snapshot()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.CrossTenantArtifactCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.CrossTenantArtifactCaseID || result.Disposition != "completed" || len(result.Interactions) != 2 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, []string{"controller-b-tenant-b-request", "rejected-before-artifact-dispatch", "no-backend-disclosure", "no-cross-tenant-operation-visible"}) {
		t.Fatalf("cross-tenant result = %#v", result)
	}
	for index, want := range []struct {
		status int
		code   string
	}{{http.StatusForbidden, "SANDBOX_FORBIDDEN"}, {http.StatusNotFound, "SANDBOX_NOT_FOUND"}} {
		interaction := result.Interactions[index]
		if interaction.WireAttempts != 1 || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != want.status || interaction.FinalOutcome.ErrorCode == nil || *interaction.FinalOutcome.ErrorCode != want.code || interaction.FinalOutcome.Retryable || interaction.FinalOutcome.RetryAfterPresent {
			t.Fatalf("interaction %d = %#v", index, interaction)
		}
	}
	if len(controllerB.artifacts) != 1 || !reflect.DeepEqual(controllerB.artifacts[0], executor.artifactRequest) || len(controllerA.artifacts) != 1 {
		t.Fatalf("artifact calls A=%#v B=%#v", controllerA.artifacts, controllerB.artifacts)
	}
	if len(controllerB.admissions) != 2 {
		t.Fatalf("controller B Admissions = %d", len(controllerB.admissions))
	}
	wantPolicyDigest, err := policyDigestFor(before.Plan.TenantBID, before.Plan.WorkOrderBID)
	if err != nil {
		t.Fatal(err)
	}
	for _, admission := range controllerB.admissions {
		if admission.Context.ControllerSubject != "spiffe://provider/controller_b" || admission.Context.TenantID != before.Plan.TenantBID || admission.Context.WorkOrderID != before.Plan.WorkOrderBID || admission.Claims.TenantID != before.Plan.TenantBID || admission.Claims.WorkOrderID != before.Plan.WorkOrderBID || admission.Context.PolicyDigest != wantPolicyDigest || admission.Claims.PolicyDigest != admission.Context.PolicyDigest {
			t.Fatalf("controller B Admission = %#v", admission)
		}
	}
	if !reflect.DeepEqual(store.Snapshot(), before) || executor.next != 14 {
		t.Fatalf("cross-tenant rejection changed state/progress = %#v / %d", store.Snapshot(), executor.next)
	}
	wire, err := json.Marshal(result)
	if err != nil || containsBytes(wire, []byte(executor.artifactRequest.ArtifactReference)) || containsBytes(wire, []byte(executor.artifactEvidence.StagingReference)) || containsBytes(wire, []byte(controllerB.admissions[0].BearerToken)) {
		t.Fatalf("public result leaked private authority: %q / %v", wire, err)
	}
	executor.Close()
	if *closed != 1 {
		t.Fatalf("controller B access closes = %d, want 1", *closed)
	}
}

func TestCrossTenantArtifactRejectionRejectsUnexpectedProviderOutcome(t *testing.T) {
	for _, test := range []struct {
		name string
		hook func(*fakeClient)
	}{
		{name: "stage accepted", hook: func(client *fakeClient) { client.artifactHook = nil }},
		{name: "wrong error code", hook: func(client *fakeClient) {
			client.artifactHook = func(int, provider.ArtifactStagingRequest, provider.Admission) error {
				return providerRejection(http.StatusForbidden, "TEST_PROVIDER_REJECTED")
			}
		}},
		{name: "operation disclosed", hook: func(client *fakeClient) {
			client.hook = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor, _, controllerB, store, _ := initialCompleteCrossTenantExecutor(t)
			defer executor.Close()
			defer store.Close()
			before := store.Snapshot()
			test.hook(controllerB)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := executor.Execute(ctx, scenariocontrol.CrossTenantArtifactCaseID); !errors.Is(err, ErrInitialScenario) {
				t.Fatalf("unexpected Provider outcome error = %v", err)
			}
			if !reflect.DeepEqual(store.Snapshot(), before) || executor.next != 13 {
				t.Fatalf("failure changed state/progress = %#v / %d", store.Snapshot(), executor.next)
			}
		})
	}
}

func TestCrossTenantArtifactRejectionRetriesOnlyExplicit503WithCorrectAdmissionSemantics(t *testing.T) {
	executor, _, controllerB, store, _ := initialCompleteCrossTenantExecutor(t)
	defer executor.Close()
	defer store.Close()
	retryAfter := 1
	stageCalls, readCalls := 0, 0
	controllerB.artifactHook = func(_ int, _ provider.ArtifactStagingRequest, _ provider.Admission) error {
		stageCalls++
		if stageCalls == 1 {
			return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}, RetryAfterSeconds: &retryAfter}
		}
		return providerRejection(http.StatusForbidden, "SANDBOX_FORBIDDEN")
	}
	controllerB.hook = func(string) error {
		readCalls++
		if readCalls == 1 {
			return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}, RetryAfterSeconds: &retryAfter}
		}
		return providerRejection(http.StatusNotFound, "SANDBOX_NOT_FOUND")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.CrossTenantArtifactCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Interactions[0].WireAttempts != 2 || len(result.Interactions[0].TransientOutcomes) != 1 || result.Interactions[1].WireAttempts != 2 || len(result.Interactions[1].TransientOutcomes) != 1 || len(controllerB.admissions) != 4 {
		t.Fatalf("retry result/admissions = %#v / %d", result.Interactions, len(controllerB.admissions))
	}
	if !reflect.DeepEqual(controllerB.admissions[0], controllerB.admissions[1]) {
		t.Fatal("mutation retry did not preserve exact Admission")
	}
	if controllerB.admissions[2].Claims.JTI == controllerB.admissions[3].Claims.JTI || controllerB.admissions[2].BearerToken == controllerB.admissions[3].BearerToken {
		t.Fatal("read retry reused Admission JTI")
	}
}

func initialCompleteCrossTenantExecutor(t *testing.T) (*InitialScenarioExecutor, *fakeClient, *fakeClient, *callerstate.Store, *int) {
	t.Helper()
	executor, controllerA, store := terminalBoundArtifactExecutor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.ArtifactStagingCaseID); err != nil {
		executor.Close()
		store.Close()
		t.Fatal(err)
	}
	controllerB := &fakeClient{store: store}
	controllerB.artifactHook = func(int, provider.ArtifactStagingRequest, provider.Admission) error {
		return providerRejection(http.StatusForbidden, "SANDBOX_FORBIDDEN")
	}
	controllerB.hook = func(string) error {
		return providerRejection(http.StatusNotFound, "SANDBOX_NOT_FOUND")
	}
	closed := 0
	executor.buildProviderAccess = fakeFactory(t, map[string]*fakeClient{"controller_b": controllerB}, &closed)
	return executor, controllerA, controllerB, store, &closed
}

func providerRejection(status int, code string) error {
	return &provider.HTTPError{StatusCode: status, Document: provider.StandardError{Code: code, Message: "closed rejection", Retryable: false, TraceID: "test-trace"}}
}
