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

func TestMTLSCallerBindingRejectionUsesControllerBTransportWithControllerAAdmission(t *testing.T) {
	executor, controllerA, controllerB, store := crossTenantCompletedExecutor(t)
	defer executor.Close()
	defer store.Close()
	before := store.Snapshot()
	controllerASubject := "spiffe://provider/controller_a"
	beforeA, beforeB := len(controllerA.admissions), len(controllerB.admissions)
	controllerB.statusHook = func(descriptor provider.ReadDescriptor, admission provider.Admission) error {
		if descriptor.Operation != "read_sandbox" || descriptor.SandboxID != before.Plan.SandboxID || admission.Context.ControllerSubject != controllerASubject || admission.Claims.Subject != controllerASubject {
			t.Fatalf("wrong-caller read = %#v / %#v", descriptor, admission)
		}
		return providerRejection(http.StatusForbidden, "SANDBOX_FORBIDDEN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.MTLSCallerBindingCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.MTLSCallerBindingCaseID || result.Disposition != "completed" || len(result.Interactions) != 1 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, []string{"admitted-controller-b-certificate", "controller-a-signed-subject", "rejected-before-state-read"}) {
		t.Fatalf("mTLS binding result = %#v", result)
	}
	interaction := result.Interactions[0]
	if interaction.WireAttempts != 1 || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != http.StatusForbidden || interaction.FinalOutcome.ErrorCode == nil || *interaction.FinalOutcome.ErrorCode != "SANDBOX_FORBIDDEN" || interaction.FinalOutcome.Retryable || interaction.FinalOutcome.RetryAfterPresent || interaction.MutationWriteObserved {
		t.Fatalf("mTLS binding interaction = %#v", interaction)
	}
	if len(controllerA.admissions) != beforeA || len(controllerB.admissions) != beforeB+1 {
		t.Fatalf("Admission transport ownership A=%d->%d B=%d->%d", beforeA, len(controllerA.admissions), beforeB, len(controllerB.admissions))
	}
	admission := controllerB.admissions[len(controllerB.admissions)-1]
	if admission.Context.ControllerSubject != controllerASubject || admission.Claims.Subject != controllerASubject || admission.Context.TenantID != before.Plan.TenantAID || admission.Context.WorkOrderID != before.Plan.WorkOrderAID || admission.Context.PolicyDigest != before.Provider.PolicyDigest {
		t.Fatalf("controller-A Admission over controller-B client = %#v", admission)
	}
	if !reflect.DeepEqual(store.Snapshot(), before) || executor.next != 15 {
		t.Fatalf("mTLS rejection changed state/progress = %#v / %d", store.Snapshot(), executor.next)
	}
}

func TestMTLSCallerBindingRejectionRejectsUnexpectedProviderOutcome(t *testing.T) {
	for _, test := range []struct {
		name string
		hook func(provider.ReadDescriptor, provider.Admission) error
	}{
		{name: "sandbox disclosed", hook: nil},
		{name: "wrong error code", hook: func(provider.ReadDescriptor, provider.Admission) error {
			return providerRejection(http.StatusForbidden, "TEST_PROVIDER_REJECTED")
		}},
		{name: "concealing not found", hook: func(provider.ReadDescriptor, provider.Admission) error {
			return providerRejection(http.StatusNotFound, "SANDBOX_NOT_FOUND")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor, _, controllerB, store := crossTenantCompletedExecutor(t)
			defer executor.Close()
			defer store.Close()
			before := store.Snapshot()
			controllerB.statusHook = test.hook
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := executor.Execute(ctx, scenariocontrol.MTLSCallerBindingCaseID); !errors.Is(err, ErrInitialScenario) {
				t.Fatalf("unexpected Provider outcome error = %v", err)
			}
			if !reflect.DeepEqual(store.Snapshot(), before) || executor.next != 14 {
				t.Fatalf("failure changed state/progress = %#v / %d", store.Snapshot(), executor.next)
			}
		})
	}
}

func TestMTLSCallerBindingReadRetryUsesFreshControllerAAdmission(t *testing.T) {
	executor, _, controllerB, store := crossTenantCompletedExecutor(t)
	defer executor.Close()
	defer store.Close()
	retryAfter, calls := 1, 0
	controllerB.statusHook = func(provider.ReadDescriptor, provider.Admission) error {
		calls++
		if calls == 1 {
			return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}, RetryAfterSeconds: &retryAfter}
		}
		return providerRejection(http.StatusForbidden, "SANDBOX_FORBIDDEN")
	}
	beforeAdmissions := len(controllerB.admissions)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.MTLSCallerBindingCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Interactions[0].WireAttempts != 2 || len(result.Interactions[0].TransientOutcomes) != 1 || len(controllerB.admissions) != beforeAdmissions+2 {
		t.Fatalf("retry result/admissions = %#v / %d", result.Interactions[0], len(controllerB.admissions))
	}
	first, second := controllerB.admissions[beforeAdmissions], controllerB.admissions[beforeAdmissions+1]
	if first.Claims.JTI == second.Claims.JTI || first.BearerToken == second.BearerToken || first.Claims.Subject != second.Claims.Subject {
		t.Fatalf("read retry Admissions = %#v / %#v", first, second)
	}
}

func crossTenantCompletedExecutor(t *testing.T) (*InitialScenarioExecutor, *fakeClient, *fakeClient, *callerstate.Store) {
	t.Helper()
	executor, controllerA, controllerB, store, _ := initialCompleteCrossTenantExecutor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.CrossTenantArtifactCaseID); err != nil {
		executor.Close()
		store.Close()
		t.Fatal(err)
	}
	return executor, controllerA, controllerB, store
}
