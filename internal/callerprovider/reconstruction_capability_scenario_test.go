//go:build darwin || linux

package callerprovider

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestReconstructionCapabilityLoadsCompleteStateStartsGatewayAndPreservesState(t *testing.T) {
	_, store := completeStore(t)
	defer store.Close()
	before := store.Snapshot()
	capabilities, raw := selectedCapabilities(t)
	client := &fakeClient{capabilities: capabilities, raw: raw, store: store}
	closed := 0
	service := &scenarioGatewayFake{}
	phase := ""
	executor, err := NewInitialScenarioExecutorWithGateway("https://provider.example", "https://gateway.example/tunnel", &credentials.Bundle{}, store, func(_ context.Context, gotPhase, _ string, _ *credentials.Bundle) (ScenarioGateway, error) {
		phase = gotPhase
		return service, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.buildProviderAccess = fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.ReconstructionCapabilityCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.ReconstructionCapabilityCaseID || result.Disposition != "completed" || len(result.Interactions) != 1 || len(result.Assertions) != 2 || !reflect.DeepEqual(result.ObservationIDs, []string{"byte-identical-capability-snapshot", "new-provider-process", "new-caller-process", "new-adapter-process", "new-gateway-process"}) {
		t.Fatalf("reconstruction capability result = %#v", result)
	}
	interaction := result.Interactions[0]
	if interaction.InteractionID != "reconstructed-capabilities" || interaction.WireAttempts != 1 || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != http.StatusOK || interaction.MutationWriteObserved {
		t.Fatalf("reconstruction capability interaction = %#v", interaction)
	}
	if phase != "reconstruction" || !service.installed || service.stopped || service.tenantA != before.Plan.TenantAID || service.tenantB != before.Plan.TenantBID || client.capabilityCalls != 1 || !reflect.DeepEqual(store.Snapshot(), before) || executor.next != 1 {
		t.Fatalf("reconstruction composition = phase %q service %#v calls %d state %#v next %d", phase, service, client.capabilityCalls, store.Snapshot(), executor.next)
	}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	if !service.stopped || service.stopCalls != 1 || closed != 1 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("reconstruction cleanup = service %#v closed %d state %#v", service, closed, store.Snapshot())
	}
}

func TestReconstructionCapabilityRetries503AndRejectsContinuityChange(t *testing.T) {
	for _, test := range []struct {
		name      string
		mutateRaw bool
		wantError error
	}{
		{name: "retry then exact", wantError: nil},
		{name: "changed bytes", mutateRaw: true, wantError: ErrCapabilityContinuity},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, store := completeStore(t)
			defer store.Close()
			before := store.Snapshot()
			capabilities, raw := selectedCapabilities(t)
			if test.mutateRaw {
				raw = append(append([]byte(nil), raw...), ' ')
			}
			client := &fakeClient{capabilities: capabilities, raw: raw, store: store}
			if !test.mutateRaw {
				client.capabilityHook = func(call int) error {
					if call == 1 {
						return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}}
					}
					return nil
				}
			}
			closed := 0
			service := &scenarioGatewayFake{}
			executor, err := NewInitialScenarioExecutorWithGateway("https://provider.example", "https://gateway.example/tunnel", &credentials.Bundle{}, store, func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
				return service, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			executor.buildProviderAccess = fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			result, gotErr := executor.Execute(ctx, scenariocontrol.ReconstructionCapabilityCaseID)
			cancel()
			if !errors.Is(gotErr, test.wantError) {
				t.Fatalf("Execute() error = %v, want %v", gotErr, test.wantError)
			}
			if test.wantError == nil && (result.Interactions[0].WireAttempts != 2 || len(result.Interactions[0].TransientOutcomes) != 1) {
				t.Fatalf("retry result = %#v", result)
			}
			if test.wantError != nil && (service.stopped || service.installed || service.stopCalls != 0 || closed != 1 || executor.next != 0) {
				t.Fatalf("continuity failure cleanup = service %#v closed %d next %d", service, closed, executor.next)
			}
			_ = executor.Close()
			if !reflect.DeepEqual(store.Snapshot(), before) {
				t.Fatalf("reconstruction changed state = %#v", store.Snapshot())
			}
		})
	}
}

func TestReconstructionLifecycleReadsRetainedCorrelationsAndPreservesStateAndGateway(t *testing.T) {
	_, store := completeStore(t)
	defer store.Close()
	before := store.Snapshot()
	capabilities, raw := selectedCapabilities(t)
	client := &fakeClient{capabilities: capabilities, raw: raw, store: store}
	closed := 0
	service := &scenarioGatewayFake{}
	executor, err := NewInitialScenarioExecutorWithGateway("https://provider.example", "https://gateway.example/tunnel", &credentials.Bundle{}, store, func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.buildProviderAccess = fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionCapabilityCaseID); err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(ctx, scenariocontrol.ReconstructionLifecycleCaseID)
	if err != nil {
		t.Fatal(err)
	}
	wantObservations := []string{"same-create-operation-correlation", "operation-succeeded", "caller-correlation-load-without-harness-reinjection-observed", "same-sandbox-correlation", "sandbox-ready", "generation-one"}
	if result.CaseID != scenariocontrol.ReconstructionLifecycleCaseID || result.Disposition != "completed" || len(result.Interactions) != 2 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, wantObservations) {
		t.Fatalf("reconstruction lifecycle result = %#v", result)
	}
	for index, interactionID := range []string{"read-reconstructed-create-operation", "read-reconstructed-sandbox"} {
		interaction := result.Interactions[index]
		if interaction.InteractionID != interactionID || interaction.WireAttempts != 1 || len(interaction.TransientOutcomes) != 0 || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != http.StatusOK || interaction.MutationWriteObserved {
			t.Fatalf("reconstruction lifecycle interaction %d = %#v", index, interaction)
		}
	}
	if result.Assertions[0].AssertionID != "correlations-originated-in-caller-durable-store" || result.Assertions[0].Result != "asserted" {
		t.Fatalf("reconstruction lifecycle assertion = %#v", result.Assertions)
	}
	if len(client.admissions) != 2 || client.admissions[0].Claims.JTI == client.admissions[1].Claims.JTI || client.admissions[0].Context.Operation != "read_operation" || client.admissions[1].Context.Operation != "read_sandbox" {
		t.Fatalf("reconstruction lifecycle admissions = %#v", client.admissions)
	}
	for _, admission := range client.admissions {
		if admission.Context.SandboxID != before.Plan.SandboxID || admission.Context.OperationID != before.Lifecycle.OperationID || admission.Context.AttemptID != before.Lifecycle.AttemptID || admission.Context.FencingToken != before.Lifecycle.FencingToken {
			t.Fatalf("admission did not originate in retained lifecycle = %#v", admission.Context)
		}
	}
	if service.stopped || !service.installed || executor.next != 2 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("reconstruction lifecycle composition = service %#v next %d state %#v", service, executor.next, store.Snapshot())
	}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	if !service.stopped || service.stopCalls != 1 || closed != 1 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("reconstruction lifecycle cleanup = service %#v closed %d state %#v", service, closed, store.Snapshot())
	}
}

func TestReconstructionLifecycleRejectsChangedRetainedOperationWithoutStateMutation(t *testing.T) {
	_, store := completeStore(t)
	defer store.Close()
	before := store.Snapshot()
	capabilities, raw := selectedCapabilities(t)
	client := &fakeClient{capabilities: capabilities, raw: raw, store: store, operationHook: func(operation *provider.ProviderOperation) {
		operation.AttemptID = "different-attempt"
	}}
	service := &scenarioGatewayFake{}
	executor, err := NewInitialScenarioExecutorWithGateway("https://provider.example", "https://gateway.example/tunnel", &credentials.Bundle{}, store, func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := 0
	executor.buildProviderAccess = fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionCapabilityCaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionLifecycleCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("changed retained operation error = %v", err)
	}
	if executor.next != 1 || service.stopped || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("changed operation composition = next %d service %#v state %#v", executor.next, service, store.Snapshot())
	}
	_ = executor.Close()
	if !service.stopped || closed != 1 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("changed operation cleanup = service %#v closed %d state %#v", service, closed, store.Snapshot())
	}
}

func TestReconstructionLifecycleRetriesOnlyExplicit503WithFreshAdmission(t *testing.T) {
	_, store := completeStore(t)
	defer store.Close()
	before := store.Snapshot()
	capabilities, raw := selectedCapabilities(t)
	polls := 0
	retryAfter := 1
	client := &fakeClient{capabilities: capabilities, raw: raw, store: store, hook: func(operation string) error {
		if operation == "poll:"+before.Lifecycle.OperationID {
			polls++
			if polls == 1 {
				return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}, RetryAfterSeconds: &retryAfter}
			}
		}
		return nil
	}}
	service := &scenarioGatewayFake{}
	executor, err := NewInitialScenarioExecutorWithGateway("https://provider.example", "https://gateway.example/tunnel", &credentials.Bundle{}, store, func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := 0
	executor.buildProviderAccess = fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionCapabilityCaseID); err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(ctx, scenariocontrol.ReconstructionLifecycleCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if polls != 2 || result.Interactions[0].WireAttempts != 2 || len(result.Interactions[0].TransientOutcomes) != 1 || result.Interactions[0].TransientOutcomes[0].StatusCode == nil || *result.Interactions[0].TransientOutcomes[0].StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("retry composition = polls %d result %#v", polls, result)
	}
	if len(client.admissions) != 3 {
		t.Fatalf("retry admissions = %#v", client.admissions)
	}
	seenJTI := make(map[string]struct{}, len(client.admissions))
	for _, admission := range client.admissions {
		if _, duplicate := seenJTI[admission.Claims.JTI]; duplicate {
			t.Fatalf("retry reused Admission JTI %q", admission.Claims.JTI)
		}
		seenJTI[admission.Claims.JTI] = struct{}{}
	}
	if !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("retry changed state = %#v", store.Snapshot())
	}
	_ = executor.Close()
}
