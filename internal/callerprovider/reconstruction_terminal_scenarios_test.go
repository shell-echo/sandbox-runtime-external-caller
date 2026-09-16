//go:build darwin || linux

package callerprovider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestReconstructionRetainsHandoffThenReconnectsThroughSameGateway(t *testing.T) {
	_, store, resultDocument, usageDocument, artifactDocument := completeStoreWithEvidence(t)
	defer store.Close()
	before := store.Snapshot()
	handoff := retainedHandoffForState(before, time.Now().Add(time.Hour))
	capabilities, raw := selectedCapabilities(t)
	client := &fakeClient{capabilities: capabilities, raw: raw, store: store, result: resultDocument, usage: usageDocument, artifactEvidence: artifactDocument, handoff: handoff}
	handoffReads := 0
	retryAfter := 1
	client.hook = func(step string) error {
		if step == "handoff" {
			handoffReads++
			if handoffReads == 1 {
				return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}, RetryAfterSeconds: &retryAfter}
			}
		}
		return nil
	}
	service := &scenarioGatewayFake{}
	executor, err := NewInitialScenarioExecutorWithGateway("https://provider.example", "https://gateway.example/tunnel", &credentials.Bundle{}, store, func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := 0
	executor.buildProviderAccess = fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)
	executor.buildGatewayAccess = func(_ *credentials.Bundle, endpoint, actor string) (*credentials.GatewayAccess, error) {
		if endpoint != executor.gatewayEndpoint || actor != "controller_a" {
			return nil, errors.New("unexpected Gateway authority")
		}
		return &credentials.GatewayAccess{Actor: actor, TLSConfig: &tls.Config{}}, nil
	}
	executor.dialGateway = func(ctx context.Context, endpoint, token string, config *tls.Config) (io.ReadWriteCloser, error) {
		if endpoint != executor.gatewayEndpoint || token != strings.Repeat("A", 43) || config == nil || service.opener == nil {
			return nil, errors.New("unexpected Gateway connection")
		}
		return service.opener(ctx, service.handoff)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	executeReconstructionPrefix(t, ctx, executor)
	admissionStart := len(client.admissions)
	handoffResult, err := executor.Execute(ctx, scenariocontrol.ReconstructionHandoffCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if handoffResult.CaseID != scenariocontrol.ReconstructionHandoffCaseID || handoffResult.Disposition != "completed" || handoffResult.Interactions[0].WireAttempts != 2 || len(handoffResult.Interactions[0].TransientOutcomes) != 1 || executor.next != 4 || service.stopped || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("retained handoff composition = result %#v next %d service %#v state %#v", handoffResult, executor.next, service, store.Snapshot())
	}
	newAdmissions := client.admissions[admissionStart:]
	if len(newAdmissions) != 2 || newAdmissions[0].Claims.JTI == newAdmissions[1].Claims.JTI {
		t.Fatalf("retained handoff admissions = %#v", newAdmissions)
	}
	reconnectResult, err := executor.Execute(ctx, scenariocontrol.ReconstructionReconnectCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if reconnectResult.CaseID != scenariocontrol.ReconstructionReconnectCaseID || reconnectResult.Disposition != "completed" || reconnectResult.Interactions[0].FinalOutcome.Transport != "authorized-byte-round-trip" ||
		len(reconnectResult.Assertions) != 2 || executor.next != 5 || service.issueCalls != 1 || service.actor != "controller_a" || service.tenant != before.Plan.TenantAID ||
		service.session != before.Terminal.RuntimeSessionID || service.handoff != before.Terminal.HandoffReference || len(client.connects) != 1 || !reflect.DeepEqual(client.connects[0], handoff) || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("reconstruction reconnect composition = result %#v service %#v connects %#v state %#v", reconnectResult, service, client.connects, store.Snapshot())
	}
	wire, err := json.Marshal([]any{handoffResult, reconnectResult})
	if err != nil || containsBytes(wire, []byte(handoff.InternalEndpointReference)) || containsBytes(wire, []byte(strings.Repeat("A", 43))) {
		t.Fatalf("private reconstruction authority leaked: %v %q", err, wire)
	}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	if !service.stopped || service.stopCalls != 1 || closed != 1 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("reconstruction cleanup = service %#v closed %d state %#v", service, closed, store.Snapshot())
	}
}

func TestReconstructionRejectsMismatchedRetainedHandoffWithoutReconnect(t *testing.T) {
	_, store, resultDocument, usageDocument, artifactDocument := completeStoreWithEvidence(t)
	defer store.Close()
	before := store.Snapshot()
	handoff := retainedHandoffForState(before, time.Now().Add(time.Hour))
	handoff.InternalEndpointReference = "ref:session:different"
	capabilities, raw := selectedCapabilities(t)
	client := &fakeClient{capabilities: capabilities, raw: raw, store: store, result: resultDocument, usage: usageDocument, artifactEvidence: artifactDocument, handoff: handoff}
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
	executeReconstructionPrefix(t, ctx, executor)
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionHandoffCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("mismatched handoff error = %v", err)
	}
	if executor.next != 3 || executor.terminalHandoff.InternalEndpointReference != "" || service.issueCalls != 0 || service.stopped || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("mismatched handoff changed authority = next %d handoff %#v service %#v state %#v", executor.next, executor.terminalHandoff, service, store.Snapshot())
	}
	_ = executor.Close()
}

func executeReconstructionPrefix(t *testing.T, ctx context.Context, executor *InitialScenarioExecutor) {
	t.Helper()
	for _, caseID := range []string{scenariocontrol.ReconstructionCapabilityCaseID, scenariocontrol.ReconstructionLifecycleCaseID, scenariocontrol.ReconstructionEvidenceCaseID} {
		if _, err := executor.Execute(ctx, caseID); err != nil {
			t.Fatal(err)
		}
	}
}

func retainedHandoffForState(state callerstate.State, expiresAt time.Time) provider.RuntimeSessionHandoff {
	return provider.RuntimeSessionHandoff{
		OperationID: state.Terminal.Operation.OperationID, AttemptID: state.Terminal.Operation.AttemptID, FencingToken: state.Terminal.Operation.FencingToken,
		SandboxID: state.Plan.SandboxID, RuntimeSessionID: state.Terminal.RuntimeSessionID, RuntimeType: "terminal", CapabilityProfileID: TerminalProfileID,
		Protocol: "websocket", InternalEndpointReference: state.Terminal.HandoffReference, ConnectionGeneration: 1, ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
	}
}
