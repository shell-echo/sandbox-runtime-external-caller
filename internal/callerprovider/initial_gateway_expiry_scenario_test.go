//go:build darwin || linux

package callerprovider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestGatewayGrantExpiryClosesAuthorizedConnectionAndPreservesState(t *testing.T) {
	executor, client, store := cancellationCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	terminalCtx, terminalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer terminalCancel()
	if _, err := executor.Execute(terminalCtx, scenariocontrol.TerminalSessionCaseID); err != nil {
		t.Fatal(err)
	}
	executor.next = 10
	before := store.Snapshot()
	service := &scenarioGatewayFake{}
	executor.bundle = &credentials.Bundle{}
	executor.gatewayEndpoint = "https://gateway.example/tunnel"
	executor.startGateway = func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	}
	executor.buildGatewayAccess = func(_ *credentials.Bundle, endpoint, actor string) (*credentials.GatewayAccess, error) {
		if endpoint != executor.gatewayEndpoint || actor != "controller_a" {
			return nil, errors.New("changed Gateway access")
		}
		return &credentials.GatewayAccess{Actor: actor, ControllerSubject: "spiffe://caller/controller-a", TLSConfig: &tls.Config{}}, nil
	}
	executor.dialGateway = func(ctx context.Context, endpoint, token string, config *tls.Config) (io.ReadWriteCloser, error) {
		if endpoint != executor.gatewayEndpoint || token != strings.Repeat("A", 43) || config == nil || !service.expiresAt.After(time.Now()) {
			return nil, errors.New("changed expiring grant")
		}
		connection, err := service.opener(ctx, service.handoff)
		if err != nil {
			return nil, err
		}
		time.AfterFunc(time.Until(service.expiresAt), func() { _ = connection.Close() })
		return connection, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.GatewayGrantExpiryCaseID)
	if err != nil {
		t.Fatal(err)
	}
	observations := []string{"grant-initially-authorized", "connection-closed-after-expiry", "no-post-expiry-forwarding"}
	if result.CaseID != scenariocontrol.GatewayGrantExpiryCaseID || result.Disposition != "completed" || len(result.Interactions) != 1 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, observations) {
		t.Fatalf("Gateway expiry result = %#v", result)
	}
	interaction := result.Interactions[0]
	if interaction.InteractionID != "gateway-expiring-grant" || interaction.Actor != "controller_a" || interaction.FinalOutcome.Transport != "gateway-closed-at-grant-expiry" || interaction.FinalOutcome.StatusCode != nil || interaction.FinalOutcome.ErrorCode != nil || interaction.WireAttempts != 1 || interaction.MutationWriteObserved || len(interaction.TransientOutcomes) != 0 || !reflect.DeepEqual(interaction.ObservationIDs, observations) {
		t.Fatalf("Gateway expiry interaction = %#v", interaction)
	}
	if !service.installed || !service.issued || !service.stopped || service.issueCalls != 1 || service.stopCalls != 1 || service.actor != "controller_a" || service.tenant != before.Plan.TenantAID || service.session != before.Terminal.RuntimeSessionID || service.handoff != before.Terminal.HandoffReference || len(client.connects) != 1 || executor.next != 11 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("Gateway expiry composition = service %#v, connects %d, next %d, state %#v", service, len(client.connects), executor.next, store.Snapshot())
	}
	public, err := json.Marshal(result)
	if err != nil || containsBytes(public, []byte(service.handoff)) || containsBytes(public, []byte(strings.Repeat("A", 43))) {
		t.Fatalf("public expiry result leaked private authority: %q / %v", public, err)
	}
}

func TestGatewayGrantExpiryFailureStopsGatewayWithoutAdvancing(t *testing.T) {
	executor, client, store := cancellationCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	terminalCtx, terminalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer terminalCancel()
	if _, err := executor.Execute(terminalCtx, scenariocontrol.TerminalSessionCaseID); err != nil {
		t.Fatal(err)
	}
	executor.next = 10
	before := store.Snapshot()
	service := &scenarioGatewayFake{}
	executor.bundle = &credentials.Bundle{}
	executor.gatewayEndpoint = "https://gateway.example/tunnel"
	executor.startGateway = func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	}
	executor.buildGatewayAccess = func(*credentials.Bundle, string, string) (*credentials.GatewayAccess, error) {
		return &credentials.GatewayAccess{Actor: "controller_a", ControllerSubject: "spiffe://caller/controller-a", TLSConfig: &tls.Config{}}, nil
	}
	client.connectHook = func(provider.RuntimeSessionHandoff, provider.Admission) (io.ReadWriteCloser, error) {
		caller, backend := net.Pipe()
		go serveFakeShell(backend, true)
		return caller, nil
	}
	executor.dialGateway = func(ctx context.Context, _ string, _ string, _ *tls.Config) (io.ReadWriteCloser, error) {
		return service.opener(ctx, service.handoff)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.GatewayGrantExpiryCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("Gateway expiry failure = %v", err)
	}
	if service.stopCalls != 1 || executor.next != 10 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("failed expiry cleanup/progress = service %#v, next %d, state %#v", service, executor.next, store.Snapshot())
	}
}
