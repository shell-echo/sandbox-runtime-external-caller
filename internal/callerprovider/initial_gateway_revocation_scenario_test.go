//go:build darwin || linux

package callerprovider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestGatewayRevocationAcknowledgesClosedAuthorizedConnectionAndPreservesState(t *testing.T) {
	executor, client, store := cancellationCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	terminalCtx, terminalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer terminalCancel()
	if _, err := executor.Execute(terminalCtx, scenariocontrol.TerminalSessionCaseID); err != nil {
		t.Fatal(err)
	}
	executor.next = 11
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
	var active io.ReadWriteCloser
	executor.dialGateway = func(ctx context.Context, endpoint, token string, config *tls.Config) (io.ReadWriteCloser, error) {
		if endpoint != executor.gatewayEndpoint || token != strings.Repeat("A", 43) || config == nil {
			return nil, errors.New("changed revocable grant")
		}
		connection, err := service.opener(ctx, service.handoff)
		active = connection
		return connection, err
	}
	service.revoke = func() error {
		if active == nil {
			return errors.New("revoked before connect")
		}
		return active.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.GatewayRevocationCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.GatewayRevocationCaseID || result.Disposition != "completed" || len(result.Interactions) != 2 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, []string{"grant-initially-authorized", "connection-closed-after-revocation", "no-post-revocation-forwarding"}) {
		t.Fatalf("Gateway revocation result = %#v", result)
	}
	connect, revoke := result.Interactions[0], result.Interactions[1]
	if connect.InteractionID != "gateway-revocable-grant" || connect.FinalOutcome.Transport != "authorized-byte-round-trip" || connect.WireAttempts != 1 || connect.MutationWriteObserved || !reflect.DeepEqual(connect.ObservationIDs, []string{"grant-initially-authorized"}) {
		t.Fatalf("Gateway revocable connection = %#v", connect)
	}
	if revoke.InteractionID != "gateway-revoke-grant" || revoke.Method != "CONTROL" || revoke.RouteTemplate != "consumer-defined:revoke-grant" || revoke.FinalOutcome.Transport != "revocation-acknowledged" || revoke.WireAttempts != 1 || !revoke.MutationWriteObserved || !reflect.DeepEqual(revoke.ObservationIDs, []string{"connection-closed-after-revocation", "no-post-revocation-forwarding"}) {
		t.Fatalf("Gateway revoke interaction = %#v", revoke)
	}
	if !service.installed || !service.issued || !service.stopped || service.issueCalls != 1 || service.revokeCalls != 1 || service.stopCalls != 1 || service.revokeActor != "controller_a" || service.revokeToken != strings.Repeat("A", 43) || len(client.connects) != 1 || executor.next != 12 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("Gateway revocation composition = service %#v, connects %d, next %d, state %#v", service, len(client.connects), executor.next, store.Snapshot())
	}
	public, err := json.Marshal(result)
	if err != nil || containsBytes(public, []byte(service.handoff)) || containsBytes(public, []byte(service.revokeToken)) {
		t.Fatalf("public revocation result leaked private authority: %q / %v", public, err)
	}
}

func TestGatewayRevocationFailureStopsGatewayWithoutAcknowledgementOrAdvancement(t *testing.T) {
	executor, _, store := cancellationCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	terminalCtx, terminalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer terminalCancel()
	if _, err := executor.Execute(terminalCtx, scenariocontrol.TerminalSessionCaseID); err != nil {
		t.Fatal(err)
	}
	executor.next = 11
	before := store.Snapshot()
	service := &scenarioGatewayFake{revoke: func() error { return errors.New("ambiguous revocation failure") }}
	executor.bundle = &credentials.Bundle{}
	executor.gatewayEndpoint = "https://gateway.example/tunnel"
	executor.startGateway = func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	}
	executor.buildGatewayAccess = func(*credentials.Bundle, string, string) (*credentials.GatewayAccess, error) {
		return &credentials.GatewayAccess{Actor: "controller_a", ControllerSubject: "spiffe://caller/controller-a", TLSConfig: &tls.Config{}}, nil
	}
	executor.dialGateway = func(ctx context.Context, _ string, _ string, _ *tls.Config) (io.ReadWriteCloser, error) {
		return service.opener(ctx, service.handoff)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.GatewayRevocationCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("Gateway revocation failure = %v", err)
	}
	if service.revokeCalls != 1 || service.stopCalls != 1 || executor.next != 11 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("failed revocation cleanup/progress = service %#v, next %d, state %#v", service, executor.next, store.Snapshot())
	}
}
