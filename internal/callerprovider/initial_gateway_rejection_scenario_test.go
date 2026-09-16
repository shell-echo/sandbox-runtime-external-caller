//go:build darwin || linux

package callerprovider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestGatewayAuthorityRejectionsDoNotOpenProviderBackendOrAdvanceState(t *testing.T) {
	executor, client, store := cancellationCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	terminalCtx, terminalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer terminalCancel()
	if _, err := executor.Execute(terminalCtx, scenariocontrol.TerminalSessionCaseID); err != nil {
		t.Fatal(err)
	}

	service := &scenarioGatewayFake{}
	controllerATLS := &tls.Config{}
	controllerBTLS := &tls.Config{}
	executor.bundle = &credentials.Bundle{}
	executor.gatewayEndpoint = "https://gateway.example/tunnel"
	starts := 0
	executor.startGateway = func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		starts++
		return service, nil
	}
	executor.buildGatewayAccess = func(_ *credentials.Bundle, endpoint, actor string) (*credentials.GatewayAccess, error) {
		if endpoint != executor.gatewayEndpoint {
			return nil, errors.New("changed endpoint")
		}
		switch actor {
		case "controller_a":
			return &credentials.GatewayAccess{Actor: actor, ControllerSubject: "spiffe://caller/controller-a", TLSConfig: controllerATLS}, nil
		case "controller_b":
			return &credentials.GatewayAccess{Actor: actor, ControllerSubject: "spiffe://caller/controller-b", TLSConfig: controllerBTLS}, nil
		default:
			return nil, errors.New("unknown actor")
		}
	}
	authorizedDials := 0
	executor.dialGateway = func(ctx context.Context, endpoint, token string, config *tls.Config) (io.ReadWriteCloser, error) {
		authorizedDials++
		if endpoint != executor.gatewayEndpoint || token == "" {
			return nil, errors.New("changed Gateway authority")
		}
		if authorizedDials == 1 && config == controllerATLS {
			return service.opener(ctx, service.handoff)
		}
		if authorizedDials == 2 && config == controllerBTLS {
			return nil, gateway.ErrUpgradeRejected
		}
		return nil, errors.New("unexpected Gateway dial")
	}
	anonymousDials := 0
	executor.dialGatewayWithoutClientCertificate = func(_ context.Context, endpoint, token string, config *tls.Config) (io.ReadWriteCloser, error) {
		anonymousDials++
		if endpoint != executor.gatewayEndpoint || token == "" || config == nil || len(config.Certificates) != 0 {
			return nil, errors.New("anonymous probe retained caller credentials")
		}
		return nil, gateway.ErrGatewayTransport
	}

	roundTripCtx, roundTripCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer roundTripCancel()
	if _, err := executor.Execute(roundTripCtx, scenariocontrol.GatewayRoundTripCaseID); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	providerConnects := len(client.connects)
	rejectionCtx, rejectionCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rejectionCancel()
	result, err := executor.Execute(rejectionCtx, scenariocontrol.GatewayAuthorityRejectionCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.GatewayAuthorityRejectionCaseID || result.Disposition != "completed" || len(result.Interactions) != 2 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, []string{"no-runtime-connection", "tenant-b-cannot-use-tenant-a-session", "no-terminal-bytes-forwarded"}) {
		t.Fatalf("Gateway rejection result = %#v", result)
	}
	for index, interaction := range result.Interactions {
		if interaction.FinalOutcome.Transport != "gateway-upgrade-rejected" || interaction.FinalOutcome.StatusCode != nil || interaction.FinalOutcome.ErrorCode != nil || interaction.WireAttempts != 1 || interaction.MutationWriteObserved || len(interaction.TransientOutcomes) != 0 {
			t.Fatalf("Gateway rejection interaction %d = %#v", index, interaction)
		}
	}
	if starts != 2 || service.issueCalls != 2 || service.stopCalls != 2 || anonymousDials != 1 || authorizedDials != 2 || len(client.connects) != providerConnects || executor.next != 10 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("Gateway rejection composition = starts %d, service %#v, anonymous %d, authorized %d, connects %d, next %d, state %#v", starts, service, anonymousDials, authorizedDials, len(client.connects), executor.next, store.Snapshot())
	}
	public, err := json.Marshal(result)
	if err != nil || containsBytes(public, []byte(service.handoff)) {
		t.Fatalf("public rejection result leaked handoff: %q / %v", public, err)
	}
}

func TestGatewayAuthorityRejectionFailureStopsGatewayWithoutAdvancing(t *testing.T) {
	executor, _, store := cancellationCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	terminalCtx, terminalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer terminalCancel()
	if _, err := executor.Execute(terminalCtx, scenariocontrol.TerminalSessionCaseID); err != nil {
		t.Fatal(err)
	}
	executor.next = 9
	before := store.Snapshot()
	service := &scenarioGatewayFake{}
	executor.bundle = &credentials.Bundle{}
	executor.gatewayEndpoint = "https://gateway.example/tunnel"
	executor.startGateway = func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	}
	executor.buildGatewayAccess = func(_ *credentials.Bundle, _ string, actor string) (*credentials.GatewayAccess, error) {
		return &credentials.GatewayAccess{Actor: actor, ControllerSubject: "spiffe://caller/" + actor, TLSConfig: &tls.Config{}}, nil
	}
	executor.dialGatewayWithoutClientCertificate = func(context.Context, string, string, *tls.Config) (io.ReadWriteCloser, error) {
		return nil, errors.New("unclassified anonymous transport failure")
	}
	executor.dialGateway = func(context.Context, string, string, *tls.Config) (io.ReadWriteCloser, error) {
		t.Fatal("cross-tenant probe ran after anonymous failure")
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.GatewayAuthorityRejectionCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("Gateway rejection failure = %v", err)
	}
	if service.stopCalls != 1 || executor.next != 9 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("failed rejection cleanup/progress = service %#v, next %d, state %#v", service, executor.next, store.Snapshot())
	}
}
