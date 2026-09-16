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

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerterminal"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

type scenarioGatewayFake struct {
	opener           callerterminal.BackendOpener
	installed        bool
	issued           bool
	stopped          bool
	issueCalls       int
	stopCalls        int
	revokeCalls      int
	tenantA, tenantB string
	actor, tenant    string
	session, handoff string
	expiresAt        time.Time
	revokeActor      string
	revokeToken      string
	revoke           func() error
}

func (service *scenarioGatewayFake) InstallPolicy(_ context.Context, tenantA, tenantB string) error {
	service.installed, service.tenantA, service.tenantB = true, tenantA, tenantB
	return nil
}

func (service *scenarioGatewayFake) SetBackend(opener callerterminal.BackendOpener) error {
	if !service.installed || opener == nil {
		return errors.New("invalid backend ordering")
	}
	service.opener = opener
	return nil
}

func (service *scenarioGatewayFake) IssueGrant(_ context.Context, actor, tenant, session, handoff string, expiresAt time.Time) (string, error) {
	if service.opener == nil {
		return "", errors.New("backend not set")
	}
	service.issued, service.actor, service.tenant = true, actor, tenant
	service.issueCalls++
	service.session, service.handoff, service.expiresAt = session, handoff, expiresAt
	return strings.Repeat("A", 43), nil
}

func (service *scenarioGatewayFake) Stop(context.Context) error {
	service.stopped = true
	service.stopCalls++
	return nil
}

func (service *scenarioGatewayFake) Revoke(_ context.Context, actor, token string) error {
	service.revokeCalls++
	service.revokeActor = actor
	service.revokeToken = token
	if service.revoke != nil {
		return service.revoke()
	}
	return nil
}

func TestGatewayRoundTripUsesCallerPolicyAndLeavesTerminalStateUnchanged(t *testing.T) {
	executor, client, store := cancellationCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	terminalCtx, terminalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer terminalCancel()
	if _, err := executor.Execute(terminalCtx, scenariocontrol.TerminalSessionCaseID); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	service := &scenarioGatewayFake{}
	executor.bundle = &credentials.Bundle{}
	executor.gatewayEndpoint = "https://gateway.example/tunnel"
	executor.startGateway = func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	}
	executor.buildGatewayAccess = func(_ *credentials.Bundle, endpoint, actor string) (*credentials.GatewayAccess, error) {
		if endpoint != executor.gatewayEndpoint || actor != "controller_a" {
			t.Fatal("Gateway access binding changed")
		}
		return &credentials.GatewayAccess{Actor: actor, TLSConfig: &tls.Config{}}, nil
	}
	executor.dialGateway = func(ctx context.Context, endpoint, token string, config *tls.Config) (io.ReadWriteCloser, error) {
		if !service.issued || endpoint != executor.gatewayEndpoint || token != strings.Repeat("A", 43) || config == nil {
			return nil, errors.New("invalid dial authority")
		}
		return service.opener(ctx, service.handoff)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.GatewayRoundTripCaseID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != scenariocontrol.GatewayRoundTripCaseID || result.Disposition != "completed" || len(result.Interactions) != 1 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, []string{"grant-bound-to-controller-a", "terminal-bytes-round-tripped", "shell-continuity-challenge-established", "shell-continuity-challenge-digest-recorded", "bounded-byte-count"}) {
		t.Fatalf("Gateway round-trip result = %#v", result)
	}
	interaction := result.Interactions[0]
	if interaction.FinalOutcome.Transport != "authorized-byte-round-trip" || interaction.FinalOutcome.StatusCode != nil || interaction.FinalOutcome.ErrorCode != nil || interaction.WireAttempts != 1 || interaction.MutationWriteObserved || len(interaction.TransientOutcomes) != 0 {
		t.Fatalf("Gateway interaction = %#v", interaction)
	}
	if !service.installed || !service.issued || !service.stopped || service.actor != "controller_a" || service.tenant != before.Plan.TenantAID || service.tenantA != before.Plan.TenantAID || service.tenantB != before.Plan.TenantBID || service.session != before.Terminal.RuntimeSessionID || service.handoff != before.Terminal.HandoffReference || !service.expiresAt.After(time.Now()) || len(client.connects) != 1 || client.connects[0] != executor.terminalHandoff || executor.next != 9 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("Gateway/private composition = service %#v, connects %#v, state %#v", service, client.connects, store.Snapshot())
	}
	lastAdmission := client.admissions[len(client.admissions)-1]
	if lastAdmission.Context.Operation != "connect_runtime_session" || lastAdmission.Context.SandboxID != before.Plan.SandboxID || lastAdmission.Context.OperationID != before.Terminal.Operation.OperationID || lastAdmission.Context.FencingToken != before.Terminal.Operation.FencingToken {
		t.Fatalf("terminal connect Admission = %#v", lastAdmission.Context)
	}
	public, err := json.Marshal(result)
	if err != nil || containsBytes(public, []byte(service.handoff)) || containsBytes(public, []byte(strings.Repeat("A", 43))) {
		t.Fatalf("public result leaked private authority: %q / %v", public, err)
	}
}

func TestGatewayRoundTripFailureStopsGatewayWithoutAdvancing(t *testing.T) {
	executor, _, store := cancellationCompletedScenarioExecutor(t)
	defer executor.Close()
	defer store.Close()
	terminalCtx, terminalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer terminalCancel()
	if _, err := executor.Execute(terminalCtx, scenariocontrol.TerminalSessionCaseID); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	service := &scenarioGatewayFake{}
	executor.bundle = &credentials.Bundle{}
	executor.gatewayEndpoint = "https://gateway.example/tunnel"
	executor.startGateway = func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	}
	executor.buildGatewayAccess = func(*credentials.Bundle, string, string) (*credentials.GatewayAccess, error) {
		return &credentials.GatewayAccess{TLSConfig: &tls.Config{}}, nil
	}
	executor.dialGateway = func(context.Context, string, string, *tls.Config) (io.ReadWriteCloser, error) {
		return nil, errors.New("synthetic Gateway dial failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.GatewayRoundTripCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("Gateway failure = %v", err)
	}
	if !service.stopped || executor.next != 8 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("failed Gateway cleanup/progress = service %#v, next %d, state %#v", service, executor.next, store.Snapshot())
	}
}

var _ ScenarioGateway = (*scenarioGatewayFake)(nil)
