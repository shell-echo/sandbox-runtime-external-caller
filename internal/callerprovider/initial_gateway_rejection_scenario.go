package callerprovider

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func dialScenarioGatewayWithoutClientCertificate(ctx context.Context, endpoint, token string, config *tls.Config) (io.ReadWriteCloser, error) {
	return gateway.DialTunnelWithoutClientCertificate(ctx, endpoint, token, config)
}

func (executor *InitialScenarioExecutor) executeGatewayAuthorityRejections(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second ||
		state.Stage != callerstate.StageTerminalBound || state.StoreRevision != 5 || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.Terminal == nil ||
		state.Plan.TenantAID == state.Plan.TenantBID || !validAccess(executor.controllerA) || executor.bundle == nil || executor.gatewayEndpoint == "" || executor.startGateway == nil ||
		executor.dialGateway == nil || executor.dialGatewayWithoutClientCertificate == nil || executor.buildGatewayAccess == nil ||
		!terminalScenarioAuthorityMatches(state, executor.terminalRequest, executor.terminalOperation, executor.terminalHandoff, startedAt) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	controllerA, err := executor.buildGatewayAccess(executor.bundle, executor.gatewayEndpoint, "controller_a")
	if err != nil || !validScenarioGatewayAccess(controllerA, "controller_a") {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	controllerB, err := executor.buildGatewayAccess(executor.bundle, executor.gatewayEndpoint, "controller_b")
	if err != nil || !validScenarioGatewayAccess(controllerB, "controller_b") || controllerA.ControllerSubject == controllerB.ControllerSubject {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	anonymousTLS := controllerA.TLSConfig.Clone()
	anonymousTLS.Certificates = nil
	anonymousTLS.GetClientCertificate = nil

	service, err := executor.startGateway(ctx, "initial", executor.gatewayEndpoint, executor.bundle)
	if err != nil || service == nil {
		stopScenarioGateway(service)
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	stopped := false
	defer func() {
		if !stopped {
			stopScenarioGateway(service)
		}
	}()
	if service.InstallPolicy(ctx, state.Plan.TenantAID, state.Plan.TenantBID) != nil || service.SetBackend(executor.openTerminalBackend(state)) != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	handoffExpiry, _ := time.Parse(time.RFC3339Nano, executor.terminalHandoff.ExpiresAt)
	grantExpiry := deadline
	if handoffExpiry.Before(grantExpiry) {
		grantExpiry = handoffExpiry
	}
	if !grantExpiry.After(executor.now()) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	token, err := service.IssueGrant(ctx, "controller_a", state.Plan.TenantAID, executor.terminalHandoff.RuntimeSessionID, executor.terminalHandoff.InternalEndpointReference, grantExpiry)
	if err != nil || !validGatewayToken(token) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	anonymousConnection, anonymousErr := executor.dialGatewayWithoutClientCertificate(ctx, executor.gatewayEndpoint, token, anonymousTLS)
	if anonymousConnection != nil {
		_ = anonymousConnection.Close()
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	// The production Gateway requires a verified client certificate during the
	// TLS handshake, so an intentionally certificate-free probe may be rejected
	// before HTTP CONNECT or by the HTTP upgrade boundary.
	if (!errors.Is(anonymousErr, gateway.ErrUpgradeRejected) && !errors.Is(anonymousErr, gateway.ErrGatewayTransport) && !errors.Is(anonymousErr, gateway.ErrResponseHeader)) || ctx.Err() != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	crossTenantConnection, crossTenantErr := executor.dialGateway(ctx, executor.gatewayEndpoint, token, controllerB.TLSConfig)
	if crossTenantConnection != nil {
		_ = crossTenantConnection.Close()
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	if !errors.Is(crossTenantErr, gateway.ErrUpgradeRejected) || ctx.Err() != nil || service.Stop(ctx) != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	stopped = true
	if executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.GatewayAuthorityRejectionCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{
				InteractionID: "gateway-missing-caller-credential", Surface: "caller_gateway", Actor: "unauthenticated_client", Method: http.MethodConnect,
				RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-missing-caller-credential", WireAttempts: 1,
				TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "gateway-upgrade-rejected"},
				ObservationIDs: []string{"no-runtime-connection"},
			},
			{
				InteractionID: "gateway-cross-tenant", Surface: "caller_gateway", Actor: "controller_b", Method: http.MethodConnect,
				RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-cross-tenant", WireAttempts: 1,
				TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "gateway-upgrade-rejected"},
				ObservationIDs: []string{"tenant-b-cannot-use-tenant-a-session", "no-terminal-bytes-forwarded"},
			},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "controllers-belong-to-distinct-tenants", Result: "asserted"}},
		ObservationIDs: []string{"no-runtime-connection", "tenant-b-cannot-use-tenant-a-session", "no-terminal-bytes-forwarded"},
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	return result, nil
}

func validScenarioGatewayAccess(access *credentials.GatewayAccess, actor string) bool {
	return access != nil && access.Actor == actor && access.ControllerSubject != "" && access.TLSConfig != nil
}
