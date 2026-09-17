package callerprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

const (
	gatewayExpiryGrantLifetime = 3 * time.Second
	gatewayExpiryCloseGrace    = 5 * time.Second
	gatewayExpirySetupMinimum  = time.Second
)

func (executor *InitialScenarioExecutor) executeGatewayGrantExpiry(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(gatewayExpiryGrantLifetime+gatewayExpiryCloseGrace)) || deadline.Sub(startedAt) > 120*time.Second ||
		state.Stage != callerstate.StageTerminalBound || state.StoreRevision != 5 || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.Terminal == nil ||
		!validAccess(executor.controllerA) || executor.bundle == nil || executor.gatewayEndpoint == "" || executor.startGateway == nil || executor.dialGateway == nil || executor.buildGatewayAccess == nil ||
		!terminalScenarioAuthorityMatches(state, executor.terminalRequest, executor.terminalOperation, executor.terminalHandoff, startedAt) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	access, err := executor.buildGatewayAccess(executor.bundle, executor.gatewayEndpoint, "controller_a")
	if err != nil || !validScenarioGatewayAccess(access, "controller_a") {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
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
	handoffExpiry, err := time.Parse(time.RFC3339Nano, executor.terminalHandoff.ExpiresAt)
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	grantExpiry := startedAt.Add(gatewayExpiryGrantLifetime)
	caseBound := deadline.Add(-gatewayExpiryCloseGrace)
	if handoffExpiry.Before(grantExpiry) {
		grantExpiry = handoffExpiry
	}
	if caseBound.Before(grantExpiry) {
		grantExpiry = caseBound
	}
	if grantExpiry.Sub(executor.now()) < gatewayExpirySetupMinimum {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	token, err := service.IssueGrant(ctx, "controller_a", state.Plan.TenantAID, executor.terminalHandoff.RuntimeSessionID, executor.terminalHandoff.InternalEndpointReference, grantExpiry)
	if err != nil || !validGatewayToken(token) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	connection, err := executor.dialGateway(ctx, executor.gatewayEndpoint, token, access.TLSConfig)
	if err != nil || connection == nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	defer connection.Close()
	deadlineConnection, ok := connection.(interface{ SetDeadline(time.Time) error })
	if !ok || deadlineConnection.SetDeadline(minTime(deadline, grantExpiry.Add(gatewayExpiryCloseGrace))) != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	challengeDigest, challengeErr := runTerminalChallenge(connection)
	initiallyAuthorized := challengeErr == nil && challengeDigest != ([sha256.Size]byte{}) && executor.now().Before(grantExpiry)
	if !initiallyAuthorized {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	var probe [1]byte
	readCount, closeErr := connection.Read(probe[:])
	var networkError net.Error
	if readCount != 0 || closeErr == nil || (errors.As(closeErr, &networkError) && networkError.Timeout()) || executor.now().Before(grantExpiry) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	// TCP may locally accept one write after a peer close has already been
	// observed. Do not mistake that buffering behavior for forwarding: probe
	// again and require the closed tunnel to return no bytes without timing out.
	_ = writeScenarioBytes(connection, []byte{0x7f})
	readCount, postExpiryReadErr := connection.Read(probe[:])
	networkError = nil
	if readCount != 0 || postExpiryReadErr == nil || (errors.As(postExpiryReadErr, &networkError) && networkError.Timeout()) || ctx.Err() != nil || service.Stop(ctx) != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	stopped = true
	if executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	observations := []string{"grant-initially-authorized", "connection-closed-after-expiry", "no-post-expiry-forwarding"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.GatewayGrantExpiryCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "gateway-expiring-grant", Surface: "caller_gateway", Actor: "controller_a", Method: http.MethodConnect,
			RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-expiring-grant", WireAttempts: 1,
			TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "gateway-closed-at-grant-expiry"},
			ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions:     []protocol.AssertionResult{{AssertionID: "caller-enforced-grant-expiry", Result: "asserted"}},
		ObservationIDs: append([]string(nil), observations...),
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	return result, nil
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
