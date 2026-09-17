package callerprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerterminal"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

const terminalChallengeBytes = 32

type ScenarioGateway interface {
	InstallPolicy(context.Context, string, string) error
	SetBackend(callerterminal.BackendOpener) error
	IssueGrant(context.Context, string, string, string, string, time.Time) (string, error)
	Revoke(context.Context, string, string) error
	Stop(context.Context) error
}

type StartScenarioGateway func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error)

func dialScenarioGateway(ctx context.Context, endpoint, token string, config *tls.Config) (io.ReadWriteCloser, error) {
	return gateway.DialTunnel(ctx, endpoint, token, config)
}

func stopScenarioGateway(service ScenarioGateway) {
	if service == nil {
		return
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = service.Stop(cleanup)
}

func (executor *InitialScenarioExecutor) executeGatewayRoundTrip(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second || state.Stage != callerstate.StageTerminalBound || state.StoreRevision != 5 || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.Terminal == nil || !validAccess(executor.controllerA) || executor.bundle == nil || executor.gatewayEndpoint == "" || executor.startGateway == nil || executor.dialGateway == nil || executor.buildGatewayAccess == nil || !terminalScenarioAuthorityMatches(state, executor.terminalRequest, executor.terminalOperation, executor.terminalHandoff, startedAt) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	access, err := executor.buildGatewayAccess(executor.bundle, executor.gatewayEndpoint, "controller_a")
	if err != nil || access == nil || access.TLSConfig == nil {
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
	connection, err := executor.dialGateway(ctx, executor.gatewayEndpoint, token, access.TLSConfig)
	if err != nil || connection == nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	deadlineConnection, ok := connection.(interface{ SetDeadline(time.Time) error })
	if !ok || deadlineConnection.SetDeadline(deadline) != nil {
		_ = connection.Close()
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	challengeDigest, roundTripErr := runTerminalChallenge(connection)
	closeErr := connection.Close()
	if roundTripErr != nil || closeErr != nil || challengeDigest == ([sha256.Size]byte{}) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	if ctx.Err() != nil || service.Stop(ctx) != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	stopped = true
	if executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	observations := []string{"grant-bound-to-controller-a", "terminal-bytes-round-tripped", "shell-continuity-challenge-established", "shell-continuity-challenge-digest-recorded", "bounded-byte-count"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.GatewayRoundTripCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "gateway-terminal-round-trip", Surface: "caller_gateway", Actor: "controller_a", Method: http.MethodConnect,
			RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-terminal-round-trip", WireAttempts: 1,
			TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "authorized-byte-round-trip"},
			ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions:     []protocol.AssertionResult{{AssertionID: "gateway-policy-owned-by-caller", Result: "asserted"}},
		ObservationIDs: append([]string(nil), observations...),
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	return result, nil
}

func (executor *InitialScenarioExecutor) openTerminalBackend(state callerstate.State) callerterminal.BackendOpener {
	handoff := executor.terminalHandoff
	return func(ctx context.Context, reference string) (io.ReadWriteCloser, error) {
		if ctx == nil {
			return nil, ErrInitialScenario
		}
		expiresAt, expiryErr := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
		deadline, ok := ctx.Deadline()
		if ctx.Err() != nil || reference != handoff.InternalEndpointReference || expiryErr != nil || !expiresAt.After(executor.now()) {
			return nil, ErrInitialScenario
		}
		if !ok || expiresAt.Before(deadline) {
			deadline = expiresAt
		}
		digest, err := provider.DigestRuntimeSessionConnectDescriptor(handoff)
		if err != nil || !deadline.After(executor.now()) {
			return nil, ErrInitialScenario
		}
		admission, err := buildAdmission(executor.controllerA, state, provider.AdmissionBinding{
			Operation: "connect_runtime_session", SandboxID: handoff.SandboxID, OperationID: handoff.OperationID,
			AttemptID: handoff.AttemptID, FencingToken: handoff.FencingToken, DeadlineAt: deadline.UTC().Format(time.RFC3339Nano),
			RequestContractID: provider.RuntimeSessionConnectDescriptorContractID, RequestDigestProfile: provider.DescriptorDigestProfile, RequestDigest: digest,
			HTTPTarget: provider.AdmissionTarget{Method: http.MethodGet, Path: "/v1/runtime-sessions:connect", NormalizedQuery: []provider.QueryParameter{}},
		}, executor.now())
		if err != nil {
			return nil, ErrInitialScenario
		}
		return executor.controllerA.client.ConnectRuntimeSession(ctx, handoff, admission)
	}
}

func terminalScenarioAuthorityMatches(state callerstate.State, request provider.RuntimeSessionOpenRequest, operation provider.ProviderOperation, handoff provider.RuntimeSessionHandoff, now time.Time) bool {
	expiresAt, err := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
	return err == nil && expiresAt.After(now) && request.OperationID == state.Terminal.Operation.OperationID && request.AttemptID == state.Terminal.Operation.AttemptID && request.FencingToken == state.Terminal.Operation.FencingToken &&
		operation.OperationID == request.OperationID && operation.AttemptID == request.AttemptID && operation.FencingToken == request.FencingToken && operation.SandboxID == state.Plan.SandboxID && operation.Type == "open_runtime_session" && operation.Status == "succeeded" &&
		handoff.OperationID == request.OperationID && handoff.AttemptID == request.AttemptID && handoff.FencingToken == request.FencingToken && handoff.SandboxID == state.Plan.SandboxID && handoff.RuntimeSessionID == state.Terminal.RuntimeSessionID && handoff.InternalEndpointReference == state.Terminal.HandoffReference && handoff.Protocol == "websocket" && handoff.ConnectionGeneration > 0
}

func validGatewayToken(token string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	valid := err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == token
	clear(raw)
	return valid
}

func writeScenarioBytes(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil || written < 1 || written > len(payload) {
			return ErrInitialScenario
		}
		payload = payload[written:]
	}
	return nil
}

func runTerminalChallenge(stream io.ReadWriter) ([sha256.Size]byte, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return [sha256.Size]byte{}, ErrInitialScenario
	}
	digest := sha256.Sum256(entropy[:])
	marker := "SRC-ROUNDTRIP-" + hex.EncodeToString(entropy[:])
	clear(entropy[:])
	command := []byte("printf '\\n" + marker + "\\n'\n")
	if writeScenarioBytes(stream, command) != nil {
		clear(command)
		return [sha256.Size]byte{}, ErrInitialScenario
	}
	clear(command)
	wantLF := []byte("\n" + marker + "\n")
	wantCRLF := []byte("\r\n" + marker + "\r\n")
	observed := make([]byte, 0, 4096)
	buffer := make([]byte, 1024)
	for len(observed) < 64<<10 {
		count, err := stream.Read(buffer)
		if count > 0 {
			observed = append(observed, buffer[:count]...)
			if bytes.Contains(observed, wantLF) || bytes.Contains(observed, wantCRLF) {
				clear(buffer)
				clear(observed)
				return digest, nil
			}
		}
		if err != nil || count == 0 {
			break
		}
	}
	clear(buffer)
	clear(observed)
	return [sha256.Size]byte{}, ErrInitialScenario
}
