package callerprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func (executor *InitialScenarioExecutor) executeReconstructionHandoff(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second ||
		state.Stage != callerstate.StageInitialComplete || state.StoreRevision != 6 || state.Provider == nil || state.Lifecycle == nil ||
		state.Exec == nil || state.Terminal == nil || state.Artifact == nil || !validAccess(executor.controllerA) || executor.reconstructionGateway == nil ||
		executor.terminalHandoff.InternalEndpointReference != "" {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor := provider.ReadDescriptor{
		Operation: "read_runtime_session", SandboxID: state.Plan.SandboxID,
		OperationID: state.Terminal.Operation.OperationID, AttemptID: state.Terminal.Operation.AttemptID,
		FencingToken: state.Terminal.Operation.FencingToken,
	}
	handoff, attempts, transients, err := readScenarioRetained(ctx, executor.controllerA, state, descriptor, executor.now, executor.controllerA.client.GetRuntimeSessionHandoff)
	if err != nil || !retainedHandoffMatches(state, descriptor, handoff, executor.now()) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	observations := []string{"same-handoff-reference-digest", "same-runtime-session", "opaque-reference"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.ReconstructionHandoffCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "read-retained-terminal-handoff", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet,
			RouteTemplate: "/v1/operations/{operation_id}/runtime-session", LogicalRequestID: "read-retained-terminal-handoff", WireAttempts: attempts,
			TransientOutcomes: cloneOutcomes(transients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)},
			MutationWriteObserved: false, ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions:     []protocol.AssertionResult{{AssertionID: "raw-handoff-reference-absent-from-evidence", Result: "asserted"}},
		ObservationIDs: append([]string(nil), observations...),
	}
	public, marshalErr := json.Marshal(result)
	if marshalErr != nil || bytes.Contains(public, []byte(handoff.InternalEndpointReference)) || protocol.ValidateScenarioResultData("reconstruction", result) != nil || ctx.Err() != nil ||
		!retainedHandoffMatches(state, descriptor, handoff, executor.now()) || executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	executor.terminalHandoff = handoff
	return result, nil
}

func retainedHandoffMatches(state callerstate.State, descriptor provider.ReadDescriptor, handoff provider.RuntimeSessionHandoff, now time.Time) bool {
	expiresAt, err := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
	return err == nil && expiresAt.After(now) && correlates(descriptor, handoff.SandboxID, handoff.OperationID, handoff.AttemptID, handoff.FencingToken) &&
		handoff.RuntimeSessionID == state.Terminal.RuntimeSessionID && handoff.RuntimeType == "terminal" && handoff.CapabilityProfileID == TerminalProfileID &&
		handoff.Protocol == "websocket" && handoff.InternalEndpointReference == state.Terminal.HandoffReference &&
		rawDigest([]byte(handoff.InternalEndpointReference)) == state.Terminal.HandoffReferenceDigest && handoff.ConnectionGeneration > 0
}

func (executor *InitialScenarioExecutor) executeReconstructionReconnect(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second ||
		state.Stage != callerstate.StageInitialComplete || state.StoreRevision != 6 || state.Provider == nil || state.Lifecycle == nil ||
		state.Exec == nil || state.Terminal == nil || state.Artifact == nil || !validAccess(executor.controllerA) || executor.reconstructionGateway == nil ||
		executor.bundle == nil || executor.gatewayEndpoint == "" || executor.dialGateway == nil || executor.buildGatewayAccess == nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor := provider.ReadDescriptor{
		Operation: "read_runtime_session", SandboxID: state.Plan.SandboxID,
		OperationID: state.Terminal.Operation.OperationID, AttemptID: state.Terminal.Operation.AttemptID,
		FencingToken: state.Terminal.Operation.FencingToken,
	}
	if !retainedHandoffMatches(state, descriptor, executor.terminalHandoff, startedAt) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	access, err := executor.buildGatewayAccess(executor.bundle, executor.gatewayEndpoint, "controller_a")
	if err != nil || access == nil || access.TLSConfig == nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	if executor.reconstructionGateway.SetBackend(executor.openTerminalBackend(state)) != nil {
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
	token, err := executor.reconstructionGateway.IssueGrant(ctx, "controller_a", state.Plan.TenantAID, state.Terminal.RuntimeSessionID, state.Terminal.HandoffReference, grantExpiry)
	if err != nil || !validGatewayToken(token) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	connection, err := executor.dialGateway(ctx, executor.gatewayEndpoint, token, access.TLSConfig)
	if err != nil || connection == nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	deadlineConnection, ok := connection.(interface{ SetDeadline(time.Time) error })
	if !ok || deadlineConnection.SetDeadline(grantExpiry) != nil {
		_ = connection.Close()
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	challenge := make([]byte, terminalChallengeBytes)
	received := make([]byte, terminalChallengeBytes)
	if _, err := rand.Read(challenge); err != nil {
		_ = connection.Close()
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	digest := sha256.Sum256(challenge)
	writeErr := writeScenarioBytes(connection, challenge)
	_, readErr := io.ReadFull(connection, received)
	closeErr := connection.Close()
	matched := reflect.DeepEqual(challenge, received)
	clear(challenge)
	clear(received)
	if writeErr != nil || readErr != nil || closeErr != nil || !matched || digest == ([sha256.Size]byte{}) || ctx.Err() != nil ||
		executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	observations := []string{"same-runtime-session", "shell-continuity-challenge-digest-matched", "bounded-byte-count", "adapter-invocation-transcript-excludes-forbidden-correlations"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.ReconstructionReconnectCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "gateway-same-shell-reconnect", Surface: "caller_gateway", Actor: "controller_a", Method: http.MethodConnect,
			RouteTemplate: "consumer-defined:terminal-connect", LogicalRequestID: "gateway-same-shell-reconnect", WireAttempts: 1,
			TransientOutcomes: []protocol.Outcome{}, FinalOutcome: protocol.Outcome{Transport: "authorized-byte-round-trip"},
			MutationWriteObserved: false, ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions: []protocol.AssertionResult{
			{AssertionID: "caller-loaded-handoff-from-own-durable-state", Result: "asserted"},
			{AssertionID: "harness-did-not-reinject-handoff", Result: "asserted"},
		},
		ObservationIDs: append([]string(nil), observations...),
	}
	public, marshalErr := json.Marshal(result)
	if marshalErr != nil || bytes.Contains(public, []byte(state.Terminal.HandoffReference)) || bytes.Contains(public, []byte(token)) ||
		protocol.ValidateScenarioResultData("reconstruction", result) != nil || !retainedHandoffMatches(state, descriptor, executor.terminalHandoff, executor.now()) ||
		!reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	return result, nil
}
