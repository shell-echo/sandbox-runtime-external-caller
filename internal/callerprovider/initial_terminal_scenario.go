package callerprovider

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

const terminalScenarioFencingToken = int64(5)

func (executor *InitialScenarioExecutor) executeTerminalSession(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second || state.Stage != callerstate.StageExecBound || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.StoreRevision != 4 || !validAccess(executor.controllerA) || executor.sandbox.ObservedState != "ready" || executor.sandbox.Generation != 1 || executor.sandbox.ObservedGeneration != 1 {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	request, err := terminalScenarioRequest(ctx, state, executor.sandbox.LeaseExpiresAt, startedAt)
	if err != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor := plannedDescriptor(state, state.Plan.Terminal, terminalScenarioFencingToken)
	admission, err := mutationAdmission(executor.controllerA, state, descriptor, "open_runtime_session", request.RequestDigest, request.DeadlineAt, provider.RuntimeSessionRequestContractID, "/v1/sandboxes/"+state.Plan.SandboxID+"/runtime-sessions", executor.now())
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	accepted, submitAttempts, submitTransients, err := submitRuntimeSession(ctx, executor.controllerA.client, state.Plan.SandboxID, request, admission)
	if err != nil || accepted.Status != "accepted" || !operationMatches(accepted, descriptor, "open_runtime_session") {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	operation, operationAttempts, operationTransients, err := pollExpectedOperation(ctx, executor.controllerA, state, descriptor, "open_runtime_session", executor.now)
	if err != nil || operation.Status != "succeeded" {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor.Operation = "read_runtime_session"
	handoff, handoffAttempts, handoffTransients, err := readScenarioRetained(ctx, executor.controllerA, state, descriptor, executor.now, executor.controllerA.client.GetRuntimeSessionHandoff)
	if err != nil || !validTerminalHandoff(handoff, descriptor, request, executor.now()) || executor.store.ValidateUnchanged() != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}

	startObservations := []string{"session-operation-accepted"}
	operationObservations := []string{"operation-succeeded"}
	handoffObservations := []string{"websocket-protocol", "opaque-reference", "connection-generation-positive"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.TerminalSessionCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "open-terminal-session", Surface: "provider_http", Actor: "controller_a", Method: http.MethodPost, RouteTemplate: "/v1/sandboxes/{sandbox_id}/runtime-sessions", LogicalRequestID: "open-terminal-session", WireAttempts: submitAttempts, TransientOutcomes: cloneOutcomes(submitTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusAccepted)}, MutationWriteObserved: true, ObservationIDs: append([]string(nil), startObservations...)},
			{InteractionID: "read-terminal-operation", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-terminal-operation", WireAttempts: operationAttempts, TransientOutcomes: cloneOutcomes(operationTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, ObservationIDs: append([]string(nil), operationObservations...)},
			{InteractionID: "read-terminal-handoff", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}/runtime-session", LogicalRequestID: "read-terminal-handoff", WireAttempts: handoffAttempts, TransientOutcomes: cloneOutcomes(handoffTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, ObservationIDs: append([]string(nil), handoffObservations...)},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "caller-retained-session-correlation", Result: "asserted"}},
		ObservationIDs: []string{"session-operation-accepted", "operation-succeeded", "websocket-protocol", "opaque-reference", "connection-generation-positive"},
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil || ctx.Err() != nil || executor.store.BindTerminal(terminalScenarioFencingToken, handoff.RuntimeSessionID, handoff.InternalEndpointReference) != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	after := executor.store.Snapshot()
	if after.Stage != callerstate.StageTerminalBound || after.StoreRevision != 5 || after.Terminal == nil || after.Terminal.Operation.OperationID != state.Plan.Terminal.OperationID || after.Terminal.Operation.AttemptID != state.Plan.Terminal.AttemptID || after.Terminal.Operation.FencingToken != terminalScenarioFencingToken || after.Terminal.RuntimeSessionID != handoff.RuntimeSessionID || after.Terminal.HandoffReference != handoff.InternalEndpointReference {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	executor.terminalRequest, executor.terminalAdmission = request, admission
	executor.terminalOperation, executor.terminalHandoff = operation, handoff
	return result, nil
}

func terminalScenarioRequest(ctx context.Context, state callerstate.State, lease string, now time.Time) (provider.RuntimeSessionOpenRequest, error) {
	request, err := runtimeSessionRequest(ctx, state, lease, now)
	if err != nil {
		return provider.RuntimeSessionOpenRequest{}, err
	}
	request.FencingToken = terminalScenarioFencingToken
	request.RequestDigest = ""
	return provider.BindRuntimeSessionOpenRequest(request)
}

func submitRuntimeSession(ctx context.Context, client providerClient, sandboxID string, request provider.RuntimeSessionOpenRequest, admission provider.Admission) (provider.ProviderOperation, int, []protocol.Outcome, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= 2; attempt++ {
		operation, err := client.OpenRuntimeSession(ctx, sandboxID, request, admission)
		if err == nil {
			return operation, attempt, transients, nil
		}
		var responseError *provider.HTTPError
		if attempt == 2 || !errors.As(err, &responseError) || (responseError.StatusCode != http.StatusTooManyRequests && responseError.StatusCode != http.StatusServiceUnavailable) || !responseError.Document.Retryable || responseError.RetryAfterSeconds == nil || *responseError.RetryAfterSeconds <= 0 {
			return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
		}
		transients = append(transients, httpOutcome(responseError))
		if waitRetry(ctx, *responseError.RetryAfterSeconds) != nil {
			return provider.ProviderOperation{}, 0, nil, preserveContext(ctx, ErrInitialScenario)
		}
	}
	return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
}

func validTerminalHandoff(handoff provider.RuntimeSessionHandoff, descriptor provider.ReadDescriptor, request provider.RuntimeSessionOpenRequest, now time.Time) bool {
	expiresAt, expiryErr := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
	requestedExpiry, requestErr := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	_, descriptorErr := provider.DigestRuntimeSessionConnectDescriptor(handoff)
	return descriptorErr == nil && correlates(descriptor, handoff.SandboxID, handoff.OperationID, handoff.AttemptID, handoff.FencingToken) &&
		handoff.RuntimeSessionID == request.RuntimeSessionID && handoff.RuntimeType == request.RuntimeType && handoff.CapabilityProfileID == request.CapabilityProfileID &&
		handoff.Protocol == "websocket" && handoff.ConnectionGeneration > 0 && expiryErr == nil && requestErr == nil && expiresAt.After(now) && !expiresAt.After(requestedExpiry)
}
