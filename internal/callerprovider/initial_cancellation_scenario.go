package callerprovider

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

const (
	cancellableExecFencingToken = int64(3)
	cancelExecFencingToken      = int64(4)
)

func (executor *InitialScenarioExecutor) executeExecCancellation(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second || state.Stage != callerstate.StageExecBound || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.StoreRevision != 4 || !validAccess(executor.controllerA) || executor.sandbox.ObservedState != "ready" || executor.sandbox.Generation != 1 || executor.sandbox.ObservedGeneration != 1 {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	request, err := cancellableExecRequest(ctx, state, executor.capabilities.Limits.MaxExecSeconds, executor.sandbox.LeaseExpiresAt, startedAt)
	if err != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	target := provider.ReadDescriptor{Operation: "read_operation", SandboxID: state.Plan.SandboxID, OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken}
	startAdmission, err := mutationAdmission(executor.controllerA, state, target, "exec", request.RequestDigest, request.DeadlineAt, provider.ExecRequestContractID, "/v1/sandboxes/"+state.Plan.SandboxID+"/exec", executor.now())
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	acceptedExec, startAttempts, startTransients, err := submitExec(ctx, executor.controllerA.client, state.Plan.SandboxID, request, startAdmission)
	if err != nil || acceptedExec.Status != "accepted" || !operationMatches(acceptedExec, target, "exec") {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}

	cancelRequest, err := cancelExecRequest(ctx, state, target, executor.sandbox.LeaseExpiresAt, executor.now())
	if err != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	cancelDescriptor := provider.ReadDescriptor{Operation: "read_operation", SandboxID: state.Plan.SandboxID, OperationID: cancelRequest.OperationID, AttemptID: cancelRequest.AttemptID, FencingToken: cancelRequest.FencingToken}
	cancelAdmission, err := mutationAdmission(executor.controllerA, state, cancelDescriptor, "cancel_exec", cancelRequest.RequestDigest, cancelRequest.DeadlineAt, provider.CancelExecRequestContractID, "/v1/sandboxes/"+state.Plan.SandboxID+"/exec:cancel", executor.now())
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	acceptedCancel, cancelAttempts, cancelTransients, err := submitCancelExec(ctx, executor.controllerA.client, state.Plan.SandboxID, cancelRequest, cancelAdmission)
	if err != nil || acceptedCancel.Status != "accepted" || !operationMatches(acceptedCancel, cancelDescriptor, "cancel_exec") {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	cancelOperation, cancelReadAttempts, cancelReadTransients, err := pollExpectedOperationStatus(ctx, executor.controllerA, state, cancelDescriptor, "cancel_exec", "succeeded", executor.now)
	if err != nil || cancelOperation.Status != "succeeded" {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	targetOperation, targetReadAttempts, targetReadTransients, err := pollExpectedOperationStatus(ctx, executor.controllerA, state, target, "exec", "cancelled", executor.now)
	if err != nil || targetOperation.Status != "cancelled" {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	target.Operation = "read_result"
	cancelledResult, resultAttempts, resultTransients, err := readScenarioRetained(ctx, executor.controllerA, state, target, executor.now, executor.controllerA.client.GetExecResult)
	if err != nil || !validCancelledExecResult(cancelledResult, target, executor.now()) || executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}

	startObservations := []string{"exec-operation-accepted"}
	cancelObservations := []string{"cancellation-intent-accepted"}
	cancelReadObservations := []string{"cancel-operation-succeeded"}
	targetReadObservations := []string{"target-exec-operation-cancelled"}
	resultObservations := []string{"exec-result-cancelled"}
	resultData := protocol.ScenarioResultData{
		CaseID: scenariocontrol.ExecCancellationCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "start-cancellable-exec", Surface: "provider_http", Actor: "controller_a", Method: http.MethodPost, RouteTemplate: "/v1/sandboxes/{sandbox_id}/exec", LogicalRequestID: "start-cancellable-exec", WireAttempts: startAttempts, TransientOutcomes: cloneOutcomes(startTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusAccepted)}, MutationWriteObserved: true, ObservationIDs: append([]string(nil), startObservations...)},
			{InteractionID: "cancel-exec", Surface: "provider_http", Actor: "controller_a", Method: http.MethodPost, RouteTemplate: "/v1/sandboxes/{sandbox_id}/exec:cancel", LogicalRequestID: "cancel-exec", WireAttempts: cancelAttempts, TransientOutcomes: cloneOutcomes(cancelTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusAccepted)}, MutationWriteObserved: true, ObservationIDs: append([]string(nil), cancelObservations...)},
			{InteractionID: "read-cancel-operation", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-cancel-operation", WireAttempts: cancelReadAttempts, TransientOutcomes: cloneOutcomes(cancelReadTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, ObservationIDs: append([]string(nil), cancelReadObservations...)},
			{InteractionID: "read-cancelled-operation", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-cancelled-operation", WireAttempts: targetReadAttempts, TransientOutcomes: cloneOutcomes(targetReadTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, ObservationIDs: append([]string(nil), targetReadObservations...)},
			{InteractionID: "read-cancelled-result", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}/exec-result", LogicalRequestID: "read-cancelled-result", WireAttempts: resultAttempts, TransientOutcomes: cloneOutcomes(resultTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, ObservationIDs: append([]string(nil), resultObservations...)},
		},
		Assertions: []protocol.AssertionResult{
			{AssertionID: "acceptance-not-treated-as-final-cancellation", Result: "asserted"},
			{AssertionID: "caller-reconciled-cancel-operation-and-target-exec", Result: "asserted"},
		},
		ObservationIDs: []string{"exec-operation-accepted", "cancellation-intent-accepted", "cancel-operation-succeeded", "target-exec-operation-cancelled", "exec-result-cancelled"},
	}
	if protocol.ValidateScenarioResultData("initial", resultData) != nil || ctx.Err() != nil || executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	return resultData, nil
}

func cancellableExecRequest(ctx context.Context, state callerstate.State, maxExecSeconds int64, lease string, now time.Time) (provider.ExecRequest, error) {
	request, err := execRequest(ctx, state, maxExecSeconds, lease, now)
	if err != nil {
		return provider.ExecRequest{}, err
	}
	request.OperationID = "cancellable-exec-operation-" + state.Plan.RunID
	request.AttemptID = "cancellable-exec-attempt-" + state.Plan.RunID
	request.IdempotencyKey = "cancellable-exec-idempotency-" + state.Plan.RunID
	request.FencingToken = cancellableExecFencingToken
	request.RequestDigest = ""
	request.Command = []string{"sleep", "60"}
	request.Capture = nil
	return provider.BindExecRequest(request)
}

func cancelExecRequest(ctx context.Context, state callerstate.State, target provider.ReadDescriptor, lease string, now time.Time) (provider.CancelExecRequest, error) {
	deadline, err := boundedDeadline(ctx, now, lease, 60)
	if err != nil {
		return provider.CancelExecRequest{}, err
	}
	return provider.BindCancelExecRequest(provider.CancelExecRequest{
		OperationID: "cancel-exec-operation-" + state.Plan.RunID, AttemptID: "cancel-exec-attempt-" + state.Plan.RunID,
		FencingToken: cancelExecFencingToken, IdempotencyKey: "cancel-exec-idempotency-" + state.Plan.RunID,
		DeadlineAt: deadline.Format(time.RFC3339Nano), ExpectedGeneration: 1,
		TargetOperationID: target.OperationID, TargetAttemptID: target.AttemptID, Reason: "caller_requested",
	})
}

func submitCancelExec(ctx context.Context, client providerClient, sandboxID string, request provider.CancelExecRequest, admission provider.Admission) (provider.ProviderOperation, int, []protocol.Outcome, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= 2; attempt++ {
		operation, err := client.CancelExec(ctx, sandboxID, request, admission)
		if err == nil {
			return operation, attempt, transients, nil
		}
		var responseError *provider.HTTPError
		if attempt == 2 || !errors.As(err, &responseError) || responseError.StatusCode != http.StatusServiceUnavailable || !responseError.Document.Retryable || responseError.RetryAfterSeconds == nil || *responseError.RetryAfterSeconds <= 0 {
			return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
		}
		transients = append(transients, httpOutcome(responseError))
		if waitRetry(ctx, *responseError.RetryAfterSeconds) != nil {
			return provider.ProviderOperation{}, 0, nil, preserveContext(ctx, ErrInitialScenario)
		}
	}
	return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
}

func validCancelledExecResult(result provider.ExecResult, descriptor provider.ReadDescriptor, now time.Time) bool {
	started, startErr := time.Parse(time.RFC3339Nano, result.StartedAt)
	completed, completeErr := time.Parse(time.RFC3339Nano, result.CompletedAt)
	retained, retainErr := time.Parse(time.RFC3339Nano, result.RetainedUntil)
	return correlates(descriptor, result.SandboxID, result.OperationID, result.AttemptID, result.FencingToken) && result.Status == "cancelled" && startErr == nil && completeErr == nil && retainErr == nil && !completed.Before(started) && !completed.After(now) && retained.After(now) && retained.After(completed)
}
