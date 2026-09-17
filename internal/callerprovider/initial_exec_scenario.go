package callerprovider

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func (executor *InitialScenarioExecutor) executeExecResultUsage(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second || state.Stage != callerstate.StageLifecycleBound || state.Provider == nil || state.Lifecycle == nil || state.StoreRevision != 3 || !validAccess(executor.controllerA) || executor.sandbox.ObservedState != "ready" || executor.sandbox.Generation != 1 || executor.sandbox.ObservedGeneration != 1 {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	lease, err := time.Parse(time.RFC3339Nano, executor.sandbox.LeaseExpiresAt)
	if err != nil || !lease.After(startedAt) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	request, err := execRequest(ctx, state, executor.capabilities.Limits.MaxExecSeconds, executor.sandbox.LeaseExpiresAt, startedAt)
	if err != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor := plannedDescriptor(state, state.Plan.Exec, execFencingToken)
	admission, err := mutationAdmission(executor.controllerA, state, descriptor, "exec", request.RequestDigest, request.DeadlineAt, provider.ExecRequestContractID, "/v1/sandboxes/"+state.Plan.SandboxID+"/exec", executor.now())
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	operation, submitAttempts, submitTransients, err := submitExec(ctx, executor.controllerA.client, state.Plan.SandboxID, request, admission)
	if err != nil || !successfulMutationStatus(operation.Status) || !operationMatches(operation, descriptor, "exec") {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	operation, operationAttempts, operationTransients, err := pollExpectedOperation(ctx, executor.controllerA, state, descriptor, "exec", executor.now)
	if err != nil || operation.Status != "succeeded" {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}

	descriptor.Operation = "read_result"
	result, resultAttempts, resultTransients, err := readScenarioRetained(ctx, executor.controllerA, state, descriptor, executor.now, executor.controllerA.client.GetExecResult)
	if err != nil || !validScenarioExecResult(result, descriptor, executor.now()) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	resultRetainedUntil, _ := time.Parse(time.RFC3339Nano, result.RetainedUntil)

	descriptor.Operation = "read_usage_evidence"
	usage, usageAttempts, usageTransients, err := readScenarioRetained(ctx, executor.controllerA, state, descriptor, executor.now, executor.controllerA.client.GetUsageEvidence)
	if err != nil || !resultRetainedUntil.After(executor.now()) || !execUsageMatches(usage, descriptor, executor.now()) || executor.store.ValidateUnchanged() != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	resultDigest, err := jcs.Digest(result)
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	usageDigest, err := jcs.Digest(usage)
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}

	startObservations := []string{"exec-operation-accepted", "single-exec-dispatch"}
	operationObservations := []string{"operation-succeeded"}
	resultObservations := []string{"exec-completed-zero-exit", "opaque-output-reference"}
	usageObservations := []string{"usage-entry-present", "reconciliation-status-present"}
	resultData := protocol.ScenarioResultData{
		CaseID: scenariocontrol.ExecResultUsageCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{
				InteractionID: "start-output-exec", Surface: "provider_http", Actor: "controller_a", Method: http.MethodPost,
				RouteTemplate: "/v1/sandboxes/{sandbox_id}/exec", LogicalRequestID: "start-output-exec", WireAttempts: submitAttempts,
				TransientOutcomes: cloneOutcomes(submitTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusAccepted)},
				MutationWriteObserved: true, ObservationIDs: append([]string(nil), startObservations...),
			},
			{
				InteractionID: "read-output-exec-operation", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet,
				RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-output-exec-operation", WireAttempts: operationAttempts,
				TransientOutcomes: cloneOutcomes(operationTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)},
				MutationWriteObserved: false, ObservationIDs: append([]string(nil), operationObservations...),
			},
			{
				InteractionID: "read-exec-result", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet,
				RouteTemplate: "/v1/operations/{operation_id}/exec-result", LogicalRequestID: "read-exec-result", WireAttempts: resultAttempts,
				TransientOutcomes: cloneOutcomes(resultTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)},
				MutationWriteObserved: false, ObservationIDs: append([]string(nil), resultObservations...),
			},
			{
				InteractionID: "read-exec-usage", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet,
				RouteTemplate: "/v1/operations/{operation_id}/usage-evidence", LogicalRequestID: "read-exec-usage", WireAttempts: usageAttempts,
				TransientOutcomes: cloneOutcomes(usageTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)},
				MutationWriteObserved: false, ObservationIDs: append([]string(nil), usageObservations...),
			},
		},
		Assertions: []protocol.AssertionResult{
			{AssertionID: "caller-consumed-only-stable-result-fields", Result: "asserted"},
			{AssertionID: "command-output-not-in-evidence", Result: "asserted"},
		},
		ObservationIDs: append(append(append(append([]string(nil), startObservations...), operationObservations...), resultObservations...), usageObservations...),
	}
	if protocol.ValidateScenarioResultData("initial", resultData) != nil || ctx.Err() != nil || executor.store.BindExec(execFencingToken, resultDigest, usageDigest) != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	after := executor.store.Snapshot()
	if after.Stage != callerstate.StageExecBound || after.StoreRevision != 4 || after.Exec == nil || after.Exec.Operation.OperationID != state.Plan.Exec.OperationID || after.Exec.Operation.AttemptID != state.Plan.Exec.AttemptID || after.Exec.Operation.FencingToken != execFencingToken || after.Exec.ResultDigest != resultDigest || after.Exec.UsageEvidenceDigest != usageDigest {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	executor.exec, executor.execAdmission, executor.operation = request, admission, operation
	executor.execResult, executor.usage = result, usage
	return resultData, nil
}

func submitExec(ctx context.Context, client providerClient, sandboxID string, request provider.ExecRequest, admission provider.Admission) (provider.ProviderOperation, int, []protocol.Outcome, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= 2; attempt++ {
		operation, err := client.CreateExec(ctx, sandboxID, request, admission)
		if err == nil {
			return operation, attempt, transients, nil
		}
		var responseError *provider.HTTPError
		if attempt == 2 || !errors.As(err, &responseError) || (responseError.StatusCode != http.StatusTooManyRequests && responseError.StatusCode != http.StatusServiceUnavailable) || !responseError.Document.Retryable || responseError.RetryAfterSeconds == nil || *responseError.RetryAfterSeconds <= 0 {
			return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
		}
		transients = append(transients, httpOutcome(responseError))
		if err := waitRetry(ctx, *responseError.RetryAfterSeconds); err != nil {
			return provider.ProviderOperation{}, 0, nil, err
		}
	}
	return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
}

func readScenarioRetained[T any](ctx context.Context, value *access, state callerstate.State, descriptor provider.ReadDescriptor, now func() time.Time, read func(context.Context, provider.ReadDescriptor, provider.Admission) (T, error)) (T, int, []protocol.Outcome, error) {
	var zero T
	transients := []protocol.Outcome{}
	for attempts := 1; attempts <= maxPollAttempts; attempts++ {
		admission, err := readAdmission(ctx, value, state, descriptor, now())
		if err != nil {
			return zero, 0, nil, err
		}
		result, err := read(ctx, descriptor, admission)
		if err == nil {
			return result, attempts, transients, nil
		}
		if outcome, retryAfter, retry := retryableReadOutcome(err, attempts); retry {
			transients = append(transients, outcome)
			if err := waitRetry(ctx, retryAfter); err != nil {
				return zero, 0, nil, err
			}
			continue
		}
		return zero, 0, nil, ErrInitialScenario
	}
	return zero, 0, nil, ErrInitialScenario
}

func validScenarioExecResult(result provider.ExecResult, descriptor provider.ReadDescriptor, now time.Time) bool {
	started, startErr := time.Parse(time.RFC3339Nano, result.StartedAt)
	completed, completeErr := time.Parse(time.RFC3339Nano, result.CompletedAt)
	retained, retainErr := time.Parse(time.RFC3339Nano, result.RetainedUntil)
	return correlates(descriptor, result.SandboxID, result.OperationID, result.AttemptID, result.FencingToken) &&
		result.Status == "completed" && result.ExitCode != nil && *result.ExitCode == 0 && result.Error == nil && result.Signal == "" && result.StdoutReference != "" &&
		startErr == nil && completeErr == nil && retainErr == nil && !completed.Before(started) && !completed.After(now) && retained.After(now) && retained.After(completed)
}
