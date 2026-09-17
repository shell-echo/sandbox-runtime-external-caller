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

func (executor *InitialScenarioExecutor) executeStaleFencing(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second || state.Stage != callerstate.StageExecBound || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.StoreRevision != 4 || !validAccess(executor.controllerA) || executor.exec.RequestDigest == "" || executor.exec.FencingToken != execFencingToken {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	request, err := staleExecRequest(ctx, state, executor.capabilities.Limits.MaxExecSeconds, executor.sandbox.LeaseExpiresAt, startedAt)
	if err != nil || request.FencingToken >= state.Exec.Operation.FencingToken {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor := provider.ReadDescriptor{
		Operation: "exec", SandboxID: state.Plan.SandboxID, OperationID: request.OperationID,
		AttemptID: request.AttemptID, FencingToken: request.FencingToken,
	}
	admission, err := mutationAdmission(executor.controllerA, state, descriptor, "exec", request.RequestDigest, request.DeadlineAt, provider.ExecRequestContractID, "/v1/sandboxes/"+state.Plan.SandboxID+"/exec", executor.now())
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	attempts, transients, rejection, err := submitRejectedExec(ctx, executor.controllerA.client, state.Plan.SandboxID, request, admission)
	if err != nil || rejection.StatusCode != http.StatusConflict || (rejection.Document.Code != "SANDBOX_CONFLICT" && rejection.Document.Code != "SANDBOX_STALE_FENCING_TOKEN") || rejection.Document.Retryable || rejection.RetryAfterSeconds != nil || executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	observations := []string{"lower-fencing-token", "rejected-before-dispatch", "closed-standard-error"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.StaleFencingCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "start-stale-fence-exec", Surface: "provider_http", Actor: "controller_a", Method: http.MethodPost,
			RouteTemplate: "/v1/sandboxes/{sandbox_id}/exec", LogicalRequestID: "start-stale-fence-exec", WireAttempts: attempts,
			TransientOutcomes: cloneOutcomes(transients), FinalOutcome: httpOutcome(rejection), MutationWriteObserved: true,
			ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions:     []protocol.AssertionResult{{AssertionID: "caller-did-not-retry-nonretryable-conflict", Result: "asserted"}},
		ObservationIDs: append([]string(nil), observations...),
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil || ctx.Err() != nil || executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	return result, nil
}

func staleExecRequest(ctx context.Context, state callerstate.State, maxExecSeconds int64, lease string, now time.Time) (provider.ExecRequest, error) {
	request, err := execRequest(ctx, state, maxExecSeconds, lease, now)
	if err != nil {
		return provider.ExecRequest{}, err
	}
	// Fencing is operation-scoped by the Provider Contract. Reuse the prior
	// logical operation ID with a fresh attempt/JTI so the lower token is
	// compared against that operation's established high-water mark.
	request.OperationID = state.Plan.Exec.OperationID
	request.AttemptID = "stale-exec-attempt-" + state.Plan.RunID
	request.IdempotencyKey = "stale-exec-idempotency-" + state.Plan.RunID
	request.FencingToken = execFencingToken - 1
	request.RequestDigest = ""
	request.Command = []string{"printf", "stale-fence-must-not-dispatch"}
	return provider.BindExecRequest(request)
}

func submitRejectedExec(ctx context.Context, client providerClient, sandboxID string, request provider.ExecRequest, admission provider.Admission) (int, []protocol.Outcome, *provider.HTTPError, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= 2; attempt++ {
		_, err := client.CreateExec(ctx, sandboxID, request, admission)
		var responseError *provider.HTTPError
		if err == nil || !errors.As(err, &responseError) {
			return 0, nil, nil, ErrInitialScenario
		}
		if responseError.StatusCode == http.StatusConflict {
			return attempt, transients, responseError, nil
		}
		if attempt == 2 || (responseError.StatusCode != http.StatusTooManyRequests && responseError.StatusCode != http.StatusServiceUnavailable) || !responseError.Document.Retryable || responseError.RetryAfterSeconds == nil || *responseError.RetryAfterSeconds <= 0 {
			return 0, nil, nil, ErrInitialScenario
		}
		transients = append(transients, httpOutcome(responseError))
		if err := waitRetry(ctx, *responseError.RetryAfterSeconds); err != nil {
			return 0, nil, nil, err
		}
	}
	return 0, nil, nil, ErrInitialScenario
}
