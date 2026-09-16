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

func (executor *InitialScenarioExecutor) executeMTLSCallerBindingRejection(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second ||
		state.Stage != callerstate.StageInitialComplete || state.Provider == nil || state.Lifecycle == nil || state.Artifact == nil || state.StoreRevision != 6 ||
		!validAccess(executor.controllerA) || !validAccess(executor.controllerB) || executor.controllerA.controllerSubject == executor.controllerB.controllerSubject {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor := plannedDescriptor(state, state.Plan.Create, createFencingToken)
	descriptor.Operation = "read_sandbox"
	attempts, transients, rejection, err := readSandboxWithWrongMTLSCaller(ctx, executor.controllerB.client, executor.controllerA, state, descriptor, executor.now)
	if err != nil || !closedRejection(rejection, http.StatusForbidden, "SANDBOX_FORBIDDEN") || !reflect.DeepEqual(executor.store.Snapshot(), state) || executor.store.ValidateUnchanged() != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	observations := []string{"admitted-controller-b-certificate", "controller-a-signed-subject", "rejected-before-state-read"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.MTLSCallerBindingCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "wrong-mtls-caller-read-sandbox", Surface: "provider_http", Actor: "controller_b", Method: http.MethodGet,
			RouteTemplate: "/v1/sandboxes/{sandbox_id}", LogicalRequestID: "wrong-mtls-caller-read-sandbox", WireAttempts: attempts,
			TransientOutcomes: cloneOutcomes(transients), FinalOutcome: httpOutcome(rejection), MutationWriteObserved: false,
			ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions:     []protocol.AssertionResult{{AssertionID: "mtls-and-jws-caller-must-match", Result: "asserted"}},
		ObservationIDs: append([]string(nil), observations...),
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil || ctx.Err() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	return result, nil
}

func readSandboxWithWrongMTLSCaller(ctx context.Context, client providerClient, signer *access, state callerstate.State, descriptor provider.ReadDescriptor, now func() time.Time) (int, []protocol.Outcome, *provider.HTTPError, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= maxPollAttempts; attempt++ {
		admission, err := readAdmission(ctx, signer, state, descriptor, now())
		if err != nil || admission.Context.ControllerSubject != signer.controllerSubject || admission.Claims.Subject != signer.controllerSubject || admission.Context.TenantID != state.Plan.TenantAID || admission.Context.WorkOrderID != state.Plan.WorkOrderAID {
			return 0, nil, nil, ErrInitialScenario
		}
		_, err = client.GetSandboxStatus(ctx, descriptor, admission)
		var responseError *provider.HTTPError
		if !errors.As(err, &responseError) {
			return 0, nil, nil, ErrInitialScenario
		}
		if responseError.StatusCode == http.StatusForbidden {
			return attempt, transients, responseError, nil
		}
		if responseError.StatusCode != http.StatusServiceUnavailable || !responseError.Document.Retryable || responseError.RetryAfterSeconds == nil || *responseError.RetryAfterSeconds <= 0 || attempt == maxPollAttempts {
			return 0, nil, nil, ErrInitialScenario
		}
		transients = append(transients, httpOutcome(responseError))
		if err := waitRetry(ctx, *responseError.RetryAfterSeconds); err != nil {
			return 0, nil, nil, err
		}
	}
	return 0, nil, nil, ErrInitialScenario
}
