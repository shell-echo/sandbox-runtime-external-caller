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

func (executor *InitialScenarioExecutor) executeCrossTenantArtifactRejection(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second ||
		state.Stage != callerstate.StageInitialComplete || state.Provider == nil || state.Artifact == nil || state.StoreRevision != 6 ||
		!validAccess(executor.controllerA) || executor.artifactRequest.RequestDigest == "" || executor.artifactRequest.OperationID != state.Plan.Artifact.OperationID || executor.artifactRequest.AttemptID != state.Plan.Artifact.AttemptID || executor.artifactRequest.FencingToken != artifactFencingToken ||
		!operationMatches(executor.artifactOperation, plannedDescriptor(state, state.Plan.Artifact, artifactFencingToken), "artifact_stage") || executor.artifactOperation.Status != "succeeded" {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	if executor.controllerB == nil {
		factory := executor.buildProviderAccess
		if factory == nil {
			factory = buildAccess
		}
		controllerB, err := factory(executor.bundle, executor.origin, "controller_b")
		if err != nil || !validAccess(controllerB) || controllerB.controllerSubject == executor.controllerA.controllerSubject {
			closeAccess(controllerB)
			return protocol.ScenarioResultData{}, ErrInitialScenario
		}
		executor.controllerB = controllerB
	}

	descriptor := plannedDescriptor(state, state.Plan.Artifact, artifactFencingToken)
	stageAdmission, err := mutationAdmissionForTenant(executor.controllerB, state, descriptor, "stage_artifact", executor.artifactRequest.RequestDigest, executor.artifactRequest.DeadlineAt, provider.ArtifactStagingRequestContractID, "/v1/sandboxes/"+state.Plan.SandboxID+"/artifacts:stage", state.Plan.TenantBID, state.Plan.WorkOrderBID, executor.now())
	if err != nil || !crossTenantAdmission(stageAdmission, state, executor.controllerB.controllerSubject) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	stageAttempts, stageTransients, stageRejection, err := submitCrossTenantArtifact(ctx, executor.controllerB.client, state.Plan.SandboxID, executor.artifactRequest, stageAdmission)
	if err != nil || !closedRejection(stageRejection, http.StatusForbidden, "SANDBOX_FORBIDDEN") {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}

	readAttempts, readTransients, readRejection, err := readCrossTenantArtifactOperation(ctx, executor.controllerB, state, descriptor, executor.now)
	if err != nil || !closedRejection(readRejection, http.StatusNotFound, "SANDBOX_NOT_FOUND") || !reflect.DeepEqual(executor.store.Snapshot(), state) || executor.store.ValidateUnchanged() != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}

	stageObservations := []string{"controller-b-tenant-b-request", "rejected-before-artifact-dispatch", "no-backend-disclosure"}
	readObservations := []string{"no-cross-tenant-operation-visible"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.CrossTenantArtifactCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "cross-tenant-stage-artifact", Surface: "provider_http", Actor: "controller_b", Method: http.MethodPost, RouteTemplate: "/v1/sandboxes/{sandbox_id}/artifacts:stage", LogicalRequestID: "cross-tenant-stage-artifact", WireAttempts: stageAttempts, TransientOutcomes: cloneOutcomes(stageTransients), FinalOutcome: httpOutcome(stageRejection), MutationWriteObserved: true, ObservationIDs: append([]string(nil), stageObservations...)},
			{InteractionID: "cross-tenant-read-artifact-operation", Surface: "provider_http", Actor: "controller_b", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "cross-tenant-read-artifact-operation", WireAttempts: readAttempts, TransientOutcomes: cloneOutcomes(readTransients), FinalOutcome: httpOutcome(readRejection), MutationWriteObserved: false, ObservationIDs: append([]string(nil), readObservations...)},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "distinct-tenant-negative-case", Result: "asserted"}},
		ObservationIDs: append(append([]string(nil), stageObservations...), readObservations...),
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil || ctx.Err() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	return result, nil
}

func mutationAdmissionForTenant(value *access, state callerstate.State, descriptor provider.ReadDescriptor, operation, digest, deadline, contractID, path, tenantID, workOrderID string, now time.Time) (provider.Admission, error) {
	return buildAdmissionForTenant(value, state, provider.AdmissionBinding{
		Operation: operation, SandboxID: descriptor.SandboxID, OperationID: descriptor.OperationID,
		AttemptID: descriptor.AttemptID, FencingToken: descriptor.FencingToken, DeadlineAt: deadline,
		RequestContractID: contractID, RequestDigestProfile: provider.MutationDigestProfile, RequestDigest: digest,
		HTTPTarget: provider.AdmissionTarget{Method: http.MethodPost, Path: path, NormalizedQuery: []provider.QueryParameter{}},
	}, tenantID, workOrderID, now)
}

func crossTenantAdmission(admission provider.Admission, state callerstate.State, subject string) bool {
	return subject != "" && admission.Context.ControllerSubject == subject && admission.Claims.Subject == subject &&
		admission.Context.TenantID == state.Plan.TenantBID && admission.Context.WorkOrderID == state.Plan.WorkOrderBID &&
		admission.Claims.TenantID == state.Plan.TenantBID && admission.Claims.WorkOrderID == state.Plan.WorkOrderBID
}

func submitCrossTenantArtifact(ctx context.Context, client providerClient, sandboxID string, request provider.ArtifactStagingRequest, admission provider.Admission) (int, []protocol.Outcome, *provider.HTTPError, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= 2; attempt++ {
		_, err := client.StageArtifact(ctx, sandboxID, request, admission)
		var responseError *provider.HTTPError
		if !errors.As(err, &responseError) {
			return 0, nil, nil, ErrInitialScenario
		}
		if responseError.StatusCode == http.StatusForbidden {
			return attempt, transients, responseError, nil
		}
		if attempt == 2 || responseError.StatusCode != http.StatusServiceUnavailable || !responseError.Document.Retryable || responseError.RetryAfterSeconds == nil || *responseError.RetryAfterSeconds <= 0 {
			return 0, nil, nil, ErrInitialScenario
		}
		transients = append(transients, httpOutcome(responseError))
		if err := waitRetry(ctx, *responseError.RetryAfterSeconds); err != nil {
			return 0, nil, nil, err
		}
	}
	return 0, nil, nil, ErrInitialScenario
}

func readCrossTenantArtifactOperation(ctx context.Context, value *access, state callerstate.State, descriptor provider.ReadDescriptor, now func() time.Time) (int, []protocol.Outcome, *provider.HTTPError, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= maxPollAttempts; attempt++ {
		admission, err := readAdmissionForTenant(ctx, value, state, descriptor, state.Plan.TenantBID, state.Plan.WorkOrderBID, now())
		if err != nil || !crossTenantAdmission(admission, state, value.controllerSubject) {
			return 0, nil, nil, ErrInitialScenario
		}
		_, err = value.client.GetOperation(ctx, descriptor, admission)
		var responseError *provider.HTTPError
		if !errors.As(err, &responseError) {
			return 0, nil, nil, ErrInitialScenario
		}
		if responseError.StatusCode == http.StatusNotFound {
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

func closedRejection(response *provider.HTTPError, status int, code string) bool {
	return response != nil && response.StatusCode == status && response.Document.Code == code && !response.Document.Retryable && response.RetryAfterSeconds == nil
}
