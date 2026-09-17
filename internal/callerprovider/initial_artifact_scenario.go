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

const (
	artifactSourcePath = "/outputs/external-caller.txt"
	artifactDigest     = "sha256:1dce5c90668d52fd4ff471e7bc3faab6c6eeb4dd35212ca56c3f6450de230dbe"
	artifactMediaType  = "text/plain"
	artifactSizeBytes  = int64(24)
)

func (executor *InitialScenarioExecutor) executeArtifactStaging(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second || state.Stage != callerstate.StageTerminalBound || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.Terminal == nil || state.StoreRevision != 5 || !validAccess(executor.controllerA) || executor.sandbox.ObservedState != "ready" || executor.sandbox.Generation != 1 || executor.sandbox.ObservedGeneration != 1 {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	request, err := artifactRequest(ctx, state, executor.sandbox.LeaseExpiresAt, startedAt)
	if err != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor := plannedDescriptor(state, state.Plan.Artifact, artifactFencingToken)
	admission, err := mutationAdmission(executor.controllerA, state, descriptor, "stage_artifact", request.RequestDigest, request.DeadlineAt, provider.ArtifactStagingRequestContractID, "/v1/sandboxes/"+state.Plan.SandboxID+"/artifacts:stage", executor.now())
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	operation, stageAttempts, stageTransients, err := submitArtifact(ctx, executor.controllerA.client, state.Plan.SandboxID, request, admission)
	if err != nil || !operationMatches(operation, descriptor, "artifact_stage") || !successfulMutationStatus(operation.Status) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	operation, operationAttempts, operationTransients, err := pollExpectedOperation(ctx, executor.controllerA, state, descriptor, "artifact_stage", executor.now)
	if err != nil || operation.Status != "succeeded" {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor.Operation = "read_artifact_staging_evidence"
	evidence, evidenceAttempts, evidenceTransients, err := readScenarioRetained(ctx, executor.controllerA, state, descriptor, executor.now, executor.controllerA.client.GetArtifactStagingEvidence)
	if err != nil || !artifactEvidenceMatches(evidence, request, descriptor, executor.now()) || executor.store.ValidateUnchanged() != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	evidenceDigest, err := jcs.Digest(evidence)
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}

	stageObservations := []string{"artifact-operation-accepted"}
	operationObservations := []string{"operation-succeeded"}
	evidenceObservations := []string{"artifact-status-staged", "content-digest-and-size-match", "opaque-staging-reference"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.ArtifactStagingCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "stage-artifact", Surface: "provider_http", Actor: "controller_a", Method: http.MethodPost, RouteTemplate: "/v1/sandboxes/{sandbox_id}/artifacts:stage", LogicalRequestID: "stage-artifact", WireAttempts: stageAttempts, TransientOutcomes: cloneOutcomes(stageTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusAccepted)}, MutationWriteObserved: true, ObservationIDs: append([]string(nil), stageObservations...)},
			{InteractionID: "read-artifact-operation", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-artifact-operation", WireAttempts: operationAttempts, TransientOutcomes: cloneOutcomes(operationTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, MutationWriteObserved: false, ObservationIDs: append([]string(nil), operationObservations...)},
			{InteractionID: "read-artifact-evidence", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}/artifact-staging-evidence", LogicalRequestID: "read-artifact-evidence", WireAttempts: evidenceAttempts, TransientOutcomes: cloneOutcomes(evidenceTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, MutationWriteObserved: false, ObservationIDs: append([]string(nil), evidenceObservations...)},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "caller-kept-aggregate-artifact-truth", Result: "asserted"}},
		ObservationIDs: append(append(append([]string(nil), stageObservations...), operationObservations...), evidenceObservations...),
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil || ctx.Err() != nil || executor.store.BindArtifact(artifactFencingToken, evidenceDigest) != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	after := executor.store.Snapshot()
	if after.Stage != callerstate.StageInitialComplete || after.StoreRevision != 6 || after.Artifact == nil || after.Artifact.Operation.OperationID != state.Plan.Artifact.OperationID || after.Artifact.Operation.AttemptID != state.Plan.Artifact.AttemptID || after.Artifact.Operation.FencingToken != artifactFencingToken || after.Artifact.EvidenceDigest != evidenceDigest {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	executor.artifactRequest, executor.artifactAdmission, executor.artifactOperation, executor.artifactEvidence = request, admission, operation, evidence
	return result, nil
}

func artifactRequest(ctx context.Context, state callerstate.State, lease string, now time.Time) (provider.ArtifactStagingRequest, error) {
	deadline, err := boundedDeadline(ctx, now, lease, 60)
	if err != nil {
		return provider.ArtifactStagingRequest{}, err
	}
	// Provider artifact retention must end no later than the mutation deadline.
	// Leave a bounded transport/validation margin instead of deriving an expiry
	// that is already invalid by the time the Provider evaluates it.
	retentionSeconds := int64(deadline.Sub(now)/time.Second) - 1
	if retentionSeconds < 1 {
		return provider.ArtifactStagingRequest{}, ErrInitialScenario
	}
	return provider.BindArtifactStagingRequest(provider.ArtifactStagingRequest{
		OperationID: state.Plan.Artifact.OperationID, AttemptID: state.Plan.Artifact.AttemptID, FencingToken: artifactFencingToken,
		IdempotencyKey: state.Plan.Artifact.IdempotencyKey, DeadlineAt: deadline.Format(time.RFC3339Nano), ExpectedGeneration: 1,
		ArtifactReference: "artifact-ref:caller/" + state.Plan.RunID, SourcePath: artifactSourcePath, ExpectedDigest: artifactDigest,
		ExpectedMediaType: artifactMediaType, MaxBytes: artifactSizeBytes, RetentionSeconds: retentionSeconds,
	})
}

func submitArtifact(ctx context.Context, client providerClient, sandboxID string, request provider.ArtifactStagingRequest, admission provider.Admission) (provider.ProviderOperation, int, []protocol.Outcome, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= 2; attempt++ {
		operation, err := client.StageArtifact(ctx, sandboxID, request, admission)
		if err == nil {
			return operation, attempt, transients, nil
		}
		var responseError *provider.HTTPError
		if attempt == 2 || !errors.As(err, &responseError) || responseError.StatusCode != http.StatusServiceUnavailable || !responseError.Document.Retryable || responseError.RetryAfterSeconds == nil || *responseError.RetryAfterSeconds <= 0 {
			return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
		}
		transients = append(transients, httpOutcome(responseError))
		if err := waitRetry(ctx, *responseError.RetryAfterSeconds); err != nil {
			return provider.ProviderOperation{}, 0, nil, err
		}
	}
	return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
}

func artifactEvidenceMatches(evidence provider.ArtifactStagingEvidence, request provider.ArtifactStagingRequest, descriptor provider.ReadDescriptor, now time.Time) bool {
	observed, observedErr := time.Parse(time.RFC3339Nano, evidence.ObservedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, evidence.ExpiresAt)
	if !correlates(descriptor, evidence.SandboxID, evidence.OperationID, evidence.AttemptID, evidence.FencingToken) || evidence.ArtifactReference != request.ArtifactReference || evidence.Status != "staged" || evidence.ContentDigest != request.ExpectedDigest || evidence.MediaType != request.ExpectedMediaType || evidence.SizeBytes != request.MaxBytes || evidence.StagingReference == "" || observedErr != nil || expiryErr != nil || observed.After(now) || !expires.After(now) || !expires.After(observed) || expires.After(observed.Add(time.Duration(request.RetentionSeconds)*time.Second)) {
		return false
	}
	for _, check := range []provider.ArtifactCheck{evidence.TenantBindingCheck, evidence.ActiveContentCheck, evidence.MalwareCheck} {
		checked, err := time.Parse(time.RFC3339Nano, check.CheckedAt)
		if err != nil || check.Status != "passed" || checked.After(observed) {
			return false
		}
	}
	return true
}
