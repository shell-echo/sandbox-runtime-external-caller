package callerprovider

import (
	"context"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func (executor *InitialScenarioExecutor) executeReconstructionEvidence(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second ||
		state.Stage != callerstate.StageInitialComplete || state.StoreRevision != 6 || state.Provider == nil || state.Lifecycle == nil ||
		state.Exec == nil || state.Terminal == nil || state.Artifact == nil || !validAccess(executor.controllerA) || executor.reconstructionGateway == nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}

	resultDescriptor := provider.ReadDescriptor{
		Operation: "read_result", SandboxID: state.Plan.SandboxID,
		OperationID: state.Exec.Operation.OperationID, AttemptID: state.Exec.Operation.AttemptID,
		FencingToken: state.Exec.Operation.FencingToken,
	}
	result, resultAttempts, resultTransients, err := readScenarioRetained(ctx, executor.controllerA, state, resultDescriptor, executor.now, executor.controllerA.client.GetExecResult)
	if err != nil || !validScenarioExecResult(result, resultDescriptor, executor.now()) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	resultDigest, err := jcs.Digest(result)
	if err != nil || resultDigest != state.Exec.ResultDigest {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}

	usageDescriptor := resultDescriptor
	usageDescriptor.Operation = "read_usage_evidence"
	usage, usageAttempts, usageTransients, err := readScenarioRetained(ctx, executor.controllerA, state, usageDescriptor, executor.now, executor.controllerA.client.GetUsageEvidence)
	if err != nil || !execUsageMatches(usage, usageDescriptor, executor.now()) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	usageDigest, err := jcs.Digest(usage)
	if err != nil || usageDigest != state.Exec.UsageEvidenceDigest {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}

	artifactDescriptor := provider.ReadDescriptor{
		Operation: "read_artifact_staging_evidence", SandboxID: state.Plan.SandboxID,
		OperationID: state.Artifact.Operation.OperationID, AttemptID: state.Artifact.Operation.AttemptID,
		FencingToken: state.Artifact.Operation.FencingToken,
	}
	expectedArtifact := provider.ArtifactStagingRequest{
		ArtifactReference: "artifact-ref:caller/" + state.Plan.RunID, ExpectedDigest: artifactDigest,
		ExpectedMediaType: artifactMediaType, MaxBytes: artifactSizeBytes, RetentionSeconds: 3600,
	}
	artifact, artifactAttempts, artifactTransients, err := readScenarioRetained(ctx, executor.controllerA, state, artifactDescriptor, executor.now, executor.controllerA.client.GetArtifactStagingEvidence)
	if err != nil || !artifactEvidenceMatches(artifact, expectedArtifact, artifactDescriptor, executor.now()) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	artifactDigestValue, err := jcs.Digest(artifact)
	if err != nil || artifactDigestValue != state.Artifact.EvidenceDigest || executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}

	resultObservations := []string{"same-exec-result-completed"}
	usageObservations := []string{"same-usage-evidence-digest"}
	artifactObservations := []string{"same-artifact-evidence-digest"}
	resultData := protocol.ScenarioResultData{
		CaseID: scenariocontrol.ReconstructionEvidenceCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{InteractionID: "read-retained-exec-result", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}/exec-result", LogicalRequestID: "read-retained-exec-result", WireAttempts: resultAttempts, TransientOutcomes: cloneOutcomes(resultTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, MutationWriteObserved: false, ObservationIDs: append([]string(nil), resultObservations...)},
			{InteractionID: "read-retained-usage", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}/usage-evidence", LogicalRequestID: "read-retained-usage", WireAttempts: usageAttempts, TransientOutcomes: cloneOutcomes(usageTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, MutationWriteObserved: false, ObservationIDs: append([]string(nil), usageObservations...)},
			{InteractionID: "read-retained-artifact-evidence", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet, RouteTemplate: "/v1/operations/{operation_id}/artifact-staging-evidence", LogicalRequestID: "read-retained-artifact-evidence", WireAttempts: artifactAttempts, TransientOutcomes: cloneOutcomes(artifactTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}, MutationWriteObserved: false, ObservationIDs: append([]string(nil), artifactObservations...)},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "retained-evidence-correlations-loaded-by-caller", Result: "asserted"}},
		ObservationIDs: append(append(append([]string(nil), resultObservations...), usageObservations...), artifactObservations...),
	}
	if protocol.ValidateScenarioResultData("reconstruction", resultData) != nil || ctx.Err() != nil ||
		!validScenarioExecResult(result, resultDescriptor, executor.now()) ||
		!execUsageMatches(usage, usageDescriptor, executor.now()) || !artifactEvidenceMatches(artifact, expectedArtifact, artifactDescriptor, executor.now()) ||
		!reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	return resultData, nil
}
