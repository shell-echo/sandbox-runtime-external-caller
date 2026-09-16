package callerprovider

import (
	"context"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func (executor *InitialScenarioExecutor) executeReconstructionLifecycle(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second ||
		state.Stage != callerstate.StageInitialComplete || state.StoreRevision != 6 || state.Provider == nil || state.Lifecycle == nil ||
		state.Exec == nil || state.Terminal == nil || state.Artifact == nil || !validAccess(executor.controllerA) || executor.reconstructionGateway == nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor := provider.ReadDescriptor{
		Operation: "read_operation", SandboxID: state.Plan.SandboxID,
		OperationID: state.Lifecycle.OperationID, AttemptID: state.Lifecycle.AttemptID,
		FencingToken: state.Lifecycle.FencingToken,
	}
	operation, operationAttempts, operationTransients, err := pollExpectedOperation(ctx, executor.controllerA, state, descriptor, "create", executor.now)
	if err != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	sandbox, statusAttempts, statusTransients, err := pollReadySandbox(ctx, executor.controllerA, state, descriptor, executor.now)
	if err != nil || executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	if operation.OperationID != state.Lifecycle.OperationID || operation.AttemptID != state.Lifecycle.AttemptID || operation.FencingToken != state.Lifecycle.FencingToken ||
		sandbox.SandboxID != state.Plan.SandboxID || sandbox.TenantID != state.Plan.TenantAID || sandbox.WorkOrderID != state.Plan.WorkOrderAID {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}

	operationObservations := []string{"same-create-operation-correlation", "operation-succeeded", "caller-correlation-load-without-harness-reinjection-observed"}
	sandboxObservations := []string{"same-sandbox-correlation", "sandbox-ready", "generation-one"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.ReconstructionLifecycleCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{
				InteractionID: "read-reconstructed-create-operation", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet,
				RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-reconstructed-create-operation", WireAttempts: operationAttempts,
				TransientOutcomes: cloneOutcomes(operationTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)},
				MutationWriteObserved: false, ObservationIDs: append([]string(nil), operationObservations...),
			},
			{
				InteractionID: "read-reconstructed-sandbox", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet,
				RouteTemplate: "/v1/sandboxes/{sandbox_id}", LogicalRequestID: "read-reconstructed-sandbox", WireAttempts: statusAttempts,
				TransientOutcomes: cloneOutcomes(statusTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)},
				MutationWriteObserved: false, ObservationIDs: append([]string(nil), sandboxObservations...),
			},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "correlations-originated-in-caller-durable-store", Result: "asserted"}},
		ObservationIDs: append(append([]string(nil), operationObservations...), sandboxObservations...),
	}
	if protocol.ValidateScenarioResultData("reconstruction", result) != nil || ctx.Err() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	return result, nil
}
