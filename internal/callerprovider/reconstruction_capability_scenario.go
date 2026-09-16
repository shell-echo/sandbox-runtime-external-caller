package callerprovider

import (
	"context"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

const reconstructionGatewayLifetime = 5 * time.Minute

func (executor *InitialScenarioExecutor) executeReconstructionCapability(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second ||
		state.Stage != callerstate.StageInitialComplete || state.StoreRevision != 6 || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.Terminal == nil || state.Artifact == nil ||
		executor.bundle == nil || executor.gatewayEndpoint == "" || executor.startGateway == nil || executor.buildProviderAccess == nil || executor.reconstructionGateway != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	controllerA, err := executor.buildProviderAccess(executor.bundle, executor.origin, "controller_a")
	if err != nil || !validAccess(controllerA) {
		closeAccess(controllerA)
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	gatewayContext, gatewayCancel := context.WithDeadline(context.Background(), startedAt.Add(reconstructionGatewayLifetime))
	stopStartupCancellation := context.AfterFunc(ctx, gatewayCancel)
	service, err := executor.startGateway(gatewayContext, "reconstruction", executor.gatewayEndpoint, executor.bundle)
	stopStartupCancellation()
	if err != nil || service == nil {
		gatewayCancel()
		closeAccess(controllerA)
		stopScenarioGateway(service)
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	keepService := false
	defer func() {
		if !keepService {
			stopScenarioGateway(service)
			gatewayCancel()
			closeAccess(controllerA)
		}
	}()
	if service.InstallPolicy(ctx, state.Plan.TenantAID, state.Plan.TenantBID) != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	discovery, err := discoverAdmittedCapabilities(ctx, controllerA.client)
	if err != nil || validateLockedCapabilitySnapshot(discovery.document) != nil || discovery.document.ProviderRevisionID != state.Provider.ProviderRevisionID || rawDigest(discovery.raw) != state.Provider.CapabilitySnapshotHash {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrCapabilityContinuity)
	}
	if executor.store.ValidateUnchanged() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	observations := []string{"byte-identical-capability-snapshot", "new-provider-process", "new-caller-process", "new-adapter-process", "new-gateway-process"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.ReconstructionCapabilityCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "reconstructed-capabilities", Surface: "provider_http", Actor: "controller_a", Method: "GET",
			RouteTemplate: "/v1/capabilities", LogicalRequestID: "reconstructed-capabilities", WireAttempts: discovery.attempts,
			TransientOutcomes: cloneOutcomes(discovery.transients), FinalOutcome: discovery.final, MutationWriteObserved: false,
			ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions: []protocol.AssertionResult{
			{AssertionID: "caller-loaded-own-durable-correlation-state", Result: "asserted"},
			{AssertionID: "harness-did-not-reinject-forbidden-bindings", Result: "asserted"},
		},
		ObservationIDs: append([]string(nil), observations...),
	}
	if protocol.ValidateScenarioResultData("reconstruction", result) != nil || ctx.Err() != nil || !reflect.DeepEqual(executor.store.Snapshot(), state) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	executor.controllerA = controllerA
	executor.reconstructionGateway = service
	executor.reconstructionGatewayCancel = gatewayCancel
	keepService = true
	return result, nil
}
