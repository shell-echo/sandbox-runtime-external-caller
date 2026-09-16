// Package callerapp implements the external-caller process boundary. It executes
// the authorized initial scenarios and the current reconstruction prefix.
package callerapp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callercontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerphase"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

const (
	ExitSuccess  = 0
	ExitUsage    = 64
	ExitData     = 65
	ExitSoftware = 70
	ExitIO       = 74
)

func Run(arguments []string, stdin io.Reader, stdout io.Writer) int {
	return RunWithScenarios(context.Background(), arguments, stdin, stdout, nil)
}

type ScenarioExecutor interface {
	Execute(context.Context, string) (protocol.ScenarioResultData, error)
	Close() error
}

type NewScenarioExecutor func(string, string, *credentials.Bundle, *callerstate.Store) (ScenarioExecutor, error)

// RunWithScenarios executes the phase-specific scenarios authorized in order by
// private control. It keeps one credential/state owner alive between results.
func RunWithScenarios(parent context.Context, arguments []string, stdin io.Reader, stdout io.Writer, newExecutor NewScenarioExecutor) int {
	if len(arguments) != 0 {
		return ExitUsage
	}
	if parent == nil {
		return ExitSoftware
	}
	input := bufio.NewReader(stdin)
	request, err := scenariocontrol.DecodeRequestRecord(input)
	if err != nil {
		return ExitData
	}
	bundle, err := credentials.NewReader(credentials.Requirements()).Read(request.CredentialChannelDescriptors)
	if err != nil {
		return ExitData
	}
	defer bundle.Destroy()
	if err := credentials.ValidateGatewayIdentityBundle(bundle, request.GatewayProbeEndpoint); err != nil {
		return ExitData
	}
	if newExecutor == nil {
		return ExitSoftware
	}
	var store *callerstate.Store
	switch request.Phase {
	case "initial":
		store, err = callerstate.CreateInitial(request.CallerStateRoot)
	case "reconstruction":
		store, err = callerstate.OpenReconstruction(request.CallerStateRoot)
	default:
		err = callerstate.ErrInvalidState
	}
	if err != nil {
		return ExitSoftware
	}
	defer store.Close()
	executor, err := newExecutor(request.ProviderOrigin, request.GatewayProbeEndpoint, bundle, store)
	if err != nil || executor == nil {
		return ExitSoftware
	}
	defer executor.Close()
	before := store.Snapshot()
	if code := runScenario(parent, request, request.CaseID, request.Deadline, executor, store, before, stdout); code != ExitSuccess {
		return code
	}
	for _, expectedCaseID := range privateContinuationCases(request.Phase) {
		command, err := scenariocontrol.DecodeCommandRecord(input)
		if err != nil || command.InvocationID != request.InvocationID || command.Phase != request.Phase || command.CaseID != expectedCaseID {
			return ExitData
		}
		before = store.Snapshot()
		if code := runScenario(parent, request, command.CaseID, command.Deadline, executor, store, before, stdout); code != ExitSuccess {
			return code
		}
	}
	if _, err := input.ReadByte(); !errors.Is(err, io.EOF) {
		return ExitData
	}
	if err := executor.Close(); err != nil || store.ValidateUnchanged() != nil {
		return ExitSoftware
	}
	bundle.Destroy()
	return ExitSuccess
}

func runScenario(parent context.Context, request scenariocontrol.Request, caseID string, deadline time.Time, executor ScenarioExecutor, store *callerstate.Store, before callerstate.State, stdout io.Writer) int {
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	data, err := executor.Execute(ctx, caseID)
	if err != nil || data.CaseID != caseID || data.Disposition != "completed" || protocol.ValidateScenarioResultData(request.Phase, data) != nil {
		return ExitSoftware
	}
	after := store.Snapshot()
	stateOK := after.Provider != nil && reflect.DeepEqual(after.Plan, before.Plan)
	switch caseID {
	case scenariocontrol.ReconstructionCapabilityCaseID, scenariocontrol.ReconstructionLifecycleCaseID, scenariocontrol.ReconstructionEvidenceCaseID, scenariocontrol.ReconstructionHandoffCaseID, scenariocontrol.ReconstructionReconnectCaseID:
		stateOK = request.Phase == "reconstruction" && before.Stage == callerstate.StageInitialComplete && before.StoreRevision == 6 && reflect.DeepEqual(after, before)
	case scenariocontrol.CapabilityCaseID:
		stateOK = stateOK && before.Stage == callerstate.StagePlanned && after.Stage == callerstate.StageCapabilitiesBound && after.StoreRevision == before.StoreRevision+1
	case scenariocontrol.LifecycleCaseID, scenariocontrol.ReplayCaseID:
		stateOK = stateOK && before.Stage == callerstate.StageCapabilitiesBound && reflect.DeepEqual(after, before)
	case scenariocontrol.LifecycleCompletionCaseID:
		stateOK = stateOK && before.Stage == callerstate.StageCapabilitiesBound && after.Stage == callerstate.StageLifecycleBound && after.StoreRevision == before.StoreRevision+1 && after.Lifecycle != nil
	case scenariocontrol.ExecResultUsageCaseID:
		stateOK = stateOK && before.Stage == callerstate.StageLifecycleBound && after.Stage == callerstate.StageExecBound && after.StoreRevision == before.StoreRevision+1 && after.Exec != nil
	case scenariocontrol.StaleFencingCaseID, scenariocontrol.ExecCancellationCaseID:
		stateOK = stateOK && before.Stage == callerstate.StageExecBound && reflect.DeepEqual(after, before)
	case scenariocontrol.TerminalSessionCaseID:
		stateOK = stateOK && before.Stage == callerstate.StageExecBound && after.Stage == callerstate.StageTerminalBound && after.StoreRevision == before.StoreRevision+1 && after.Terminal != nil
	case scenariocontrol.GatewayRoundTripCaseID, scenariocontrol.GatewayAuthorityRejectionCaseID, scenariocontrol.GatewayGrantExpiryCaseID, scenariocontrol.GatewayRevocationCaseID:
		stateOK = stateOK && before.Stage == callerstate.StageTerminalBound && reflect.DeepEqual(after, before)
	case scenariocontrol.ArtifactStagingCaseID:
		stateOK = stateOK && before.Stage == callerstate.StageTerminalBound && after.Stage == callerstate.StageInitialComplete && after.StoreRevision == before.StoreRevision+1 && after.Artifact != nil
	case scenariocontrol.CrossTenantArtifactCaseID, scenariocontrol.MTLSCallerBindingCaseID:
		stateOK = stateOK && before.Stage == callerstate.StageInitialComplete && reflect.DeepEqual(after, before)
	default:
		stateOK = false
	}
	if !stateOK || store.ValidateUnchanged() != nil {
		return ExitSoftware
	}
	result, err := scenariocontrol.NewResult(request, os.Getpid(), data)
	if err != nil {
		return ExitData
	}
	if err := scenariocontrol.EncodeResult(stdout, result); err != nil {
		return ExitIO
	}
	return ExitSuccess
}

func privateContinuationCases(phase string) []string {
	if phase == "reconstruction" {
		return []string{scenariocontrol.ReconstructionLifecycleCaseID, scenariocontrol.ReconstructionEvidenceCaseID, scenariocontrol.ReconstructionHandoffCaseID, scenariocontrol.ReconstructionReconnectCaseID}
	}
	if phase != "initial" {
		return nil
	}
	return []string{scenariocontrol.LifecycleCaseID, scenariocontrol.ReplayCaseID, scenariocontrol.LifecycleCompletionCaseID, scenariocontrol.ExecResultUsageCaseID, scenariocontrol.StaleFencingCaseID, scenariocontrol.ExecCancellationCaseID, scenariocontrol.TerminalSessionCaseID, scenariocontrol.GatewayRoundTripCaseID, scenariocontrol.GatewayAuthorityRejectionCaseID, scenariocontrol.GatewayGrantExpiryCaseID, scenariocontrol.GatewayRevocationCaseID, scenariocontrol.ArtifactStagingCaseID, scenariocontrol.CrossTenantArtifactCaseID, scenariocontrol.MTLSCallerBindingCaseID}
}

// RunWithCoordinator executes one private phase using an injected fixed-sibling
// Gateway service starter. A nil starter fails closed after input validation.
func RunWithCoordinator(ctx context.Context, arguments []string, stdin io.Reader, stdout io.Writer, start callerphase.StartGateway, runProvider callerphase.RunProvider) int {
	if len(arguments) != 0 {
		return ExitUsage
	}
	request, err := callercontrol.DecodeRequest(stdin)
	if err != nil {
		return ExitData
	}
	bundle, err := credentials.NewReader(credentials.Requirements()).Read(request.CredentialChannelDescriptors)
	if err != nil {
		return ExitData
	}
	defer bundle.Destroy()
	if err := credentials.ValidateGatewayIdentityBundle(bundle, request.GatewayProbeEndpoint); err != nil {
		return ExitData
	}
	if err := callerphase.Coordinate(ctx, request, bundle, start, runProvider); err != nil {
		bundle.Destroy()
		return ExitSoftware
	}
	bundle.Destroy()
	result, err := callercontrol.NewResult(request.Phase, os.Getpid())
	if err != nil {
		return ExitData
	}
	if err := callercontrol.EncodeResult(stdout, result); err != nil {
		return ExitIO
	}
	return ExitSuccess
}
