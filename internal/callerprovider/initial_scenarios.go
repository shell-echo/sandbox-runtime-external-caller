package callerprovider

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

var ErrInitialScenario = errors.New("locked initial scenario failed")

// InitialScenarioExecutor keeps caller-private authority in one process across
// ordered scenarios. In particular, the accepted create request and its exact
// Admission JWS remain available for the following replay-semantics case.
type InitialScenarioExecutor struct {
	origin                              string
	bundle                              *credentials.Bundle
	store                               *callerstate.Store
	now                                 func() time.Time
	next                                int
	capabilities                        provider.ProviderCapabilities
	controllerA                         *access
	controllerB                         *access
	buildProviderAccess                 accessFactory
	create                              provider.CreateSandboxRequest
	admission                           provider.Admission
	operation                           provider.ProviderOperation
	sandbox                             provider.SandboxStatus
	exec                                provider.ExecRequest
	execAdmission                       provider.Admission
	execResult                          provider.ExecResult
	usage                               provider.UsageEvidence
	terminalRequest                     provider.RuntimeSessionOpenRequest
	terminalAdmission                   provider.Admission
	terminalOperation                   provider.ProviderOperation
	terminalHandoff                     provider.RuntimeSessionHandoff
	artifactRequest                     provider.ArtifactStagingRequest
	artifactAdmission                   provider.Admission
	artifactOperation                   provider.ProviderOperation
	artifactEvidence                    provider.ArtifactStagingEvidence
	gatewayEndpoint                     string
	startGateway                        StartScenarioGateway
	dialGateway                         func(context.Context, string, string, *tls.Config) (io.ReadWriteCloser, error)
	dialGatewayWithoutClientCertificate func(context.Context, string, string, *tls.Config) (io.ReadWriteCloser, error)
	buildGatewayAccess                  func(*credentials.Bundle, string, string) (*credentials.GatewayAccess, error)
	reconstructionGateway               ScenarioGateway
	reconstructionGatewayCancel         context.CancelFunc
}

func NewInitialScenarioExecutor(origin string, bundle *credentials.Bundle, store *callerstate.Store) (*InitialScenarioExecutor, error) {
	if origin == "" || bundle == nil || store == nil {
		return nil, ErrInitialScenario
	}
	return &InitialScenarioExecutor{origin: origin, bundle: bundle, store: store, now: time.Now, buildProviderAccess: buildAccess}, nil
}

func NewInitialScenarioExecutorWithGateway(origin, endpoint string, bundle *credentials.Bundle, store *callerstate.Store, start StartScenarioGateway) (*InitialScenarioExecutor, error) {
	executor, err := NewInitialScenarioExecutor(origin, bundle, store)
	if err != nil || endpoint == "" || start == nil {
		return nil, ErrInitialScenario
	}
	executor.gatewayEndpoint = endpoint
	executor.startGateway = start
	executor.dialGateway = dialScenarioGateway
	executor.dialGatewayWithoutClientCertificate = dialScenarioGatewayWithoutClientCertificate
	executor.buildGatewayAccess = credentials.BuildGatewayAccessFromBundle
	return executor, nil
}

func (executor *InitialScenarioExecutor) Execute(ctx context.Context, caseID string) (protocol.ScenarioResultData, error) {
	if executor == nil || executor.store == nil || ctx == nil || ctx.Err() != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	switch {
	case executor.next == 0 && caseID == scenariocontrol.ReconstructionCapabilityCaseID:
		result, err := executor.executeReconstructionCapability(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 1
		return result, nil
	case executor.next == 1 && caseID == scenariocontrol.ReconstructionLifecycleCaseID:
		result, err := executor.executeReconstructionLifecycle(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 2
		return result, nil
	case executor.next == 2 && caseID == scenariocontrol.ReconstructionEvidenceCaseID:
		result, err := executor.executeReconstructionEvidence(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 3
		return result, nil
	case executor.next == 3 && caseID == scenariocontrol.ReconstructionHandoffCaseID:
		result, err := executor.executeReconstructionHandoff(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 4
		return result, nil
	case executor.next == 4 && caseID == scenariocontrol.ReconstructionReconnectCaseID:
		result, err := executor.executeReconstructionReconnect(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 5
		return result, nil
	case executor.next == 0 && caseID == scenariocontrol.CapabilityCaseID:
		result, capabilities, err := runCapabilityDiscoveryScenario(ctx, executor.origin, executor.bundle, executor.store, executor.now)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.capabilities = capabilities
		executor.next = 1
		return result, nil
	case executor.next == 1 && caseID == scenariocontrol.LifecycleCaseID:
		result, err := executor.executeCreate(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 2
		return result, nil
	case executor.next == 2 && caseID == scenariocontrol.ReplayCaseID:
		result, err := executor.executeReplay(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 3
		return result, nil
	case executor.next == 3 && caseID == scenariocontrol.LifecycleCompletionCaseID:
		result, err := executor.executeLifecycleCompletion(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 4
		return result, nil
	case executor.next == 4 && caseID == scenariocontrol.ExecResultUsageCaseID:
		result, err := executor.executeExecResultUsage(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 5
		return result, nil
	case executor.next == 5 && caseID == scenariocontrol.StaleFencingCaseID:
		result, err := executor.executeStaleFencing(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 6
		return result, nil
	case executor.next == 6 && caseID == scenariocontrol.ExecCancellationCaseID:
		result, err := executor.executeExecCancellation(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 7
		return result, nil
	case executor.next == 7 && caseID == scenariocontrol.TerminalSessionCaseID:
		result, err := executor.executeTerminalSession(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 8
		return result, nil
	case executor.next == 8 && caseID == scenariocontrol.GatewayRoundTripCaseID:
		result, err := executor.executeGatewayRoundTrip(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 9
		return result, nil
	case executor.next == 9 && caseID == scenariocontrol.GatewayAuthorityRejectionCaseID:
		result, err := executor.executeGatewayAuthorityRejections(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 10
		return result, nil
	case executor.next == 10 && caseID == scenariocontrol.GatewayGrantExpiryCaseID:
		result, err := executor.executeGatewayGrantExpiry(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 11
		return result, nil
	case executor.next == 11 && caseID == scenariocontrol.GatewayRevocationCaseID:
		result, err := executor.executeGatewayRevocation(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 12
		return result, nil
	case executor.next == 12 && caseID == scenariocontrol.ArtifactStagingCaseID:
		result, err := executor.executeArtifactStaging(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 13
		return result, nil
	case executor.next == 13 && caseID == scenariocontrol.CrossTenantArtifactCaseID:
		result, err := executor.executeCrossTenantArtifactRejection(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 14
		return result, nil
	case executor.next == 14 && caseID == scenariocontrol.MTLSCallerBindingCaseID:
		result, err := executor.executeMTLSCallerBindingRejection(ctx)
		if err != nil {
			return protocol.ScenarioResultData{}, err
		}
		executor.next = 15
		return result, nil
	default:
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
}

func (executor *InitialScenarioExecutor) executeReplay(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second || state.Stage != callerstate.StageCapabilitiesBound || state.Provider == nil || state.StoreRevision != 2 ||
		!validAccess(executor.controllerA) || executor.create.RequestDigest == "" || executor.admission.BearerToken == "" || executor.operation.OperationID == "" {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	exactAttempts, exactTransients, rejected, err := submitCreateReplay(ctx, executor.controllerA.client, executor.create, executor.admission)
	if err != nil || rejected.StatusCode != http.StatusConflict || rejected.Document.Retryable || rejected.RetryAfterSeconds != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	fresh, err := createAdmission(executor.controllerA, state, executor.create, executor.now())
	if err != nil || fresh.Claims.JTI == executor.admission.Claims.JTI || fresh.BearerToken == executor.admission.BearerToken || !reflect.DeepEqual(fresh.Context, executor.admission.Context) {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	operation, freshAttempts, freshTransients, err := submitCreate(ctx, executor.controllerA.client, executor.create, fresh)
	if err != nil || !sameCreateOperationIdentity(operation, executor.operation) || executor.store.ValidateUnchanged() != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}

	exactObservations := []string{"same-compact-jws-replayed", "closed-standard-error", "rejected-before-dispatch"}
	freshObservations := []string{"new-jti-same-logical-request", "same-logical-operation-returned", "no-second-runtime-dispatch"}
	replayOf := "create-sandbox"
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.ReplayCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{
				InteractionID: "exact-jti-replay", Surface: "provider_http", Actor: "controller_a", Method: http.MethodPost,
				RouteTemplate: "/v1/sandboxes", LogicalRequestID: "create-sandbox", ReplayOf: &replayOf, WireAttempts: exactAttempts,
				TransientOutcomes: cloneOutcomes(exactTransients), FinalOutcome: httpOutcome(rejected), MutationWriteObserved: true,
				ObservationIDs: append([]string(nil), exactObservations...),
			},
			{
				InteractionID: "new-jti-idempotency-replay", Surface: "provider_http", Actor: "controller_a", Method: http.MethodPost,
				RouteTemplate: "/v1/sandboxes", LogicalRequestID: "create-sandbox", ReplayOf: &replayOf, WireAttempts: freshAttempts,
				TransientOutcomes: cloneOutcomes(freshTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusAccepted)}, MutationWriteObserved: true,
				ObservationIDs: append([]string(nil), freshObservations...),
			},
		},
		Assertions: []protocol.AssertionResult{
			{AssertionID: "jti-replay-is-not-idempotency-replay", Result: "asserted"},
			{AssertionID: "idempotency-key-body-operation-and-fence-unchanged", Result: "asserted"},
		},
		ObservationIDs: append(append([]string(nil), exactObservations...), freshObservations...),
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	return result, nil
}

func submitCreateReplay(ctx context.Context, client providerClient, request provider.CreateSandboxRequest, admission provider.Admission) (int, []protocol.Outcome, *provider.HTTPError, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= 2; attempt++ {
		_, err := client.CreateSandbox(ctx, request, admission)
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

func sameCreateOperation(left, right provider.ProviderOperation) bool {
	return left.OperationID == right.OperationID && left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken && left.SandboxID == right.SandboxID && left.Type == right.Type && left.Status == right.Status
}

func sameCreateOperationIdentity(left, right provider.ProviderOperation) bool {
	if left.OperationID != right.OperationID || left.AttemptID != right.AttemptID || left.FencingToken != right.FencingToken || left.SandboxID != right.SandboxID || left.Type != right.Type {
		return false
	}
	return successfulMutationStatus(left.Status)
}

func successfulMutationStatus(status string) bool {
	return status == "accepted" || status == "running" || status == "succeeded"
}

func (executor *InitialScenarioExecutor) Close() error {
	if executor == nil {
		return nil
	}
	var stopErr error
	if executor.reconstructionGateway != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stopErr = executor.reconstructionGateway.Stop(cleanup)
		cancel()
		executor.reconstructionGateway = nil
	}
	if executor.reconstructionGatewayCancel != nil {
		executor.reconstructionGatewayCancel()
		executor.reconstructionGatewayCancel = nil
	}
	closeAccess(executor.controllerA)
	closeAccess(executor.controllerB)
	executor.controllerA = nil
	executor.controllerB = nil
	executor.buildProviderAccess = nil
	executor.bundle = nil
	executor.store = nil
	executor.origin = ""
	executor.capabilities = provider.ProviderCapabilities{}
	executor.create = provider.CreateSandboxRequest{}
	executor.admission = provider.Admission{}
	executor.operation = provider.ProviderOperation{}
	executor.sandbox = provider.SandboxStatus{}
	executor.exec = provider.ExecRequest{}
	executor.execAdmission = provider.Admission{}
	executor.execResult = provider.ExecResult{}
	executor.usage = provider.UsageEvidence{}
	executor.terminalRequest = provider.RuntimeSessionOpenRequest{}
	executor.terminalAdmission = provider.Admission{}
	executor.terminalOperation = provider.ProviderOperation{}
	executor.terminalHandoff = provider.RuntimeSessionHandoff{}
	executor.artifactRequest = provider.ArtifactStagingRequest{}
	executor.artifactAdmission = provider.Admission{}
	executor.artifactOperation = provider.ProviderOperation{}
	executor.artifactEvidence = provider.ArtifactStagingEvidence{}
	executor.gatewayEndpoint = ""
	executor.startGateway = nil
	executor.dialGateway = nil
	executor.dialGatewayWithoutClientCertificate = nil
	executor.buildGatewayAccess = nil
	return stopErr
}

func (executor *InitialScenarioExecutor) executeLifecycleCompletion(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	state := executor.store.Snapshot()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second || state.Stage != callerstate.StageCapabilitiesBound || state.Provider == nil || state.StoreRevision != 2 || !validAccess(executor.controllerA) || !sameCreateOperationIdentity(executor.operation, provider.ProviderOperation{
		OperationID: state.Plan.Create.OperationID, AttemptID: state.Plan.Create.AttemptID, FencingToken: createFencingToken,
		SandboxID: state.Plan.SandboxID, Type: "create", Status: "accepted",
	}) {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	descriptor := provider.ReadDescriptor{
		Operation: "read_operation", SandboxID: state.Plan.SandboxID, OperationID: state.Plan.Create.OperationID,
		AttemptID: state.Plan.Create.AttemptID, FencingToken: createFencingToken,
	}
	operation, operationAttempts, operationTransients, err := pollExpectedOperation(ctx, executor.controllerA, state, descriptor, "create", executor.now)
	if err != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	sandbox, statusAttempts, statusTransients, err := pollReadySandbox(ctx, executor.controllerA, state, descriptor, executor.now)
	if err != nil || executor.store.ValidateUnchanged() != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	operationObservations := []string{"operation-succeeded"}
	statusObservations := []string{"sandbox-ready", "generation-one", "tenant-a-binding"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.LifecycleCompletionCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{
			{
				InteractionID: "read-create-operation", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet,
				RouteTemplate: "/v1/operations/{operation_id}", LogicalRequestID: "read-create-operation", WireAttempts: operationAttempts,
				TransientOutcomes: cloneOutcomes(operationTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)},
				MutationWriteObserved: false, ObservationIDs: append([]string(nil), operationObservations...),
			},
			{
				InteractionID: "read-sandbox-status", Surface: "provider_http", Actor: "controller_a", Method: http.MethodGet,
				RouteTemplate: "/v1/sandboxes/{sandbox_id}", LogicalRequestID: "read-sandbox-status", WireAttempts: statusAttempts,
				TransientOutcomes: cloneOutcomes(statusTransients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)},
				MutationWriteObserved: false, ObservationIDs: append([]string(nil), statusObservations...),
			},
		},
		Assertions:     []protocol.AssertionResult{{AssertionID: "caller-reconciled-accepted-operation", Result: "asserted"}},
		ObservationIDs: append(append([]string(nil), operationObservations...), statusObservations...),
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil || executor.store.BindLifecycle(createFencingToken) != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	after := executor.store.Snapshot()
	if after.Stage != callerstate.StageLifecycleBound || after.StoreRevision != 3 || after.Lifecycle == nil || after.Lifecycle.OperationID != descriptor.OperationID || after.Lifecycle.AttemptID != descriptor.AttemptID || after.Lifecycle.FencingToken != descriptor.FencingToken {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	executor.operation, executor.sandbox = operation, sandbox
	return result, nil
}

func pollExpectedOperation(ctx context.Context, value *access, state callerstate.State, descriptor provider.ReadDescriptor, expectedType string, now func() time.Time) (provider.ProviderOperation, int, []protocol.Outcome, error) {
	return pollExpectedOperationStatus(ctx, value, state, descriptor, expectedType, "succeeded", now)
}

func pollExpectedOperationStatus(ctx context.Context, value *access, state callerstate.State, descriptor provider.ReadDescriptor, expectedType, expectedStatus string, now func() time.Time) (provider.ProviderOperation, int, []protocol.Outcome, error) {
	transients := []protocol.Outcome{}
	for attempts := 1; attempts <= maxPollAttempts; attempts++ {
		admission, err := readAdmission(ctx, value, state, descriptor, now())
		if err != nil {
			return provider.ProviderOperation{}, 0, nil, err
		}
		operation, err := value.client.GetOperation(ctx, descriptor, admission)
		if err != nil {
			if outcome, retryAfter, retry := retryableReadOutcome(err, attempts); retry {
				transients = append(transients, outcome)
				if err := waitRetry(ctx, retryAfter); err != nil {
					return provider.ProviderOperation{}, 0, nil, err
				}
				continue
			}
			return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
		}
		if !operationMatches(operation, descriptor, expectedType) {
			return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
		}
		switch operation.Status {
		case expectedStatus:
			return operation, attempts, transients, nil
		case "accepted", "running":
			if attempts == maxPollAttempts || wait(ctx) != nil {
				return provider.ProviderOperation{}, 0, nil, preserveContext(ctx, ErrInitialScenario)
			}
		default:
			return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
		}
	}
	return provider.ProviderOperation{}, 0, nil, ErrInitialScenario
}

func pollReadySandbox(ctx context.Context, value *access, state callerstate.State, lifecycle provider.ReadDescriptor, now func() time.Time) (provider.SandboxStatus, int, []protocol.Outcome, error) {
	descriptor := lifecycle
	descriptor.Operation = "read_sandbox"
	transients := []protocol.Outcome{}
	for attempts := 1; attempts <= maxPollAttempts; attempts++ {
		admission, err := readAdmission(ctx, value, state, descriptor, now())
		if err != nil {
			return provider.SandboxStatus{}, 0, nil, err
		}
		status, err := value.client.GetSandboxStatus(ctx, descriptor, admission)
		if err != nil {
			if outcome, retryAfter, retry := retryableReadOutcome(err, attempts); retry {
				transients = append(transients, outcome)
				if err := waitRetry(ctx, retryAfter); err != nil {
					return provider.SandboxStatus{}, 0, nil, err
				}
				continue
			}
			return provider.SandboxStatus{}, 0, nil, ErrInitialScenario
		}
		if status.WorkspaceID != state.Plan.WorkspaceID || status.SandboxSlotKey != SandboxSlotKey || status.ProviderRevisionID != state.Provider.ProviderRevisionID {
			return provider.SandboxStatus{}, 0, nil, ErrInitialScenario
		}
		if status.DesiredState == "ready" && status.ObservedState == "ready" && status.Generation == 1 && status.ObservedGeneration == 1 && status.RuntimeProfile == RuntimeProfileID {
			lease, err := time.Parse(time.RFC3339Nano, status.LeaseExpiresAt)
			if err != nil || !lease.After(now()) {
				return provider.SandboxStatus{}, 0, nil, ErrInitialScenario
			}
			return status, attempts, transients, nil
		}
		if status.ObservedState != "requested" && status.ObservedState != "provisioning" {
			return provider.SandboxStatus{}, 0, nil, ErrInitialScenario
		}
		if attempts == maxPollAttempts || wait(ctx) != nil {
			return provider.SandboxStatus{}, 0, nil, preserveContext(ctx, ErrInitialScenario)
		}
	}
	return provider.SandboxStatus{}, 0, nil, ErrInitialScenario
}

func retryableReadOutcome(err error, attempt int) (protocol.Outcome, int, bool) {
	var rejection *provider.HTTPError
	if !errors.As(err, &rejection) || rejection.StatusCode != http.StatusServiceUnavailable || !rejection.Document.Retryable || rejection.RetryAfterSeconds == nil || *rejection.RetryAfterSeconds <= 0 || attempt == maxPollAttempts {
		return protocol.Outcome{}, 0, false
	}
	return httpOutcome(rejection), *rejection.RetryAfterSeconds, true
}

func (executor *InitialScenarioExecutor) executeCreate(ctx context.Context) (protocol.ScenarioResultData, error) {
	startedAt := executor.now()
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(startedAt.Add(time.Second)) || deadline.Sub(startedAt) > 120*time.Second {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	state := executor.store.Snapshot()
	if state.Stage != callerstate.StageCapabilitiesBound || state.Provider == nil || state.StoreRevision != 2 || executor.capabilities.ProviderRevisionID != state.Provider.ProviderRevisionID {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	if executor.controllerA == nil {
		factory := executor.buildProviderAccess
		if factory == nil {
			factory = buildAccess
		}
		controllerA, err := factory(executor.bundle, executor.origin, "controller_a")
		if err != nil || !validAccess(controllerA) {
			closeAccess(controllerA)
			return protocol.ScenarioResultData{}, ErrInitialScenario
		}
		executor.controllerA = controllerA
	}
	request, err := createRequest(ctx, state, executor.capabilities, startedAt)
	if err != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	admission, err := createAdmission(executor.controllerA, state, request, executor.now())
	if err != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	operation, attempts, transients, err := submitCreate(ctx, executor.controllerA.client, request, admission)
	if err != nil {
		return protocol.ScenarioResultData{}, preserveContext(ctx, ErrInitialScenario)
	}
	if operation.OperationID != state.Plan.Create.OperationID || operation.AttemptID != state.Plan.Create.AttemptID || operation.FencingToken != createFencingToken || operation.SandboxID != state.Plan.SandboxID || operation.Type != "create" || !successfulMutationStatus(operation.Status) ||
		admission.Context.TenantID != state.Plan.TenantAID || admission.Context.WorkOrderID != state.Plan.WorkOrderAID || admission.Context.RequestDigest != request.RequestDigest || admission.Context.OperationID != request.OperationID || admission.Context.AttemptID != request.AttemptID || admission.Context.FencingToken != request.FencingToken || executor.store.ValidateUnchanged() != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}

	observations := []string{"mutation-write-observed", "operation-accepted", "operation-correlation-exact", "single-runtime-dispatch", "run-owned-sandbox-resource-count-one"}
	result := protocol.ScenarioResultData{
		CaseID: scenariocontrol.LifecycleCaseID, Disposition: "completed",
		Interactions: []protocol.InteractionResult{{
			InteractionID: "create-sandbox", Surface: "provider_http", Actor: "controller_a", Method: http.MethodPost,
			RouteTemplate: "/v1/sandboxes", LogicalRequestID: "create-sandbox", WireAttempts: attempts,
			TransientOutcomes: cloneOutcomes(transients), FinalOutcome: protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusAccepted)},
			MutationWriteObserved: true, ObservationIDs: append([]string(nil), observations...),
		}},
		Assertions: []protocol.AssertionResult{
			{AssertionID: "caller-constructed-mtls-jws-and-admission-context", Result: "asserted"},
			{AssertionID: "caller-retained-durable-correlation", Result: "asserted"},
			{AssertionID: "run-owned-sandbox-id", Result: "asserted"},
		},
		ObservationIDs: append([]string(nil), observations...),
	}
	if protocol.ValidateScenarioResultData("initial", result) != nil {
		return protocol.ScenarioResultData{}, ErrInitialScenario
	}
	executor.create, executor.admission, executor.operation = request, admission, operation
	return result, nil
}

func submitCreate(ctx context.Context, client providerClient, request provider.CreateSandboxRequest, admission provider.Admission) (provider.ProviderOperation, int, []protocol.Outcome, error) {
	transients := []protocol.Outcome{}
	for attempt := 1; attempt <= 2; attempt++ {
		operation, err := client.CreateSandbox(ctx, request, admission)
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

func waitRetry(ctx context.Context, seconds int) error {
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return context.Cause(ctx)
	}
}
