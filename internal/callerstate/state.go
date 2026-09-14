// Package callerstate owns the external caller's private durable correlation
// state. The state is not a Provider DTO and must never be copied into evidence.
package callerstate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const (
	FormatVersion = 1
	StateType     = "sandbox-runtime-external-caller-correlation-state"

	StagePlanned           = "planned"
	StageCapabilitiesBound = "capabilities_bound"
	StageLifecycleBound    = "lifecycle_bound"
	StageExecBound         = "exec_bound"
	StageTerminalBound     = "terminal_bound"
	StageInitialComplete   = "initial_complete"

	maxSafeInteger = int64(1<<53 - 1)
)

var (
	ErrInvalidState      = errors.New("caller correlation state is invalid")
	ErrInvalidTransition = errors.New("caller correlation state transition is invalid")
	ErrEntropy           = errors.New("caller correlation entropy failed")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type State struct {
	FormatVersion    int               `json:"format_version"`
	StateType        string            `json:"state_type"`
	ContractRevision string            `json:"contract_revision"`
	ProfileID        string            `json:"profile_id"`
	ProfileDigest    string            `json:"profile_digest"`
	StoreRevision    int64             `json:"store_revision"`
	Stage            string            `json:"stage"`
	Plan             Plan              `json:"plan"`
	Provider         *ProviderBinding  `json:"provider"`
	Lifecycle        *OperationBinding `json:"lifecycle"`
	Exec             *ExecBinding      `json:"exec"`
	Terminal         *TerminalBinding  `json:"terminal"`
	Artifact         *ArtifactBinding  `json:"artifact"`
}

type Plan struct {
	RunID                string           `json:"run_id"`
	TenantAID            string           `json:"tenant_a_id"`
	TenantBID            string           `json:"tenant_b_id"`
	WorkOrderAID         string           `json:"work_order_a_id"`
	WorkOrderBID         string           `json:"work_order_b_id"`
	WorkspaceID          string           `json:"workspace_id"`
	BranchID             string           `json:"branch_id"`
	ProviderResolutionID string           `json:"provider_resolution_id"`
	SandboxID            string           `json:"sandbox_id"`
	Create               PlannedOperation `json:"create"`
	Exec                 PlannedOperation `json:"exec"`
	Terminal             PlannedOperation `json:"terminal"`
	Artifact             PlannedOperation `json:"artifact"`
}

type PlannedOperation struct {
	OperationID    string `json:"operation_id"`
	AttemptID      string `json:"attempt_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

type ProviderBinding struct {
	ProviderRevisionID     string `json:"provider_revision_id"`
	CapabilitySnapshotHash string `json:"capability_snapshot_sha256"`
	PolicyDigest           string `json:"policy_digest"`
	PolicyDecidedAt        string `json:"policy_decided_at"`
}

type OperationBinding struct {
	OperationID    string `json:"operation_id"`
	AttemptID      string `json:"attempt_id"`
	IdempotencyKey string `json:"idempotency_key"`
	FencingToken   int64  `json:"fencing_token"`
}

type ExecBinding struct {
	Operation           OperationBinding `json:"operation"`
	ResultDigest        string           `json:"result_digest"`
	UsageEvidenceDigest string           `json:"usage_evidence_digest"`
}

type TerminalBinding struct {
	Operation              OperationBinding `json:"operation"`
	RuntimeSessionID       string           `json:"runtime_session_id"`
	HandoffReference       string           `json:"handoff_reference"`
	HandoffReferenceDigest string           `json:"handoff_reference_digest"`
}

type ArtifactBinding struct {
	Operation      OperationBinding `json:"operation"`
	EvidenceDigest string           `json:"evidence_digest"`
}

func newInitialState() (State, error) {
	plan, err := newPlan()
	if err != nil {
		return State{}, err
	}
	state := State{
		FormatVersion: FormatVersion, StateType: StateType,
		ContractRevision: protocol.ContractRevision, ProfileID: protocol.ProfileID, ProfileDigest: protocol.ProfileDigest,
		StoreRevision: 1, Stage: StagePlanned, Plan: plan,
	}
	if err := validateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func newPlan() (Plan, error) {
	values := make([]string, 0, 21)
	for _, prefix := range []string{
		"run", "tenant-a", "tenant-b", "work-a", "work-b", "workspace", "branch", "resolution", "sandbox",
		"create-operation", "create-attempt", "create-idempotency",
		"exec-operation", "exec-attempt", "exec-idempotency",
		"terminal-operation", "terminal-attempt", "terminal-idempotency",
		"artifact-operation", "artifact-attempt", "artifact-idempotency",
	} {
		value, err := randomIdentifier(prefix)
		if err != nil {
			return Plan{}, err
		}
		values = append(values, value)
	}
	return Plan{
		RunID: values[0], TenantAID: values[1], TenantBID: values[2], WorkOrderAID: values[3], WorkOrderBID: values[4],
		WorkspaceID: values[5], BranchID: values[6], ProviderResolutionID: values[7], SandboxID: values[8],
		Create:   PlannedOperation{OperationID: values[9], AttemptID: values[10], IdempotencyKey: values[11]},
		Exec:     PlannedOperation{OperationID: values[12], AttemptID: values[13], IdempotencyKey: values[14]},
		Terminal: PlannedOperation{OperationID: values[15], AttemptID: values[16], IdempotencyKey: values[17]},
		Artifact: PlannedOperation{OperationID: values[18], AttemptID: values[19], IdempotencyKey: values[20]},
	}, nil
}

func randomIdentifier(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", ErrEntropy
	}
	return prefix + "-" + hex.EncodeToString(random), nil
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func operationFromPlan(plan PlannedOperation, fencingToken int64) OperationBinding {
	return OperationBinding{
		OperationID: plan.OperationID, AttemptID: plan.AttemptID,
		IdempotencyKey: plan.IdempotencyKey, FencingToken: fencingToken,
	}
}

func validateState(state State) error {
	if state.FormatVersion != FormatVersion || state.StateType != StateType || state.ContractRevision != protocol.ContractRevision || state.ProfileID != protocol.ProfileID || state.ProfileDigest != protocol.ProfileDigest || state.StoreRevision < 1 || state.StoreRevision > maxSafeInteger || !validPlan(state.Plan) {
		return ErrInvalidState
	}
	providerValid := state.Provider != nil && validIdentifier(state.Provider.ProviderRevisionID) && digestPattern.MatchString(state.Provider.CapabilitySnapshotHash) &&
		digestPattern.MatchString(state.Provider.PolicyDigest) && validDateTime(state.Provider.PolicyDecidedAt)
	lifecycleValid := state.Lifecycle != nil && validOperation(*state.Lifecycle) && matchesPlan(*state.Lifecycle, state.Plan.Create)
	execValid := state.Exec != nil && validOperation(state.Exec.Operation) && matchesPlan(state.Exec.Operation, state.Plan.Exec) && digestPattern.MatchString(state.Exec.ResultDigest) && digestPattern.MatchString(state.Exec.UsageEvidenceDigest)
	terminalValid := state.Terminal != nil && validOperation(state.Terminal.Operation) && matchesPlan(state.Terminal.Operation, state.Plan.Terminal) && validIdentifier(state.Terminal.RuntimeSessionID) && validOpaqueReference(state.Terminal.HandoffReference) && state.Terminal.HandoffReferenceDigest == rawDigest([]byte(state.Terminal.HandoffReference))
	artifactValid := state.Artifact != nil && validOperation(state.Artifact.Operation) && matchesPlan(state.Artifact.Operation, state.Plan.Artifact) && digestPattern.MatchString(state.Artifact.EvidenceDigest)

	switch state.Stage {
	case StagePlanned:
		if state.Provider != nil || state.Lifecycle != nil || state.Exec != nil || state.Terminal != nil || state.Artifact != nil {
			return ErrInvalidState
		}
	case StageCapabilitiesBound:
		if !providerValid || state.Lifecycle != nil || state.Exec != nil || state.Terminal != nil || state.Artifact != nil {
			return ErrInvalidState
		}
	case StageLifecycleBound:
		if !providerValid || !lifecycleValid || state.Exec != nil || state.Terminal != nil || state.Artifact != nil {
			return ErrInvalidState
		}
	case StageExecBound:
		if !providerValid || !lifecycleValid || !execValid || state.Terminal != nil || state.Artifact != nil {
			return ErrInvalidState
		}
	case StageTerminalBound:
		if !providerValid || !lifecycleValid || !execValid || !terminalValid || state.Artifact != nil {
			return ErrInvalidState
		}
	case StageInitialComplete:
		if !providerValid || !lifecycleValid || !execValid || !terminalValid || !artifactValid {
			return ErrInvalidState
		}
	default:
		return ErrInvalidState
	}
	return nil
}

func validPlan(plan Plan) bool {
	values := []string{
		plan.RunID, plan.TenantAID, plan.TenantBID, plan.WorkOrderAID, plan.WorkOrderBID, plan.WorkspaceID, plan.BranchID,
		plan.ProviderResolutionID, plan.SandboxID,
		plan.Create.OperationID, plan.Create.AttemptID, plan.Create.IdempotencyKey,
		plan.Exec.OperationID, plan.Exec.AttemptID, plan.Exec.IdempotencyKey,
		plan.Terminal.OperationID, plan.Terminal.AttemptID, plan.Terminal.IdempotencyKey,
		plan.Artifact.OperationID, plan.Artifact.AttemptID, plan.Artifact.IdempotencyKey,
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validIdentifier(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return plan.TenantAID != plan.TenantBID && plan.WorkOrderAID != plan.WorkOrderBID
}

func validOperation(operation OperationBinding) bool {
	return validIdentifier(operation.OperationID) && validIdentifier(operation.AttemptID) && validIdentifier(operation.IdempotencyKey) && operation.FencingToken >= 1 && operation.FencingToken <= maxSafeInteger
}

func matchesPlan(operation OperationBinding, plan PlannedOperation) bool {
	return operation.OperationID == plan.OperationID && operation.AttemptID == plan.AttemptID && operation.IdempotencyKey == plan.IdempotencyKey
}

func validIdentifier(value string) bool {
	return identifierPattern.MatchString(value)
}

func validOpaqueReference(value string) bool {
	if len(value) < 1 || len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsAny(value, "\x00\r\n")
}

func validDateTime(value string) bool {
	if value == "" || strings.Contains(value, " ") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}
