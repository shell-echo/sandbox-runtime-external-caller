// Package callerprovider composes caller-owned policy with the clean-room
// Provider client. It owns no Provider implementation or qualification truth.
package callerprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

const (
	RuntimeProfileID  = "sandbox-runtime-coding-shell-v1"
	ExecProfileID     = "exec-v1"
	TerminalProfileID = "terminal-v1"
	ImageReference    = "registry.invalid/sandbox/base"
	ImageDigest       = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	EmptyBaseDigest   = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	SandboxSlotKey    = "primary-code"

	createFencingToken = int64(1)
	maxPollAttempts    = 64
	pollInterval       = 25 * time.Millisecond
)

var (
	ErrProviderAccess       = errors.New("caller Provider access failed")
	ErrCapabilitySelection  = errors.New("Provider capabilities do not satisfy the locked caller selection")
	ErrCapabilityContinuity = errors.New("Provider capability continuity failed")
	ErrPolicy               = errors.New("caller Provider policy construction failed")
	ErrLifecycle            = errors.New("Provider lifecycle did not reach the required state")
)

type providerClient interface {
	DiscoverCapabilitiesDocument(context.Context) (provider.ProviderCapabilities, []byte, error)
	CreateSandbox(context.Context, provider.CreateSandboxRequest, provider.Admission) (provider.ProviderOperation, error)
	GetSandboxStatus(context.Context, provider.ReadDescriptor, provider.Admission) (provider.SandboxStatus, error)
	GetOperation(context.Context, provider.ReadDescriptor, provider.Admission) (provider.ProviderOperation, error)
}

type access struct {
	controllerSubject string
	issuer            string
	audience          string
	signer            provider.Signer
	client            providerClient
	close             func()
}

type accessFactory func(*credentials.Bundle, string, string) (*access, error)

// Run performs only capability and create-lifecycle work. Initial advances a
// planned store through lifecycle_bound. Reconstruction proves the exact
// retained capability and lifecycle bindings without mutating the store.
func Run(ctx context.Context, phase, origin string, bundle *credentials.Bundle, store *callerstate.Store) error {
	return run(ctx, phase, origin, bundle, store, buildAccess, time.Now)
}

func run(ctx context.Context, phase, origin string, bundle *credentials.Bundle, store *callerstate.Store, factory accessFactory, now func() time.Time) error {
	if ctx == nil || bundle == nil || store == nil || factory == nil || now == nil || ctx.Err() != nil {
		return preserveContext(ctx, ErrProviderAccess)
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(now().Add(time.Second)) {
		return preserveContext(ctx, ErrLifecycle)
	}
	controllerA, err := factory(bundle, origin, "controller_a")
	if err != nil || !validAccess(controllerA) {
		closeAccess(controllerA)
		return ErrProviderAccess
	}
	defer closeAccess(controllerA)

	switch phase {
	case "initial":
		controllerB, err := factory(bundle, origin, "controller_b")
		if err != nil || !validAccess(controllerB) {
			closeAccess(controllerB)
			return ErrProviderAccess
		}
		defer closeAccess(controllerB)
		return runInitial(ctx, store, controllerA, controllerB, now)
	case "reconstruction":
		return runReconstruction(ctx, store, controllerA, now)
	default:
		return ErrLifecycle
	}
}

func runInitial(ctx context.Context, store *callerstate.Store, controllerA, controllerB *access, now func() time.Time) error {
	state := store.Snapshot()
	if state.Stage != callerstate.StagePlanned {
		return ErrLifecycle
	}
	capabilitiesA, rawA, err := controllerA.client.DiscoverCapabilitiesDocument(ctx)
	if err != nil {
		return preserveContext(ctx, ErrLifecycle)
	}
	capabilitiesB, rawB, err := controllerB.client.DiscoverCapabilitiesDocument(ctx)
	if err != nil {
		return preserveContext(ctx, ErrLifecycle)
	}
	if !bytes.Equal(rawA, rawB) || capabilitiesA.ProviderRevisionID != capabilitiesB.ProviderRevisionID {
		return ErrCapabilityContinuity
	}
	if validateSelection(capabilitiesA) != nil || validateSelection(capabilitiesB) != nil {
		return ErrCapabilitySelection
	}
	policyDigest, err := policyDigest(state)
	if err != nil {
		return ErrPolicy
	}
	decidedAt := now().UTC().Format(time.RFC3339Nano)
	if err := store.BindCapabilities(capabilitiesA.ProviderRevisionID, rawA, policyDigest, decidedAt); err != nil {
		return ErrLifecycle
	}
	state = store.Snapshot()
	request, err := createRequest(ctx, state, capabilitiesA, now())
	if err != nil {
		return err
	}
	admission, err := createAdmission(controllerA, state, request, now())
	if err != nil {
		return err
	}
	operation, err := controllerA.client.CreateSandbox(ctx, request, admission)
	if err != nil || operation.Status != "accepted" {
		return preserveContext(ctx, ErrLifecycle)
	}
	descriptor := provider.ReadDescriptor{
		Operation: "read_operation", SandboxID: state.Plan.SandboxID, OperationID: state.Plan.Create.OperationID,
		AttemptID: state.Plan.Create.AttemptID, FencingToken: createFencingToken,
	}
	if err := waitOperation(ctx, controllerA, state, descriptor, now); err != nil {
		return err
	}
	if err := waitSandboxReady(ctx, controllerA, state, descriptor, now); err != nil {
		return err
	}
	if err := store.BindLifecycle(createFencingToken); err != nil {
		return ErrLifecycle
	}
	return nil
}

func runReconstruction(ctx context.Context, store *callerstate.Store, controllerA *access, now func() time.Time) error {
	state := store.Snapshot()
	if state.Stage != callerstate.StageInitialComplete || state.Provider == nil || state.Lifecycle == nil {
		return ErrLifecycle
	}
	capabilities, raw, err := controllerA.client.DiscoverCapabilitiesDocument(ctx)
	if err != nil {
		return preserveContext(ctx, ErrLifecycle)
	}
	if validateSelection(capabilities) != nil || capabilities.ProviderRevisionID != state.Provider.ProviderRevisionID || rawDigest(raw) != state.Provider.CapabilitySnapshotHash {
		return ErrCapabilityContinuity
	}
	descriptor := provider.ReadDescriptor{
		Operation: "read_operation", SandboxID: state.Plan.SandboxID, OperationID: state.Lifecycle.OperationID,
		AttemptID: state.Lifecycle.AttemptID, FencingToken: state.Lifecycle.FencingToken,
	}
	if err := waitOperation(ctx, controllerA, state, descriptor, now); err != nil {
		return err
	}
	return waitSandboxReady(ctx, controllerA, state, descriptor, now)
}

func buildAccess(bundle *credentials.Bundle, origin, actor string) (*access, error) {
	material, err := credentials.BuildProviderAccessFromBundle(bundle, origin, actor)
	if err != nil || material == nil || material.Admission == nil {
		if material != nil {
			material.Close()
		}
		return nil, ErrProviderAccess
	}
	return &access{
		controllerSubject: material.ControllerSubject, issuer: material.Admission.Issuer,
		audience: material.Admission.ProviderInstanceAudience, signer: material.Admission.Signer,
		client: material.Client, close: material.Close,
	}, nil
}

func validAccess(value *access) bool {
	return value != nil && value.controllerSubject != "" && value.issuer != "" && value.audience != "" && value.signer != nil && value.client != nil && value.close != nil
}

func closeAccess(value *access) {
	if value != nil && value.close != nil {
		value.close()
	}
}

func validateSelection(capabilities provider.ProviderCapabilities) error {
	if capabilities.APIVersion != "v1" || capabilities.ProviderRevisionID == "" ||
		capabilities.Limits.MaxCPUMillis < 500 || capabilities.Limits.MaxMemoryBytes < 268435456 ||
		capabilities.Limits.MaxEphemeralStorageBytes < 268435456 || capabilities.Limits.MaxLeaseSeconds < 1 || capabilities.Limits.MaxExecSeconds < 1 {
		return ErrCapabilitySelection
	}
	if !hasCapability(capabilities.Capabilities, "sandbox.exec", "1.0.0", ExecProfileID) || !hasCapability(capabilities.Capabilities, "sandbox.terminal", "1.0.0", TerminalProfileID) {
		return ErrCapabilitySelection
	}
	for _, profile := range capabilities.RuntimeProfiles {
		if profile.ID == RuntimeProfileID && contains(profile.CapabilityProfileIDs, ExecProfileID) && contains(profile.CapabilityProfileIDs, TerminalProfileID) {
			return nil
		}
	}
	return ErrCapabilitySelection
}

func hasCapability(capabilities []provider.Capability, id, version, profile string) bool {
	for _, capability := range capabilities {
		if capability.ID == id && contains(capability.Versions, version) && contains(capability.Profiles, profile) {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func policyDigest(state callerstate.State) (string, error) {
	return jcs.Digest(struct {
		FormatVersion int      `json:"format_version"`
		PolicyID      string   `json:"policy_id"`
		TenantID      string   `json:"tenant_id"`
		WorkOrderID   string   `json:"work_order_id"`
		Operations    []string `json:"operations"`
	}{
		FormatVersion: 1, PolicyID: "external-caller-coding-shell-v1", TenantID: state.Plan.TenantAID,
		WorkOrderID: state.Plan.WorkOrderAID, Operations: []string{"create", "read_operation", "read_sandbox"},
	})
}

func createRequest(ctx context.Context, state callerstate.State, capabilities provider.ProviderCapabilities, now time.Time) (provider.CreateSandboxRequest, error) {
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(now.Add(time.Second)) {
		return provider.CreateSandboxRequest{}, preserveContext(ctx, ErrLifecycle)
	}
	leaseSeconds := capabilities.Limits.MaxLeaseSeconds
	if leaseSeconds > 1800 {
		leaseSeconds = 1800
	}
	request := provider.CreateSandboxRequest{
		OperationID: state.Plan.Create.OperationID, AttemptID: state.Plan.Create.AttemptID,
		FencingToken: createFencingToken, IdempotencyKey: state.Plan.Create.IdempotencyKey,
		DeadlineAt: deadline.UTC().Format(time.RFC3339Nano), ProtocolVersion: "v1",
		Spec: provider.SandboxSpec{
			SandboxID: state.Plan.SandboxID, TenantID: state.Plan.TenantAID, WorkOrderID: state.Plan.WorkOrderAID,
			WorkspaceID: state.Plan.WorkspaceID, BranchID: state.Plan.BranchID, ProviderResolutionID: state.Plan.ProviderResolutionID,
			ProviderRevisionID: capabilities.ProviderRevisionID,
			Image:              provider.Image{Reference: ImageReference, Digest: ImageDigest}, RuntimeProfile: RuntimeProfileID,
			Resources:            provider.Resources{CPUMillis: 500, MemoryBytes: 268435456, EphemeralStorageBytes: 268435456, PIDsLimit: 64},
			RequiredCapabilities: []provider.CapabilityRequirement{{ID: "sandbox.exec", Version: "1.0.0", Profile: ExecProfileID}, {ID: "sandbox.terminal", Version: "1.0.0", Profile: TerminalProfileID}},
			Network:              provider.NetworkPolicy{Mode: "none"},
			Workspace:            provider.WorkspacePolicy{Mode: "ephemeral", BaseRevisionID: state.Plan.WorkspaceID, BaseRevisionDigest: EmptyBaseDigest, BaseWorkspaceHeadVersion: 0, CommitMode: "read_only", MountPath: "/workspace"},
			Lease:                provider.LeasePolicy{ExpiresAt: now.Add(time.Duration(leaseSeconds) * time.Second).UTC().Format(time.RFC3339Nano)},
			Security:             provider.SecurityPolicy{PrivilegeLevel: "unprivileged", RootFilesystem: "read_only", ServiceAccountMode: "none", SeccompProfile: "runtime-default"},
			SandboxSlotKey:       SandboxSlotKey, AgentRunID: state.Plan.RunID,
		},
	}
	return provider.BindCreateRequest(request)
}

func createAdmission(value *access, state callerstate.State, request provider.CreateSandboxRequest, now time.Time) (provider.Admission, error) {
	return buildAdmission(value, state, provider.AdmissionBinding{
		Operation: "create", SandboxID: state.Plan.SandboxID, OperationID: state.Plan.Create.OperationID,
		AttemptID: state.Plan.Create.AttemptID, FencingToken: createFencingToken, DeadlineAt: request.DeadlineAt,
		RequestContractID: provider.CreateRequestContractID, RequestDigestProfile: provider.MutationDigestProfile, RequestDigest: request.RequestDigest,
		HTTPTarget: provider.AdmissionTarget{Method: http.MethodPost, Path: "/v1/sandboxes", NormalizedQuery: []provider.QueryParameter{}},
	}, now)
}

func readAdmission(ctx context.Context, value *access, state callerstate.State, descriptor provider.ReadDescriptor, now time.Time) (provider.Admission, error) {
	digest, err := provider.DigestReadDescriptor(descriptor)
	if err != nil {
		return provider.Admission{}, ErrPolicy
	}
	contractID, path := provider.OperationDescriptorContractID, "/v1/operations/"+descriptor.OperationID
	if descriptor.Operation == "read_sandbox" {
		contractID, path = provider.StatusDescriptorContractID, "/v1/sandboxes/"+descriptor.SandboxID
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(now.Add(time.Second)) {
		return provider.Admission{}, preserveContext(ctx, ErrLifecycle)
	}
	return buildAdmission(value, state, provider.AdmissionBinding{
		Operation: descriptor.Operation, SandboxID: descriptor.SandboxID, OperationID: descriptor.OperationID,
		AttemptID: descriptor.AttemptID, FencingToken: descriptor.FencingToken,
		DeadlineAt:        deadline.UTC().Format(time.RFC3339Nano),
		RequestContractID: contractID, RequestDigestProfile: provider.DescriptorDigestProfile, RequestDigest: digest,
		HTTPTarget: provider.AdmissionTarget{Method: http.MethodGet, Path: path, NormalizedQuery: []provider.QueryParameter{}},
	}, now)
}

func buildAdmission(value *access, state callerstate.State, binding provider.AdmissionBinding, now time.Time) (provider.Admission, error) {
	if state.Provider == nil {
		return provider.Admission{}, ErrPolicy
	}
	issuedAt := now.UTC().Add(-time.Second)
	expiresAt := now.UTC().Add(60 * time.Second)
	deadline, err := time.Parse(time.RFC3339Nano, binding.DeadlineAt)
	if err != nil || !deadline.After(now) {
		return provider.Admission{}, ErrPolicy
	}
	if deadline.Before(expiresAt) {
		expiresAt = deadline
	}
	if !expiresAt.After(now) {
		return provider.Admission{}, ErrPolicy
	}
	binding.JTI = newJTI()
	if binding.JTI == "" {
		return provider.Admission{}, ErrPolicy
	}
	binding.IssuedAt, binding.NotBefore, binding.ExpiresAt = issuedAt, issuedAt, expiresAt
	binding.TenantID, binding.WorkOrderID = state.Plan.TenantAID, state.Plan.WorkOrderAID
	binding.PolicyDigest, binding.PolicyDecidedAt = state.Provider.PolicyDigest, state.Provider.PolicyDecidedAt
	if binding.DeadlineAt == "" {
		binding.DeadlineAt = expiresAt.Format(time.RFC3339Nano)
	}
	authority := provider.AdmissionAuthority{
		Issuer: value.issuer, ControllerSubject: value.controllerSubject,
		ProviderInstanceAudience: value.audience, ProviderRevisionID: state.Provider.ProviderRevisionID,
	}
	admission, err := provider.BuildAdmission(authority, binding, value.signer)
	if err != nil {
		return provider.Admission{}, ErrPolicy
	}
	return admission, nil
}

func waitOperation(ctx context.Context, value *access, state callerstate.State, descriptor provider.ReadDescriptor, now func() time.Time) error {
	for attempt := 0; attempt < maxPollAttempts; attempt++ {
		admission, err := readAdmission(ctx, value, state, descriptor, now())
		if err != nil {
			return err
		}
		operation, err := value.client.GetOperation(ctx, descriptor, admission)
		if err != nil {
			return preserveContext(ctx, ErrLifecycle)
		}
		switch operation.Status {
		case "succeeded":
			return nil
		case "accepted", "running":
			if err := wait(ctx); err != nil {
				return err
			}
		default:
			return ErrLifecycle
		}
	}
	return ErrLifecycle
}

func waitSandboxReady(ctx context.Context, value *access, state callerstate.State, lifecycle provider.ReadDescriptor, now func() time.Time) error {
	descriptor := lifecycle
	descriptor.Operation = "read_sandbox"
	for attempt := 0; attempt < maxPollAttempts; attempt++ {
		admission, err := readAdmission(ctx, value, state, descriptor, now())
		if err != nil {
			return err
		}
		status, err := value.client.GetSandboxStatus(ctx, descriptor, admission)
		if err != nil {
			return preserveContext(ctx, ErrLifecycle)
		}
		if status.WorkspaceID != state.Plan.WorkspaceID || status.SandboxSlotKey != SandboxSlotKey || status.ProviderRevisionID != state.Provider.ProviderRevisionID {
			return ErrLifecycle
		}
		if status.DesiredState == "ready" && status.ObservedState == "ready" && status.Generation == 1 && status.ObservedGeneration == 1 && status.RuntimeProfile == RuntimeProfileID {
			return nil
		}
		if status.ObservedState != "requested" && status.ObservedState != "provisioning" {
			return ErrLifecycle
		}
		if err := wait(ctx); err != nil {
			return err
		}
	}
	return ErrLifecycle
}

func wait(ctx context.Context) error {
	timer := time.NewTimer(pollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func newJTI() string {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return ""
	}
	return "admission-" + hex.EncodeToString(random)
}

func rawDigest(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func preserveContext(ctx context.Context, fallback error) error {
	if ctx != nil && ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return fallback
}
