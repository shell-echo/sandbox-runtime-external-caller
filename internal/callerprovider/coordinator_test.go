//go:build darwin || linux

package callerprovider

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

type fakeClient struct {
	capabilities         provider.ProviderCapabilities
	raw                  []byte
	store                *callerstate.Store
	operations           []string
	statuses             []string
	creates              []provider.CreateSandboxRequest
	admissions           []provider.Admission
	execs                []provider.ExecRequest
	cancels              []provider.CancelExecRequest
	sessions             []provider.RuntimeSessionOpenRequest
	artifacts            []provider.ArtifactStagingRequest
	connects             []provider.RuntimeSessionHandoff
	result               provider.ExecResult
	usage                provider.UsageEvidence
	handoff              provider.RuntimeSessionHandoff
	artifactEvidence     provider.ArtifactStagingEvidence
	hook                 func(string) error
	resultHook           func(*provider.ExecResult)
	usageHook            func(*provider.UsageEvidence)
	handoffHook          func(*provider.RuntimeSessionHandoff)
	operationHook        func(*provider.ProviderOperation)
	lastOperation        provider.ProviderOperation
	createHook           func(int, provider.CreateSandboxRequest, provider.Admission) error
	execHook             func(int, provider.ExecRequest, provider.Admission) error
	cancelHook           func(int, provider.CancelExecRequest, provider.Admission) error
	sessionHook          func(int, provider.RuntimeSessionOpenRequest, provider.Admission) error
	artifactHook         func(int, provider.ArtifactStagingRequest, provider.Admission) error
	artifactEvidenceHook func(*provider.ArtifactStagingEvidence)
	statusHook           func(provider.ReadDescriptor, provider.Admission) error
	connectHook          func(provider.RuntimeSessionHandoff, provider.Admission) (io.ReadWriteCloser, error)
	capabilityCalls      int
	capabilityHook       func(int) error
}

func (client *fakeClient) DiscoverCapabilitiesDocument(context.Context) (provider.ProviderCapabilities, []byte, error) {
	client.capabilityCalls++
	if client.capabilityHook != nil {
		if err := client.capabilityHook(client.capabilityCalls); err != nil {
			return provider.ProviderCapabilities{}, nil, err
		}
	}
	return client.capabilities, append([]byte(nil), client.raw...), nil
}

func (client *fakeClient) CreateSandbox(_ context.Context, request provider.CreateSandboxRequest, admission provider.Admission) (provider.ProviderOperation, error) {
	client.creates = append(client.creates, request)
	client.admissions = append(client.admissions, admission)
	if client.createHook != nil {
		if err := client.createHook(len(client.creates), request, admission); err != nil {
			return provider.ProviderOperation{}, err
		}
	}
	return provider.ProviderOperation{
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		SandboxID: request.Spec.SandboxID, Type: "create", Status: "accepted", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (client *fakeClient) GetOperation(_ context.Context, descriptor provider.ReadDescriptor, admission provider.Admission) (provider.ProviderOperation, error) {
	client.admissions = append(client.admissions, admission)
	if client.hook != nil {
		if err := client.hook("poll:" + descriptor.OperationID); err != nil {
			return provider.ProviderOperation{}, err
		}
	}
	status := "succeeded"
	if len(client.operations) > 0 {
		status, client.operations = client.operations[0], client.operations[1:]
	}
	typ := "create"
	if descriptor.OperationID == client.store.Snapshot().Plan.Exec.OperationID {
		typ = "exec"
	}
	if descriptor.OperationID == client.store.Snapshot().Plan.Terminal.OperationID {
		typ = "open_runtime_session"
	}
	if descriptor.OperationID == client.store.Snapshot().Plan.Artifact.OperationID {
		typ = "artifact_stage"
	}
	operation := provider.ProviderOperation{
		OperationID: descriptor.OperationID, AttemptID: descriptor.AttemptID, FencingToken: descriptor.FencingToken,
		SandboxID: descriptor.SandboxID, Type: typ, Status: status, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if client.operationHook != nil {
		client.operationHook(&operation)
	}
	client.lastOperation = operation
	return operation, nil
}

func (client *fakeClient) StageArtifact(_ context.Context, sandboxID string, request provider.ArtifactStagingRequest, admission provider.Admission) (provider.ProviderOperation, error) {
	client.artifacts = append(client.artifacts, request)
	client.admissions = append(client.admissions, admission)
	if client.artifactHook != nil {
		if err := client.artifactHook(len(client.artifacts), request, admission); err != nil {
			return provider.ProviderOperation{}, err
		}
	}
	return provider.ProviderOperation{OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken, SandboxID: sandboxID, Type: "artifact_stage", Status: "accepted", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}

func (client *fakeClient) GetArtifactStagingEvidence(_ context.Context, descriptor provider.ReadDescriptor, admission provider.Admission) (provider.ArtifactStagingEvidence, error) {
	client.admissions = append(client.admissions, admission)
	if client.hook != nil {
		if err := client.hook("artifact-evidence:" + descriptor.OperationID); err != nil {
			return provider.ArtifactStagingEvidence{}, err
		}
	}
	evidence := client.artifactEvidence
	if evidence.OperationID == "" {
		now := time.Now().UTC()
		evidence = provider.ArtifactStagingEvidence{
			OperationID: descriptor.OperationID, AttemptID: descriptor.AttemptID, FencingToken: descriptor.FencingToken, SandboxID: descriptor.SandboxID,
			ArtifactReference: client.artifacts[len(client.artifacts)-1].ArtifactReference, StagingReference: "ref:staging:synthetic", Status: "staged",
			ContentDigest: artifactDigest, MediaType: artifactMediaType, SizeBytes: artifactSizeBytes,
			TenantBindingCheck: provider.ArtifactCheck{Status: "passed", CheckedAt: now.Format(time.RFC3339Nano), EvidenceReference: "ref:check:tenant"},
			ActiveContentCheck: provider.ArtifactCheck{Status: "passed", CheckedAt: now.Format(time.RFC3339Nano), EvidenceReference: "ref:check:active"},
			MalwareCheck:       provider.ArtifactCheck{Status: "passed", CheckedAt: now.Format(time.RFC3339Nano), EvidenceReference: "ref:check:malware"},
			ObservedAt:         now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), EvidenceDigest: "sha256:" + strings.Repeat("e", 64),
		}
	}
	if client.artifactEvidenceHook != nil {
		client.artifactEvidenceHook(&evidence)
	}
	client.artifactEvidence = evidence
	return evidence, nil
}

func (client *fakeClient) GetSandboxStatus(_ context.Context, descriptor provider.ReadDescriptor, admission provider.Admission) (provider.SandboxStatus, error) {
	client.admissions = append(client.admissions, admission)
	if client.statusHook != nil {
		if err := client.statusHook(descriptor, admission); err != nil {
			return provider.SandboxStatus{}, err
		}
	}
	observed := "ready"
	if len(client.statuses) > 0 {
		observed, client.statuses = client.statuses[0], client.statuses[1:]
	}
	state := client.store.Snapshot()
	return provider.SandboxStatus{
		SandboxID: descriptor.SandboxID, TenantID: state.Plan.TenantAID, WorkOrderID: state.Plan.WorkOrderAID,
		WorkspaceID: state.Plan.WorkspaceID, ProviderRevisionID: state.Provider.ProviderRevisionID,
		DesiredState: "ready", ObservedState: observed, Generation: 1, RuntimeProfile: RuntimeProfileID,
		LeaseExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), SandboxSlotKey: SandboxSlotKey,
		ObservedGeneration: map[bool]int64{true: 1, false: 0}[observed == "ready"],
	}, nil
}

func TestInitialBindsExactCapabilitiesAndSucceededLifecycle(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	clients := map[string]*fakeClient{
		"controller_a": {capabilities: capabilities, raw: raw, store: store, operations: []string{"accepted", "running", "succeeded"}, statuses: []string{"provisioning", "ready"}},
		"controller_b": {capabilities: capabilities, raw: raw, store: store},
	}
	base := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	closed := 0
	authority, err := run(ctx, "initial", "https://provider.example", &credentials.Bundle{}, store, fakeFactory(t, clients, &closed), func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	authority.Close()
	state := store.Snapshot()
	if state.Stage != callerstate.StageTerminalBound || state.StoreRevision != 5 || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.Terminal == nil || state.Provider.ProviderRevisionID != capabilities.ProviderRevisionID || state.Provider.CapabilitySnapshotHash != rawDigest(raw) || state.Provider.PolicyDigest == "" || state.Provider.PolicyDecidedAt == "" {
		t.Fatalf("bound lifecycle state = %#v", state)
	}
	if state.Lifecycle.OperationID != state.Plan.Create.OperationID || state.Lifecycle.FencingToken != createFencingToken {
		t.Fatalf("lifecycle binding = %#v", state.Lifecycle)
	}
	if len(clients["controller_a"].creates) != 1 || closed != 2 {
		t.Fatalf("create/close counts = %d/%d", len(clients["controller_a"].creates), closed)
	}
	request := clients["controller_a"].creates[0]
	if request.Spec.SandboxID != state.Plan.SandboxID || request.Spec.TenantID != state.Plan.TenantAID || request.Spec.RuntimeProfile != RuntimeProfileID || request.Spec.Image.Reference != ImageReference || request.Spec.Image.Digest != ImageDigest || request.Spec.Resources.CPUMillis != 500 || request.Spec.Resources.PIDsLimit != 64 || request.RequestDigest == "" {
		t.Fatalf("caller create request = %#v", request)
	}
	seenJTI := map[string]struct{}{}
	for _, admission := range clients["controller_a"].admissions {
		if admission.Context.PolicyDigest != state.Provider.PolicyDigest || admission.Context.PolicyDecidedAt != state.Provider.PolicyDecidedAt {
			t.Fatalf("admission policy binding = %#v", admission.Context)
		}
		if _, duplicate := seenJTI[admission.Claims.JTI]; duplicate {
			t.Fatalf("duplicate JTI %q", admission.Claims.JTI)
		}
		if admission.Claims.ExpiresAt > base.Add(5*time.Second).Unix() {
			t.Fatalf("admission expiry %d exceeds phase deadline", admission.Claims.ExpiresAt)
		}
		seenJTI[admission.Claims.JTI] = struct{}{}
	}
}

func TestProductionRuntimeImagePin(t *testing.T) {
	const repository = "ghcr.io/shell-echo/sandbox-runtime-coding-shell"
	const digest = "sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1"
	if ImageReference != repository || ImageDigest != digest || strings.Contains(ImageReference, "@") || strings.Contains(ImageReference, ":sha-") {
		t.Fatalf("runtime image pin = %q @ %q", ImageReference, ImageDigest)
	}
}

func TestReconstructionRequiresCapabilityAndLifecycleContinuityWithoutMutation(t *testing.T) {
	root, store := completeStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reconstructed, err := callerstate.OpenReconstruction(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reconstructed.Close()
	capabilities, raw := selectedCapabilities(t)
	want := reconstructed.Snapshot()
	client := &fakeClient{capabilities: capabilities, raw: raw, store: reconstructed}
	base := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	closed := 0
	if _, err := run(ctx, "reconstruction", "https://provider.example", &credentials.Bundle{}, reconstructed, fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed), func() time.Time { return base }); err != nil {
		t.Fatal(err)
	}
	if got := reconstructed.Snapshot(); !reflect.DeepEqual(got, want) || closed != 1 {
		t.Fatalf("reconstruction mutation/close = %#v / %d", got, closed)
	}
}

func TestInitialRejectsCrossControllerCapabilityMismatchBeforeBinding(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	changed := append([]byte(nil), raw...)
	changed = append(changed, ' ')
	clients := map[string]*fakeClient{
		"controller_a": {capabilities: capabilities, raw: raw, store: store},
		"controller_b": {capabilities: capabilities, raw: changed, store: store},
	}
	base := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	closed := 0
	if _, err := run(ctx, "initial", "https://provider.example", &credentials.Bundle{}, store, fakeFactory(t, clients, &closed), func() time.Time { return base }); !errors.Is(err, ErrCapabilityContinuity) {
		t.Fatalf("capability mismatch error = %v", err)
	}
	if state := store.Snapshot(); state.Stage != callerstate.StagePlanned || state.Provider != nil || closed != 2 {
		t.Fatalf("mismatch changed state/close = %#v / %d", state, closed)
	}
}

func TestInitialRejectsIncompleteCapabilitySelectionBeforeBinding(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, _ := selectedCapabilities(t)
	capabilities.Capabilities = capabilities.Capabilities[:1]
	raw, err := json.Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	clients := map[string]*fakeClient{
		"controller_a": {capabilities: capabilities, raw: raw, store: store},
		"controller_b": {capabilities: capabilities, raw: raw, store: store},
	}
	base := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	closed := 0
	if _, err := run(ctx, "initial", "https://provider.example", &credentials.Bundle{}, store, fakeFactory(t, clients, &closed), func() time.Time { return base }); !errors.Is(err, ErrCapabilitySelection) {
		t.Fatalf("incomplete capability error = %v", err)
	}
	if state := store.Snapshot(); state.Stage != callerstate.StagePlanned || state.Provider != nil || closed != 2 {
		t.Fatalf("incomplete capability changed state/close = %#v / %d", state, closed)
	}
}

func TestInitialLifecycleFailureRetainsOnlyCapabilityBinding(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	capabilities, raw := selectedCapabilities(t)
	clients := map[string]*fakeClient{
		"controller_a": {capabilities: capabilities, raw: raw, store: store, statuses: []string{"failed"}},
		"controller_b": {capabilities: capabilities, raw: raw, store: store},
	}
	base := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	closed := 0
	if _, err := run(ctx, "initial", "https://provider.example", &credentials.Bundle{}, store, fakeFactory(t, clients, &closed), func() time.Time { return base }); !errors.Is(err, ErrLifecycle) {
		t.Fatalf("lifecycle failure error = %v", err)
	}
	state := store.Snapshot()
	if state.Stage != callerstate.StageCapabilitiesBound || state.Provider == nil || state.Lifecycle != nil || state.StoreRevision != 2 || closed != 2 {
		t.Fatalf("lifecycle failure state/close = %#v / %d", state, closed)
	}
}

func TestReconstructionRejectsChangedCapabilityBytesWithoutMutation(t *testing.T) {
	root, store := completeStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reconstructed, err := callerstate.OpenReconstruction(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reconstructed.Close()
	want := reconstructed.Snapshot()
	capabilities, raw := selectedCapabilities(t)
	raw = append(raw, ' ')
	client := &fakeClient{capabilities: capabilities, raw: raw, store: reconstructed}
	base := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(5*time.Second))
	defer cancel()
	closed := 0
	if _, err := run(ctx, "reconstruction", "https://provider.example", &credentials.Bundle{}, reconstructed, fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed), func() time.Time { return base }); !errors.Is(err, ErrCapabilityContinuity) {
		t.Fatalf("changed capability error = %v", err)
	}
	if got := reconstructed.Snapshot(); !reflect.DeepEqual(got, want) || closed != 1 {
		t.Fatalf("changed capability mutated state/close = %#v / %d", got, closed)
	}
}

func fakeFactory(t *testing.T, clients map[string]*fakeClient, closed *int) accessFactory {
	t.Helper()
	return func(_ *credentials.Bundle, _ string, actor string) (*access, error) {
		client := clients[actor]
		if client == nil {
			return nil, ErrProviderAccess
		}
		seed := make([]byte, ed25519.SeedSize)
		for index := range seed {
			seed[index] = byte(index + len(actor) + 1)
		}
		signer, err := provider.NewEd25519Signer("test-key-"+actor, ed25519.NewKeyFromSeed(seed))
		if err != nil {
			t.Fatal(err)
		}
		return &access{
			controllerSubject: "spiffe://provider/" + actor, issuer: "https://caller.example.test/control",
			audience: "urn:shell-echo:sandbox-runtime:provider-instance:test", signer: signer, client: client,
			close: func() { signer.Destroy(); (*closed)++ },
		}, nil
	}
}

func selectedCapabilities(t *testing.T) (provider.ProviderCapabilities, []byte) {
	t.Helper()
	workspace := int64(1073741824)
	capabilities := provider.ProviderCapabilities{
		ProviderRevisionID: "provider-revision-local-v1", APIVersion: "v1",
		Capabilities: []provider.Capability{
			{ID: "sandbox.exec", Versions: []string{"1.0.0"}, Profiles: []string{ExecProfileID}},
			{ID: "sandbox.terminal", Versions: []string{"1.0.0"}, Profiles: []string{TerminalProfileID}},
			{ID: "sandbox.terminal-connect", Versions: []string{"1.0.0"}, Profiles: []string{TerminalConnectProfileID}},
		},
		RuntimeProfiles:         []provider.RuntimeProfile{{ID: RuntimeProfileID, IsolationClass: "container", CapabilityProfileIDs: []string{ExecProfileID, TerminalProfileID, TerminalConnectProfileID}}},
		SnapshotRestoreProfiles: []provider.SnapshotRestoreProfile{{ProfileID: "sandbox-snapshot-workspace-v1", Level: "workspace", SuiteID: "sandbox-provider", SuiteVersion: "1.0.0", SuiteDigest: "sha256:" + strings.Repeat("a", 64)}},
		Limits:                  provider.ProviderLimits{MaxCPUMillis: 1000, MaxMemoryBytes: 1073741824, MaxEphemeralStorageBytes: 1073741824, MaxWorkspaceBytes: &workspace, MaxLeaseSeconds: 3600, MaxExecSeconds: 300},
	}
	raw, err := json.Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	return capabilities, raw
}

func initialStore(t *testing.T) *callerstate.Store {
	t.Helper()
	root := privateRoot(t)
	store, err := callerstate.CreateInitial(root)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func completeStore(t *testing.T) (string, *callerstate.Store) {
	t.Helper()
	root := privateRoot(t)
	store, err := callerstate.CreateInitial(root)
	if err != nil {
		t.Fatal(err)
	}
	_, raw := selectedCapabilities(t)
	if err := store.BindCapabilities("provider-revision-local-v1", raw, "sha256:"+strings.Repeat("f", 64), "2026-09-12T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	for _, step := range []func() error{
		func() error { return store.BindLifecycle(1) },
		func() error {
			return store.BindExec(2, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64))
		},
		func() error { return store.BindTerminal(3, "runtime-session-1", "opaque:handoff:1") },
		func() error { return store.BindArtifact(4, "sha256:"+strings.Repeat("c", 64)) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	return root, store
}

func privateRoot(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "caller-state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
