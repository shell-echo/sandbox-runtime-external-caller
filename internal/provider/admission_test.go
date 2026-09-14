package provider

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
)

func TestBindCreateRequestIsStableAndRejectsSuppliedMismatch(t *testing.T) {
	request := testCreateRequest(time.Now().UTC().Truncate(time.Second))
	bound, err := BindCreateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !digestPattern.MatchString(bound.RequestDigest) {
		t.Fatalf("request digest = %q", bound.RequestDigest)
	}
	rebound, err := BindCreateRequest(bound)
	if err != nil || rebound.RequestDigest != bound.RequestDigest {
		t.Fatalf("rebind = %#v, %v", rebound, err)
	}
	request.RequestDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := BindCreateRequest(request); !errors.Is(err, ErrInvalidContractDocument) {
		t.Fatalf("mismatched request digest error = %v", err)
	}
}

func TestBuildAdmissionProducesVerifiableClosedJWSAndContext(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request, err := BindCreateRequest(testCreateRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	signer, publicKey := testSigner(t)
	admission, err := BuildAdmission(testAuthority(), testCreateBinding(request, now), signer)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader, encodedClaims, signature, err := signingParts(admission.BearerToken)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, []byte(encodedHeader+"."+encodedClaims), signature) {
		t.Fatal("compact JWS signature did not verify")
	}
	if strings.Contains(admission.BearerToken, "=") || strings.Contains(admission.ContextHeader, "=") {
		t.Fatal("protected admission used padded base64url")
	}
	contextDocument, err := base64.RawURLEncoding.DecodeString(admission.ContextHeader)
	if err != nil {
		t.Fatal(err)
	}
	var contextDocumentValue AdmissionContext
	if err := json.Unmarshal(contextDocument, &contextDocumentValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(contextDocumentValue, admission.Context) {
		t.Fatalf("decoded context differs: %#v != %#v", contextDocumentValue, admission.Context)
	}
	digest, err := jcs.DigestExcluding(admission.Context, "context_digest")
	if err != nil || digest != admission.Context.ContextDigest || admission.Claims.AdmissionContextDigest != digest {
		t.Fatalf("context digest binding = %q/%q, error %v", digest, admission.Claims.AdmissionContextDigest, err)
	}
	if err := validateAdmissionEnvelope(admission); err != nil {
		t.Fatal(err)
	}
}

func TestBuildAdmissionRejectsWrongAuthorityLifetimeAndTarget(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request, err := BindCreateRequest(testCreateRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := testSigner(t)
	tests := []struct {
		name      string
		authority AdmissionAuthority
		binding   AdmissionBinding
	}{
		{name: "subject is not URI SAN", authority: func() AdmissionAuthority {
			value := testAuthority()
			value.ControllerSubject = "controller-a"
			return value
		}(), binding: testCreateBinding(request, now)},
		{name: "lifetime exceeds 300 seconds", authority: testAuthority(), binding: func() AdmissionBinding {
			value := testCreateBinding(request, now)
			value.ExpiresAt = value.IssuedAt.Add(301 * time.Second)
			return value
		}()},
		{name: "wrong target", authority: testAuthority(), binding: func() AdmissionBinding {
			value := testCreateBinding(request, now)
			value.HTTPTarget.Path = "/v1/sandboxes/other"
			return value
		}()},
		{name: "wrong contract id", authority: testAuthority(), binding: func() AdmissionBinding {
			value := testCreateBinding(request, now)
			value.RequestContractID = StatusDescriptorContractID
			return value
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildAdmission(test.authority, test.binding, signer); !errors.Is(err, ErrAdmissionBinding) {
				t.Fatalf("BuildAdmission() error = %v", err)
			}
		})
	}
}

func TestDigestReadDescriptorMatchesLockedPublicFixture(t *testing.T) {
	descriptor := ReadDescriptor{
		Operation: "read_artifact_staging_evidence", SandboxID: "sandbox-1", OperationID: "artifact-operation-1", AttemptID: "artifact-attempt-1", FencingToken: 3,
	}
	digest, err := DigestReadDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	want := "sha256:a4dab0ecaeb1d468b1ebfbc692c323b71aa312af72d1e441084bde8caa7f6eee"
	if digest != want {
		t.Fatalf("descriptor digest = %q, want %q", digest, want)
	}
}

func testSigner(t *testing.T) (*Ed25519Signer, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	signer, err := NewEd25519Signer("caller-key-2026-09", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, privateKey.Public().(ed25519.PublicKey)
}

func testAuthority() AdmissionAuthority {
	return AdmissionAuthority{
		Issuer: "https://caller.example.test/sandbox-control-plane", ControllerSubject: "spiffe://provider/controller-a",
		ProviderInstanceAudience: "urn:shell-echo:sandbox-runtime:provider-instance:provider-1", ProviderRevisionID: "provider-revision-local-v1",
	}
}

func testCreateBinding(request CreateSandboxRequest, now time.Time) AdmissionBinding {
	return AdmissionBinding{
		JTI: "admission-token-0001", IssuedAt: now.Add(-time.Second), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(60 * time.Second),
		TenantID: request.Spec.TenantID, WorkOrderID: request.Spec.WorkOrderID, PolicyDigest: "sha256:" + strings.Repeat("b", 64), PolicyDecidedAt: now.Add(-time.Minute).Format(time.RFC3339),
		Operation: "create", SandboxID: request.Spec.SandboxID, OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		DeadlineAt: request.DeadlineAt, RequestContractID: CreateRequestContractID, RequestDigestProfile: MutationDigestProfile, RequestDigest: request.RequestDigest,
		HTTPTarget: AdmissionTarget{Method: "POST", Path: "/v1/sandboxes", NormalizedQuery: []QueryParameter{}},
	}
}

func testCreateRequest(now time.Time) CreateSandboxRequest {
	return CreateSandboxRequest{
		OperationID: "operation-create-1", AttemptID: "attempt-create-1", FencingToken: 1, IdempotencyKey: "create-sandbox-1", DeadlineAt: now.Add(2 * time.Minute).Format(time.RFC3339), ProtocolVersion: "v1",
		Spec: SandboxSpec{
			SandboxID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-order-1", WorkspaceID: "workspace-1", BranchID: "branch-1", ProviderResolutionID: "provider-resolution-1", ProviderRevisionID: "provider-revision-local-v1",
			Image: Image{Reference: "registry.invalid/sandbox/base", Digest: "sha256:" + strings.Repeat("d", 64)}, RuntimeProfile: "sandbox-runtime-coding-shell-v1",
			Resources:            Resources{CPUMillis: 500, MemoryBytes: 268435456, EphemeralStorageBytes: 268435456, PIDsLimit: 64},
			RequiredCapabilities: []CapabilityRequirement{{ID: "sandbox.exec", Version: "1.0.0", Profile: "exec-v1"}, {ID: "sandbox.terminal", Version: "1.0.0", Profile: "terminal-v1"}},
			Network:              NetworkPolicy{Mode: "none"},
			Workspace:            WorkspacePolicy{Mode: "ephemeral", BaseRevisionID: "workspace-revision-1", BaseRevisionDigest: "sha256:" + strings.Repeat("e", 64), BaseWorkspaceHeadVersion: 0, CommitMode: "read_only", MountPath: "/workspace"},
			Lease:                LeasePolicy{ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), MaxExtensionSeconds: 3600},
			Security:             SecurityPolicy{PrivilegeLevel: "unprivileged", RootFilesystem: "read_only", ServiceAccountMode: "none", SeccompProfile: "runtime-default"},
			SandboxSlotKey:       "primary-code",
		},
	}
}
