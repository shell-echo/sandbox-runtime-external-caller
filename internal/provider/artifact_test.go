package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestArtifactStageAndEvidenceAreExactlyBound(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	requestDocument, err := BindArtifactStagingRequest(testArtifactRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := testSigner(t)
	binding := testCreateBinding(testCreateRequest(now), now)
	binding.Operation, binding.RequestContractID, binding.RequestDigest, binding.FencingToken = "stage_artifact", ArtifactStagingRequestContractID, requestDocument.RequestDigest, requestDocument.FencingToken
	binding.OperationID, binding.AttemptID, binding.DeadlineAt = requestDocument.OperationID, requestDocument.AttemptID, requestDocument.DeadlineAt
	binding.HTTPTarget.Path = "/v1/sandboxes/sandbox-1/artifacts:stage"
	admission, err := BuildAdmission(testAuthority(), binding, signer)
	if err != nil {
		t.Fatal(err)
	}
	stamp := now.Format(time.RFC3339Nano)
	evidence := testArtifactEvidence(stamp)
	calls := 0
	client, err := NewClient("https://provider.example", roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		switch request.URL.Path {
		case "/v1/sandboxes/sandbox-1/artifacts:stage":
			body, _ := io.ReadAll(request.Body)
			var sent ArtifactStagingRequest
			if request.Method != http.MethodPost || json.Unmarshal(body, &sent) != nil || sent != requestDocument {
				t.Fatalf("artifact stage wire = %s %#v", request.Method, sent)
			}
			return jsonResponse(t, http.StatusAccepted, ProviderOperation{OperationID: sent.OperationID, AttemptID: sent.AttemptID, FencingToken: sent.FencingToken, SandboxID: "sandbox-1", Type: "artifact_stage", Status: "accepted", ObservedAt: stamp}), nil
		case "/v1/operations/artifact-operation-1/artifact-staging-evidence":
			if request.Method != http.MethodGet || request.Body != nil {
				t.Fatalf("artifact evidence wire = %#v", request)
			}
			return jsonResponse(t, http.StatusOK, evidence), nil
		default:
			return nil, errors.New("unexpected route")
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	if _, err := client.StageArtifact(context.Background(), "sandbox-1", requestDocument, admission); err != nil {
		t.Fatal(err)
	}
	descriptor := ReadDescriptor{Operation: "read_artifact_staging_evidence", SandboxID: "sandbox-1", OperationID: requestDocument.OperationID, AttemptID: requestDocument.AttemptID, FencingToken: requestDocument.FencingToken}
	readAdmission := testReadAdmission(t, signer, descriptor, ArtifactEvidenceDescriptorContractID, "/v1/operations/artifact-operation-1/artifact-staging-evidence", now, "artifact-read-token-0001")
	got, err := client.GetArtifactStagingEvidence(context.Background(), descriptor, readAdmission)
	if err != nil || got.StagingReference != evidence.StagingReference || calls != 2 {
		t.Fatalf("artifact evidence = %#v, calls %d, error %v", got, calls, err)
	}
}

func TestArtifactDocumentsRejectInvalidPathsShapesAndStagedChecks(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	base := testArtifactRequest(now)
	for _, path := range []string{"/output/file", "/outputs/../file", "/outputs//file", "/outputs/file name", "/outputs/file/"} {
		candidate := base
		candidate.SourcePath = path
		if _, err := BindArtifactStagingRequest(candidate); !errors.Is(err, ErrInvalidContractDocument) {
			t.Fatalf("accepted source path %q", path)
		}
	}
	stamp := now.Format(time.RFC3339Nano)
	baseEvidence, _ := json.Marshal(testArtifactEvidence(stamp))
	for name, mutate := range map[string]func(map[string]any){
		"unknown":             func(value map[string]any) { value["unknown"] = true },
		"missing staging":     func(value map[string]any) { delete(value, "staging_reference") },
		"failed staged check": func(value map[string]any) { value["malware_check"].(map[string]any)["status"] = "failed" },
		"unknown check field": func(value map[string]any) { value["tenant_binding_check"].(map[string]any)["private"] = true },
		"bad media":           func(value map[string]any) { value["media_type"] = "Text/Plain" },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate map[string]any
			_ = json.Unmarshal(baseEvidence, &candidate)
			mutate(candidate)
			document, _ := json.Marshal(candidate)
			if err := decodeArtifactStagingEvidence(document, &ArtifactStagingEvidence{}); !errors.Is(err, ErrInvalidContractDocument) {
				t.Fatalf("invalid artifact evidence accepted: %s", document)
			}
		})
	}
}

func testArtifactRequest(now time.Time) ArtifactStagingRequest {
	return ArtifactStagingRequest{OperationID: "artifact-operation-1", AttemptID: "artifact-attempt-1", FencingToken: 4, IdempotencyKey: "artifact-key-1", DeadlineAt: now.Add(time.Minute).Format(time.RFC3339Nano), ExpectedGeneration: 1, ArtifactReference: "artifact-ref:caller/artifact-1", SourcePath: "/outputs/result.txt", ExpectedDigest: "sha256:" + strings.Repeat("b", 64), ExpectedMediaType: "text/plain", MaxBytes: 24, RetentionSeconds: 3600}
}

func testArtifactEvidence(stamp string) ArtifactStagingEvidence {
	check := func(reference string) ArtifactCheck {
		return ArtifactCheck{Status: "passed", CheckedAt: stamp, EvidenceReference: reference}
	}
	return ArtifactStagingEvidence{OperationID: "artifact-operation-1", AttemptID: "artifact-attempt-1", FencingToken: 4, SandboxID: "sandbox-1", ArtifactReference: "artifact-ref:caller/artifact-1", StagingReference: "ref:staging:artifact-1", Status: "staged", ContentDigest: "sha256:" + strings.Repeat("b", 64), MediaType: "text/plain", SizeBytes: 24, TenantBindingCheck: check("ref:check:tenant"), ActiveContentCheck: check("ref:check:active"), MalwareCheck: check("ref:check:malware"), ObservedAt: stamp, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), EvidenceDigest: "sha256:" + strings.Repeat("c", 64)}
}
