package testprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

// Check the actual HTTP carrier and body as well as the signature. This makes
// loopback composition tests detect caller descriptor/route/digest mistakes.
func boundAdmission(request *http.Request, claims provider.JWSClaims, admitted provider.AdmissionContext) bool {
	deadline, err := time.Parse(time.RFC3339Nano, claims.DeadlineAt)
	if err != nil || !deadline.After(time.Now()) || time.Now().Unix() < claims.NotBefore || time.Now().Unix() >= claims.ExpiresAt || claims.JTI == "" || admitted.ControllerSubject != claims.Subject || admitted.ProviderRevisionID != claims.ProviderRevisionID || admitted.ProviderInstanceAudience != claims.Audience || admitted.TenantID != claims.TenantID || admitted.WorkOrderID != claims.WorkOrderID || admitted.PolicyDigest != claims.PolicyDigest || admitted.PolicyDecidedAt != claims.PolicyDecidedAt || admitted.Operation != claims.Operation || admitted.SandboxID != claims.SandboxID || admitted.OperationID != claims.OperationID || admitted.AttemptID != claims.AttemptID || admitted.FencingToken != claims.FencingToken || admitted.DeadlineAt != claims.DeadlineAt || admitted.RequestContractID != claims.RequestContractID || admitted.RequestDigestProfile != claims.RequestDigestProfile || admitted.RequestDigest != claims.RequestDigest {
		return false
	}
	contextDigest, err := jcs.DigestExcluding(admitted, "context_digest")
	if err != nil || admitted.ContextDigest != contextDigest || claims.AdmissionContextDigest != contextDigest || admitted.ContextContractID != provider.AdmissionContextContractID || claims.AdmissionContextContractID != admitted.ContextContractID || admitted.ContextDigestProfile != provider.AdmissionContextDigestProfile || claims.AdmissionContextDigestProfile != admitted.ContextDigestProfile || admitted.HTTPTarget.Method != request.Method || admitted.HTTPTarget.Path != request.URL.Path || admitted.HTTPTarget.NormalizedQuery == nil || len(admitted.HTTPTarget.NormalizedQuery) != 0 || request.URL.RawQuery != "" {
		return false
	}
	paths := map[string]string{
		"create": "/v1/sandboxes", "exec": "/v1/sandboxes/" + claims.SandboxID + "/exec", "cancel_exec": "/v1/sandboxes/" + claims.SandboxID + "/exec:cancel", "open_runtime_session": "/v1/sandboxes/" + claims.SandboxID + "/runtime-sessions",
		"stage_artifact":          "/v1/sandboxes/" + claims.SandboxID + "/artifacts:stage",
		"connect_runtime_session": "/v1/runtime-sessions:connect",
		"read_operation":          "/v1/operations/" + claims.OperationID, "read_sandbox": "/v1/sandboxes/" + claims.SandboxID,
		"read_result": "/v1/operations/" + claims.OperationID + "/exec-result", "read_usage_evidence": "/v1/operations/" + claims.OperationID + "/usage-evidence", "read_runtime_session": "/v1/operations/" + claims.OperationID + "/runtime-session",
		"read_artifact_staging_evidence": "/v1/operations/" + claims.OperationID + "/artifact-staging-evidence",
	}
	contracts := map[string]string{
		"create": provider.CreateRequestContractID, "exec": provider.ExecRequestContractID, "cancel_exec": provider.CancelExecRequestContractID, "open_runtime_session": provider.RuntimeSessionRequestContractID,
		"stage_artifact": provider.ArtifactStagingRequestContractID,
		"read_operation": provider.OperationDescriptorContractID, "read_sandbox": provider.StatusDescriptorContractID,
		"read_result": provider.ExecResultDescriptorContractID, "read_usage_evidence": provider.UsageDescriptorContractID, "read_runtime_session": provider.SessionDescriptorContractID,
		"read_artifact_staging_evidence": provider.ArtifactEvidenceDescriptorContractID,
		"connect_runtime_session":        provider.RuntimeSessionConnectDescriptorContractID,
	}
	if paths[claims.Operation] != request.URL.Path || contracts[claims.Operation] != claims.RequestContractID {
		return false
	}
	if request.Method == http.MethodGet {
		if claims.Operation == "connect_runtime_session" {
			raw, err := base64.RawURLEncoding.Strict().DecodeString(request.Header.Get("X-Sandbox-Runtime-Session-Handoff"))
			if err != nil || len(raw) > 4096 {
				return false
			}
			var descriptor provider.RuntimeSessionHandoff
			if json.Unmarshal(raw, &descriptor) != nil || descriptor.SandboxID != claims.SandboxID || descriptor.OperationID != claims.OperationID || descriptor.AttemptID != claims.AttemptID || descriptor.FencingToken != claims.FencingToken {
				return false
			}
			digest, err := provider.DigestRuntimeSessionConnectDescriptor(descriptor)
			return err == nil && claims.RequestDigestProfile == provider.DescriptorDigestProfile && claims.RequestDigest == digest
		}
		digest, err := provider.DigestReadDescriptor(provider.ReadDescriptor{Operation: claims.Operation, SandboxID: claims.SandboxID, OperationID: claims.OperationID, AttemptID: claims.AttemptID, FencingToken: claims.FencingToken})
		return err == nil && claims.RequestDigestProfile == provider.DescriptorDigestProfile && claims.RequestDigest == digest
	}
	if request.Method != http.MethodPost || claims.RequestDigestProfile != provider.MutationDigestProfile {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return false
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if _, err := jcs.Canonicalize(body); err != nil {
		return false
	}
	digest, err := jcs.DigestExcluding(json.RawMessage(body), "request_digest")
	if err != nil || digest != claims.RequestDigest {
		return false
	}
	var fields struct {
		OperationID   string                `json:"operation_id"`
		AttemptID     string                `json:"attempt_id"`
		FencingToken  int64                 `json:"fencing_token"`
		DeadlineAt    string                `json:"deadline_at"`
		RequestDigest string                `json:"request_digest"`
		Spec          *provider.SandboxSpec `json:"spec"`
	}
	if json.Unmarshal(body, &fields) != nil || fields.OperationID != claims.OperationID || fields.AttemptID != claims.AttemptID || fields.FencingToken != claims.FencingToken || fields.DeadlineAt != claims.DeadlineAt || fields.RequestDigest != digest {
		return false
	}
	return claims.Operation != "create" || fields.Spec != nil && fields.Spec.SandboxID == claims.SandboxID && fields.Spec.TenantID == claims.TenantID && fields.Spec.WorkOrderID == claims.WorkOrderID
}
