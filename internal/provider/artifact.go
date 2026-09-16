package provider

import (
	"context"
	"encoding/json"
	"net/http"
)

func (c *Client) StageArtifact(ctx context.Context, sandboxID string, requestDocument ArtifactStagingRequest, admission Admission) (ProviderOperation, error) {
	bound, err := BindArtifactStagingRequest(requestDocument)
	if err != nil || bound.RequestDigest != requestDocument.RequestDigest {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	path := "/v1/sandboxes/" + sandboxID + "/artifacts:stage"
	if err := validateMutationAdmission(bound.OperationID, bound.AttemptID, bound.FencingToken, bound.RequestDigest, bound.DeadlineAt, sandboxID, admission, "stage_artifact", ArtifactStagingRequestContractID, path); err != nil {
		return ProviderOperation{}, err
	}
	body, err := marshalJSON(bound)
	if err != nil || len(body) > 65536 {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	request, err := c.newRequest(ctx, http.MethodPost, path, body, &admission)
	if err != nil {
		return ProviderOperation{}, err
	}
	response, err := c.do(request, http.StatusAccepted, statusSet(400, 401, 403, 409, 422, 503))
	if err != nil {
		return ProviderOperation{}, err
	}
	var operation ProviderOperation
	if err := decodeProviderOperation(response, &operation); err != nil {
		return ProviderOperation{}, err
	}
	if operation.OperationID != bound.OperationID || operation.AttemptID != bound.AttemptID || operation.FencingToken != bound.FencingToken || operation.SandboxID != sandboxID || operation.Type != "artifact_stage" || operation.Status != "accepted" {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	return operation, nil
}

func (c *Client) GetArtifactStagingEvidence(ctx context.Context, descriptor ReadDescriptor, admission Admission) (ArtifactStagingEvidence, error) {
	path := "/v1/operations/" + descriptor.OperationID + "/artifact-staging-evidence"
	if descriptor.Operation != "read_artifact_staging_evidence" || validateReadAdmission(descriptor, admission, ArtifactEvidenceDescriptorContractID, path) != nil {
		return ArtifactStagingEvidence{}, ErrAdmissionBinding
	}
	request, err := c.newRequest(ctx, http.MethodGet, path, nil, &admission)
	if err != nil {
		return ArtifactStagingEvidence{}, err
	}
	response, err := c.do(request, http.StatusOK, statusSet(400, 401, 403, 404, 410, 503))
	if err != nil {
		return ArtifactStagingEvidence{}, err
	}
	var evidence ArtifactStagingEvidence
	if err := decodeArtifactStagingEvidence(response, &evidence); err != nil {
		return ArtifactStagingEvidence{}, err
	}
	if evidence.OperationID != descriptor.OperationID || evidence.AttemptID != descriptor.AttemptID || evidence.FencingToken != descriptor.FencingToken || evidence.SandboxID != descriptor.SandboxID {
		return ArtifactStagingEvidence{}, ErrInvalidContractDocument
	}
	return evidence, nil
}

func decodeArtifactStagingEvidence(document []byte, target *ArtifactStagingEvidence) error {
	object, err := decodeStrict(document, target,
		[]string{"operation_id", "attempt_id", "fencing_token", "sandbox_id", "artifact_reference", "status", "content_digest", "media_type", "size_bytes", "tenant_binding_check", "active_content_check", "malware_check", "observed_at", "expires_at", "evidence_digest"},
		[]string{"staging_reference"})
	if err != nil {
		return err
	}
	for _, key := range []string{"tenant_binding_check", "active_content_check", "malware_check"} {
		if !objectShape(object[key], []string{"status", "checked_at"}, []string{"evidence_reference"}) {
			return ErrInvalidContractDocument
		}
		var check map[string]json.RawMessage
		if json.Unmarshal(object[key], &check) != nil {
			return ErrInvalidContractDocument
		}
		if raw, present := check["evidence_reference"]; present && string(raw) == `""` {
			return ErrInvalidContractDocument
		}
	}
	if raw, present := object["staging_reference"]; present && string(raw) == `""` {
		return ErrInvalidContractDocument
	}
	return validateArtifactStagingEvidence(*target)
}
