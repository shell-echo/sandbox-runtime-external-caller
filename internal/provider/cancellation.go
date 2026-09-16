package provider

import (
	"context"
	"net/http"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
)

func BindCancelExecRequest(request CancelExecRequest) (CancelExecRequest, error) {
	digest, err := jcs.DigestExcluding(request, "request_digest")
	if err != nil || request.RequestDigest != "" && request.RequestDigest != digest {
		return CancelExecRequest{}, ErrInvalidContractDocument
	}
	request.RequestDigest = digest
	if ValidateCancelExecRequest(request) != nil {
		return CancelExecRequest{}, ErrInvalidContractDocument
	}
	return request, nil
}

func (c *Client) CancelExec(ctx context.Context, sandboxID string, requestDocument CancelExecRequest, admission Admission) (ProviderOperation, error) {
	bound, err := BindCancelExecRequest(requestDocument)
	if err != nil || bound.RequestDigest != requestDocument.RequestDigest {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	path := "/v1/sandboxes/" + sandboxID + "/exec:cancel"
	if validateMutationAdmission(bound.OperationID, bound.AttemptID, bound.FencingToken, bound.RequestDigest, bound.DeadlineAt, sandboxID, admission, "cancel_exec", CancelExecRequestContractID, path) != nil {
		return ProviderOperation{}, ErrAdmissionBinding
	}
	body, err := marshalJSON(bound)
	if err != nil || len(body) > 65536 {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	request, err := c.newRequest(ctx, http.MethodPost, path, body, &admission)
	if err != nil {
		return ProviderOperation{}, err
	}
	response, err := c.do(request, http.StatusAccepted, statusSet(400, 401, 403, 404, 409, 422, 503))
	if err != nil {
		return ProviderOperation{}, err
	}
	var operation ProviderOperation
	if decodeProviderOperation(response, &operation) != nil || operation.OperationID != bound.OperationID || operation.AttemptID != bound.AttemptID || operation.FencingToken != bound.FencingToken || operation.SandboxID != sandboxID || operation.Type != "cancel_exec" || operation.Status != "accepted" {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	return operation, nil
}
