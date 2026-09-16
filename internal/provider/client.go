package provider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
)

const (
	maxCreateBodyBytes = 1 << 20
	maxResponseBytes   = 1 << 20
)

var (
	ErrInvalidOrigin    = errors.New("provider origin is not a canonical HTTPS origin")
	ErrMissingTransport = errors.New("provider HTTP transport is required")
	ErrTransport        = errors.New("provider HTTP transport failed")
	ErrResponseTooLarge = errors.New("provider response exceeds the caller limit")
	ErrContentType      = errors.New("provider response media type is not application/json")
	ErrUnexpectedStatus = errors.New("provider returned a status outside the locked OpenAPI operation")
	ErrTLSRejected      = errors.New("provider TLS peer rejected the connection")
)

type HTTPError struct {
	StatusCode        int
	Document          StandardError
	RetryAfterSeconds *int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("provider request rejected with status %d and code %s", e.StatusCode, e.Document.Code)
}

type Client struct {
	origin string
	http   *http.Client
	now    func() time.Time
}

func NewClient(origin string, transport http.RoundTripper) (*Client, error) {
	if !validProviderOrigin(origin) {
		return nil, ErrInvalidOrigin
	}
	if transport == nil {
		return nil, ErrMissingTransport
	}
	return &Client{
		origin: origin,
		now:    time.Now,
		http: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrUnexpectedStatus
			},
		},
	}, nil
}

func (c *Client) DiscoverCapabilities(ctx context.Context) (ProviderCapabilities, error) {
	document, _, err := c.DiscoverCapabilitiesDocument(ctx)
	return document, err
}

// DiscoverCapabilitiesDocument returns an independent copy of the exact
// bounded response body alongside the strictly decoded document. Callers use
// the raw bytes for cross-controller equality and durable digest binding.
func (c *Client) DiscoverCapabilitiesDocument(ctx context.Context) (ProviderCapabilities, []byte, error) {
	request, err := c.newRequest(ctx, http.MethodGet, "/v1/capabilities", nil, nil)
	if err != nil {
		return ProviderCapabilities{}, nil, err
	}
	response, err := c.do(request, http.StatusOK, statusSet(400, 401, 403, 500, 501, 503))
	if err != nil {
		return ProviderCapabilities{}, nil, err
	}
	var document ProviderCapabilities
	if err := decodeCapabilities(response, &document); err != nil {
		return ProviderCapabilities{}, nil, err
	}
	return document, append([]byte(nil), response...), nil
}

func (c *Client) CreateSandbox(ctx context.Context, requestDocument CreateSandboxRequest, admission Admission) (ProviderOperation, error) {
	bound, err := BindCreateRequest(requestDocument)
	if err != nil || bound.RequestDigest != requestDocument.RequestDigest {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	if err := validateCreateAdmission(bound, admission); err != nil {
		return ProviderOperation{}, err
	}
	body, err := marshalJSON(bound)
	if err != nil || len(body) > maxCreateBodyBytes {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	request, err := c.newRequest(ctx, http.MethodPost, "/v1/sandboxes", body, &admission)
	if err != nil {
		return ProviderOperation{}, err
	}
	response, err := c.do(request, http.StatusAccepted, statusSet(400, 401, 403, 409, 422, 429, 503))
	if err != nil {
		return ProviderOperation{}, err
	}
	var operation ProviderOperation
	if err := decodeProviderOperation(response, &operation); err != nil {
		return ProviderOperation{}, err
	}
	if operation.OperationID != bound.OperationID || operation.AttemptID != bound.AttemptID || operation.FencingToken != bound.FencingToken || operation.SandboxID != bound.Spec.SandboxID || operation.Type != "create" || operation.Status != "accepted" {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	return operation, nil
}

func (c *Client) GetSandboxStatus(ctx context.Context, descriptor ReadDescriptor, admission Admission) (SandboxStatus, error) {
	if descriptor.Operation != "read_sandbox" {
		return SandboxStatus{}, ErrInvalidContractDocument
	}
	path := "/v1/sandboxes/" + descriptor.SandboxID
	if err := validateReadAdmission(descriptor, admission, StatusDescriptorContractID, path); err != nil {
		return SandboxStatus{}, err
	}
	request, err := c.newRequest(ctx, http.MethodGet, path, nil, &admission)
	if err != nil {
		return SandboxStatus{}, err
	}
	response, err := c.do(request, http.StatusOK, statusSet(400, 401, 403, 404, 503))
	if err != nil {
		return SandboxStatus{}, err
	}
	var status SandboxStatus
	if err := decodeSandboxStatus(response, &status); err != nil {
		return SandboxStatus{}, err
	}
	if status.SandboxID != descriptor.SandboxID || status.TenantID != admission.Context.TenantID || status.WorkOrderID != admission.Context.WorkOrderID || status.ProviderRevisionID != admission.Context.ProviderRevisionID {
		return SandboxStatus{}, ErrInvalidContractDocument
	}
	return status, nil
}

func (c *Client) GetOperation(ctx context.Context, descriptor ReadDescriptor, admission Admission) (ProviderOperation, error) {
	if descriptor.Operation != "read_operation" {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	path := "/v1/operations/" + descriptor.OperationID
	if err := validateReadAdmission(descriptor, admission, OperationDescriptorContractID, path); err != nil {
		return ProviderOperation{}, err
	}
	request, err := c.newRequest(ctx, http.MethodGet, path, nil, &admission)
	if err != nil {
		return ProviderOperation{}, err
	}
	response, err := c.do(request, http.StatusOK, statusSet(400, 401, 403, 404, 410, 503))
	if err != nil {
		return ProviderOperation{}, err
	}
	var operation ProviderOperation
	if err := decodeProviderOperation(response, &operation); err != nil {
		return ProviderOperation{}, err
	}
	if operation.OperationID != descriptor.OperationID || operation.AttemptID != descriptor.AttemptID || operation.FencingToken != descriptor.FencingToken || operation.SandboxID != descriptor.SandboxID {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	return operation, nil
}

func (c *Client) CreateExec(ctx context.Context, sandboxID string, requestDocument ExecRequest, admission Admission) (ProviderOperation, error) {
	bound, err := BindExecRequest(requestDocument)
	if err != nil || bound.RequestDigest != requestDocument.RequestDigest {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	if err := validateMutationAdmission(bound.OperationID, bound.AttemptID, bound.FencingToken, bound.RequestDigest, bound.DeadlineAt, sandboxID, admission, "exec", ExecRequestContractID, "/v1/sandboxes/"+sandboxID+"/exec"); err != nil {
		return ProviderOperation{}, err
	}
	body, err := marshalJSON(bound)
	if err != nil || len(body) > 262144 {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	request, err := c.newRequest(ctx, http.MethodPost, "/v1/sandboxes/"+sandboxID+"/exec", body, &admission)
	if err != nil {
		return ProviderOperation{}, err
	}
	response, err := c.do(request, http.StatusAccepted, statusSet(400, 401, 403, 409, 422, 429, 503))
	if err != nil {
		return ProviderOperation{}, err
	}
	var operation ProviderOperation
	if err := decodeProviderOperation(response, &operation); err != nil {
		return ProviderOperation{}, err
	}
	if operation.OperationID != bound.OperationID || operation.AttemptID != bound.AttemptID || operation.FencingToken != bound.FencingToken || operation.SandboxID != admission.Context.SandboxID || operation.Type != "exec" || operation.Status != "accepted" {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	return operation, nil
}

func (c *Client) GetExecResult(ctx context.Context, descriptor ReadDescriptor, admission Admission) (ExecResult, error) {
	if descriptor.Operation != "read_result" || validateReadAdmission(descriptor, admission, ExecResultDescriptorContractID, "/v1/operations/"+descriptor.OperationID+"/exec-result") != nil {
		return ExecResult{}, ErrAdmissionBinding
	}
	request, err := c.newRequest(ctx, http.MethodGet, "/v1/operations/"+descriptor.OperationID+"/exec-result", nil, &admission)
	if err != nil {
		return ExecResult{}, err
	}
	response, err := c.do(request, http.StatusOK, statusSet(400, 401, 403, 404, 410, 503))
	if err != nil {
		return ExecResult{}, err
	}
	var result ExecResult
	if err := decodeExecResult(response, &result); err != nil {
		return ExecResult{}, err
	}
	if result.OperationID != descriptor.OperationID || result.AttemptID != descriptor.AttemptID || result.FencingToken != descriptor.FencingToken || result.SandboxID != descriptor.SandboxID {
		return ExecResult{}, ErrInvalidContractDocument
	}
	return result, nil
}

func (c *Client) OpenRuntimeSession(ctx context.Context, sandboxID string, requestDocument RuntimeSessionOpenRequest, admission Admission) (ProviderOperation, error) {
	bound, err := BindRuntimeSessionOpenRequest(requestDocument)
	if err != nil || bound.RequestDigest != requestDocument.RequestDigest {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	if err := validateMutationAdmission(bound.OperationID, bound.AttemptID, bound.FencingToken, bound.RequestDigest, bound.DeadlineAt, sandboxID, admission, "open_runtime_session", RuntimeSessionRequestContractID, "/v1/sandboxes/"+sandboxID+"/runtime-sessions"); err != nil {
		return ProviderOperation{}, err
	}
	body, err := marshalJSON(bound)
	if err != nil || len(body) > 65536 {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	request, err := c.newRequest(ctx, http.MethodPost, "/v1/sandboxes/"+sandboxID+"/runtime-sessions", body, &admission)
	if err != nil {
		return ProviderOperation{}, err
	}
	response, err := c.do(request, http.StatusAccepted, statusSet(400, 401, 403, 409, 422, 429, 503))
	if err != nil {
		return ProviderOperation{}, err
	}
	var operation ProviderOperation
	if err := decodeProviderOperation(response, &operation); err != nil {
		return ProviderOperation{}, err
	}
	if operation.OperationID != bound.OperationID || operation.AttemptID != bound.AttemptID || operation.FencingToken != bound.FencingToken || operation.SandboxID != admission.Context.SandboxID || operation.Type != "open_runtime_session" || operation.Status != "accepted" {
		return ProviderOperation{}, ErrInvalidContractDocument
	}
	return operation, nil
}

func validateMutationAdmission(operationID, attemptID string, fencing int64, digest, deadline, sandboxID string, admission Admission, operation, contractID, path string) error {
	if validateAdmissionEnvelope(admission) != nil {
		return ErrAdmissionBinding
	}
	c := admission.Context
	if c.SandboxID != sandboxID || c.DeadlineAt != deadline || c.Operation != operation || c.OperationID != operationID || c.AttemptID != attemptID || c.FencingToken != fencing || c.RequestContractID != contractID || c.RequestDigestProfile != MutationDigestProfile || c.RequestDigest != digest || c.HTTPTarget.Method != http.MethodPost || c.HTTPTarget.Path != path {
		return ErrAdmissionBinding
	}
	return nil
}

func (c *Client) GetRuntimeSessionHandoff(ctx context.Context, descriptor ReadDescriptor, admission Admission) (RuntimeSessionHandoff, error) {
	if descriptor.Operation != "read_runtime_session" || validateReadAdmission(descriptor, admission, SessionDescriptorContractID, "/v1/operations/"+descriptor.OperationID+"/runtime-session") != nil {
		return RuntimeSessionHandoff{}, ErrAdmissionBinding
	}
	request, err := c.newRequest(ctx, http.MethodGet, "/v1/operations/"+descriptor.OperationID+"/runtime-session", nil, &admission)
	if err != nil {
		return RuntimeSessionHandoff{}, err
	}
	response, err := c.do(request, http.StatusOK, statusSet(400, 401, 403, 404, 410, 503))
	if err != nil {
		return RuntimeSessionHandoff{}, err
	}
	var handoff RuntimeSessionHandoff
	if err := decodeRuntimeSessionHandoff(response, &handoff); err != nil {
		return RuntimeSessionHandoff{}, err
	}
	if handoff.OperationID != descriptor.OperationID || handoff.AttemptID != descriptor.AttemptID || handoff.FencingToken != descriptor.FencingToken || handoff.SandboxID != descriptor.SandboxID {
		return RuntimeSessionHandoff{}, ErrInvalidContractDocument
	}
	return handoff, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body []byte, admission *Admission) (*http.Request, error) {
	if ctx == nil {
		return nil, ErrTransport
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.origin+path, reader)
	if err != nil {
		return nil, ErrTransport
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len(body))
	}
	if admission != nil {
		if err := validateAdmissionAt(*admission, c.now()); err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+admission.BearerToken)
		request.Header.Set(AdmissionHeaderName, admission.ContextHeader)
	}
	return request, nil
}

func validateAdmissionAt(admission Admission, now time.Time) error {
	deadline, err := time.Parse(time.RFC3339Nano, admission.Context.DeadlineAt)
	if err != nil || now.Unix() < admission.Claims.NotBefore || now.Unix() >= admission.Claims.ExpiresAt || !now.Before(deadline) {
		return ErrAdmissionBinding
	}
	return nil
}

func (c *Client) do(request *http.Request, successStatus int, errorStatuses map[int]struct{}) ([]byte, error) {
	response, err := c.http.Do(request)
	if err != nil {
		var alert tls.AlertError
		if errors.As(err, &alert) {
			return nil, ErrTLSRejected
		}
		return nil, ErrTransport
	}
	if response == nil || response.Body == nil {
		return nil, ErrTransport
	}
	defer response.Body.Close()
	document, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if len(document) > maxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	if err != nil {
		return nil, ErrTransport
	}
	if response.StatusCode == successStatus {
		if !isJSONMediaType(response.Header.Values("Content-Type")) {
			return nil, ErrContentType
		}
		return document, nil
	}
	if _, allowed := errorStatuses[response.StatusCode]; !allowed {
		return nil, ErrUnexpectedStatus
	}
	if !isJSONMediaType(response.Header.Values("Content-Type")) {
		return nil, ErrContentType
	}
	var standardError StandardError
	if err := decodeStandardError(document, &standardError); err != nil {
		return nil, err
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return nil, ErrInvalidContractDocument
	}
	return nil, &HTTPError{StatusCode: response.StatusCode, Document: standardError, RetryAfterSeconds: retryAfter}
}

func validateCreateAdmission(request CreateSandboxRequest, admission Admission) error {
	if err := validateAdmissionEnvelope(admission); err != nil {
		return err
	}
	context := admission.Context
	if context.Operation != "create" || context.SandboxID != request.Spec.SandboxID || context.OperationID != request.OperationID || context.AttemptID != request.AttemptID || context.FencingToken != request.FencingToken ||
		context.TenantID != request.Spec.TenantID || context.WorkOrderID != request.Spec.WorkOrderID || context.ProviderRevisionID != request.Spec.ProviderRevisionID || context.DeadlineAt != request.DeadlineAt ||
		context.RequestContractID != CreateRequestContractID || context.RequestDigestProfile != MutationDigestProfile || context.RequestDigest != request.RequestDigest || context.HTTPTarget.Method != http.MethodPost || context.HTTPTarget.Path != "/v1/sandboxes" {
		return ErrAdmissionBinding
	}
	return nil
}

func validateReadAdmission(descriptor ReadDescriptor, admission Admission, contractID, path string) error {
	digest, err := DigestReadDescriptor(descriptor)
	if err != nil || validateAdmissionEnvelope(admission) != nil {
		return ErrAdmissionBinding
	}
	context := admission.Context
	if context.Operation != descriptor.Operation || context.SandboxID != descriptor.SandboxID || context.OperationID != descriptor.OperationID || context.AttemptID != descriptor.AttemptID || context.FencingToken != descriptor.FencingToken ||
		context.RequestContractID != contractID || context.RequestDigestProfile != DescriptorDigestProfile || context.RequestDigest != digest || context.HTTPTarget.Method != http.MethodGet || context.HTTPTarget.Path != path {
		return ErrAdmissionBinding
	}
	return nil
}

func validateAdmissionEnvelope(admission Admission) error {
	if len(admission.BearerToken) == 0 || len(admission.BearerToken) > maxBearerBytes || len(admission.ContextHeader) == 0 || len(admission.ContextHeader) > maxAdmissionContextBytes || strings.Contains(admission.ContextHeader, "=") {
		return ErrAdmissionBinding
	}
	contextDigest, err := jcs.DigestExcluding(admission.Context, "context_digest")
	if err != nil || admission.Context.ContextContractID != AdmissionContextContractID || admission.Context.ContextDigestProfile != AdmissionContextDigestProfile || contextDigest != admission.Context.ContextDigest || validateAdmissionAuthority(AdmissionAuthority{
		Issuer: admission.Claims.Issuer, ControllerSubject: admission.Context.ControllerSubject, ProviderInstanceAudience: admission.Context.ProviderInstanceAudience, ProviderRevisionID: admission.Context.ProviderRevisionID,
	}) != nil {
		return ErrAdmissionBinding
	}
	contextDocument, err := jcs.Marshal(admission.Context)
	if err != nil || base64.RawURLEncoding.EncodeToString(contextDocument) != admission.ContextHeader {
		return ErrAdmissionBinding
	}
	if admission.Claims.Subject != admission.Context.ControllerSubject || admission.Claims.Audience != admission.Context.ProviderInstanceAudience || admission.Claims.ProviderRevisionID != admission.Context.ProviderRevisionID || admission.Claims.Operation != admission.Context.Operation ||
		admission.Claims.SandboxID != admission.Context.SandboxID || admission.Claims.OperationID != admission.Context.OperationID || admission.Claims.AttemptID != admission.Context.AttemptID || admission.Claims.FencingToken != admission.Context.FencingToken ||
		admission.Claims.TenantID != admission.Context.TenantID || admission.Claims.WorkOrderID != admission.Context.WorkOrderID || admission.Claims.PolicyDigest != admission.Context.PolicyDigest || admission.Claims.PolicyDecidedAt != admission.Context.PolicyDecidedAt ||
		admission.Claims.RequestContractID != admission.Context.RequestContractID || admission.Claims.RequestDigestProfile != admission.Context.RequestDigestProfile || admission.Claims.RequestDigest != admission.Context.RequestDigest || admission.Claims.DeadlineAt != admission.Context.DeadlineAt ||
		admission.Claims.AdmissionContextContractID != AdmissionContextContractID || admission.Claims.AdmissionContextDigestProfile != AdmissionContextDigestProfile || admission.Claims.AdmissionContextDigest != admission.Context.ContextDigest {
		return ErrAdmissionBinding
	}
	if validateAdmissionBinding(AdmissionBinding{
		JTI: admission.Claims.JTI, IssuedAt: time.Unix(admission.Claims.IssuedAt, 0), NotBefore: time.Unix(admission.Claims.NotBefore, 0), ExpiresAt: time.Unix(admission.Claims.ExpiresAt, 0),
		TenantID: admission.Context.TenantID, WorkOrderID: admission.Context.WorkOrderID, PolicyDigest: admission.Context.PolicyDigest, PolicyDecidedAt: admission.Context.PolicyDecidedAt,
		Operation: admission.Context.Operation, SandboxID: admission.Context.SandboxID, OperationID: admission.Context.OperationID, AttemptID: admission.Context.AttemptID,
		FencingToken: admission.Context.FencingToken, DeadlineAt: admission.Context.DeadlineAt, RequestContractID: admission.Context.RequestContractID,
		RequestDigestProfile: admission.Context.RequestDigestProfile, RequestDigest: admission.Context.RequestDigest, HTTPTarget: admission.Context.HTTPTarget,
	}) != nil {
		return ErrAdmissionBinding
	}
	headerDocument, err := jcs.Marshal(admission.Header)
	if err != nil || !oneOf(admission.Header.Algorithm, "EdDSA", "ES256") || !boundedString(admission.Header.KeyID, 1, 128) || admission.Header.Type != JWSHeaderType {
		return ErrAdmissionBinding
	}
	claimsDocument, err := jcs.Marshal(admission.Claims)
	if err != nil {
		return ErrAdmissionBinding
	}
	parts := strings.Split(admission.BearerToken, ".")
	if len(parts) != 3 || parts[0] != base64.RawURLEncoding.EncodeToString(headerDocument) || parts[1] != base64.RawURLEncoding.EncodeToString(claimsDocument) || strings.Contains(parts[2], "=") {
		return ErrAdmissionBinding
	}
	if signature, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != parts[2] {
		return ErrAdmissionBinding
	}
	return nil
}

func decodeCapabilities(document []byte, target *ProviderCapabilities) error {
	object, err := decodeStrict(document, target,
		[]string{"provider_revision_id", "api_version", "capabilities", "runtime_profiles", "snapshot_restore_profiles", "limits"}, nil)
	if err != nil {
		return err
	}
	if !arrayObjectShape(object["capabilities"], []string{"id", "versions"}, []string{"profiles"}) || !arrayObjectShape(object["runtime_profiles"], []string{"id", "isolation_class"}, []string{"runtime_class_name", "architecture", "capability_profile_ids"}) ||
		!arrayObjectShape(object["snapshot_restore_profiles"], []string{"profile_id", "level", "suite_id", "suite_version", "suite_digest"}, nil) || !objectShape(object["limits"], []string{"max_cpu_millis", "max_memory_bytes", "max_ephemeral_storage_bytes", "max_lease_seconds", "max_exec_seconds"}, []string{"max_workspace_bytes", "max_gpu_count"}) {
		return ErrInvalidContractDocument
	}
	var runtimeProfiles []map[string]json.RawMessage
	if json.Unmarshal(object["runtime_profiles"], &runtimeProfiles) != nil {
		return ErrInvalidContractDocument
	}
	for _, profile := range runtimeProfiles {
		if raw, present := profile["capability_profile_ids"]; present {
			var values []string
			if json.Unmarshal(raw, &values) != nil || len(values) < 1 {
				return ErrInvalidContractDocument
			}
		}
	}
	return validateCapabilities(*target)
}

func decodeProviderOperation(document []byte, target *ProviderOperation) error {
	object, err := decodeStrict(document, target,
		[]string{"operation_id", "attempt_id", "fencing_token", "sandbox_id", "type", "status", "observed_at"},
		[]string{"provider_operation_id", "result_reference", "error"})
	if err != nil {
		return err
	}
	if raw, ok := object["error"]; ok && !objectShape(raw, []string{"code", "message", "retryable", "outcome"}, []string{"provider_code", "details"}) {
		return ErrInvalidContractDocument
	}
	return validateProviderOperation(*target)
}

func decodeSandboxStatus(document []byte, target *SandboxStatus) error {
	object, err := decodeStrict(document, target,
		[]string{"sandbox_id", "tenant_id", "work_order_id", "workspace_id", "provider_revision_id", "desired_state", "observed_state", "generation", "observed_generation", "lease_expires_at", "created_at", "updated_at", "sandbox_slot_key"},
		[]string{"runtime_profile", "runtime_endpoint_reference", "snapshot_reference", "last_error", "agent_run_id", "provider_state_reference"})
	if err != nil {
		return err
	}
	if raw, ok := object["last_error"]; ok && !objectShape(raw, []string{"code", "message", "retryable", "outcome"}, []string{"provider_code", "details"}) {
		return ErrInvalidContractDocument
	}
	return validateSandboxStatus(*target)
}

func decodeExecResult(document []byte, target *ExecResult) error {
	object, err := decodeStrict(document, target, []string{"operation_id", "attempt_id", "fencing_token", "sandbox_id", "status", "started_at", "completed_at", "retained_until"}, []string{"signal", "stdout_reference", "stderr_reference", "error"})
	if err != nil {
		return err
	}
	for _, name := range []string{"signal", "stdout_reference", "stderr_reference"} {
		if raw, present := object[name]; present && bytes.Equal(raw, []byte(`""`)) {
			return ErrInvalidContractDocument
		}
	}
	if raw, ok := object["error"]; ok && !objectShape(raw, []string{"code", "message", "retryable", "outcome"}, []string{"provider_code", "details"}) {
		return ErrInvalidContractDocument
	}
	return validateExecResult(*target)
}

func decodeRuntimeSessionHandoff(document []byte, target *RuntimeSessionHandoff) error {
	if _, err := decodeStrict(document, target, []string{"operation_id", "attempt_id", "fencing_token", "sandbox_id", "runtime_session_id", "runtime_type", "capability_profile_id", "protocol", "internal_endpoint_reference", "connection_generation", "expires_at"}, nil); err != nil {
		return err
	}
	return validateRuntimeSessionHandoff(*target)
}

func decodeStandardError(document []byte, target *StandardError) error {
	if _, err := decodeStrict(document, target, []string{"code", "message", "retryable", "trace_id"}, nil); err != nil {
		return err
	}
	return validateStandardError(*target)
}

func arrayObjectShape(document json.RawMessage, required, nonNullOptional []string) bool {
	var items []json.RawMessage
	if json.Unmarshal(document, &items) != nil || items == nil {
		return false
	}
	for _, item := range items {
		if !objectShape(item, required, nonNullOptional) {
			return false
		}
	}
	return true
}

func objectShape(document json.RawMessage, required, nonNullOptional []string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(document, &object) != nil || object == nil {
		return false
	}
	for _, key := range required {
		if value, ok := object[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	for _, key := range nonNullOptional {
		if value, ok := object[key]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func isJSONMediaType(values []string) bool {
	if len(values) != 1 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	return err == nil && mediaType == "application/json"
}

func parseRetryAfter(values []string) (*int, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, ErrInvalidContractDocument
	}
	value, err := strconv.Atoi(values[0])
	if err != nil || value < 1 || strconv.Itoa(value) != values[0] {
		return nil, ErrInvalidContractDocument
	}
	return &value, nil
}

func statusSet(values ...int) map[int]struct{} {
	result := make(map[int]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func validProviderOrigin(value string) bool {
	if len(value) == 0 || len(value) > 2048 || !visibleASCII(value) || strings.ContainsAny(value, "%@?#\\") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	authority, ok := canonicalAuthority(parsed.Host)
	return ok && authority == parsed.Host && value == "https://"+authority
}

func canonicalAuthority(authority string) (string, bool) {
	host, port := authority, ""
	if strings.HasPrefix(authority, "[") {
		closing := strings.IndexByte(authority, ']')
		if closing < 0 {
			return "", false
		}
		host = authority[1:closing]
		remainder := authority[closing+1:]
		if remainder != "" {
			if !strings.HasPrefix(remainder, ":") || len(remainder) == 1 {
				return "", false
			}
			port = remainder[1:]
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() || address.Is4In6() || address.String() != host {
			return "", false
		}
		host = "[" + host + "]"
	} else {
		if strings.Count(authority, ":") > 1 {
			return "", false
		}
		if separator := strings.LastIndexByte(authority, ':'); separator >= 0 {
			host, port = authority[:separator], authority[separator+1:]
			if host == "" || port == "" {
				return "", false
			}
		}
		address, err := netip.ParseAddr(host)
		switch {
		case err == nil && address.Is4():
			if address.String() != host {
				return "", false
			}
		case err == nil:
			return "", false
		case !validDNSName(host):
			return "", false
		}
	}
	if port != "" {
		if len(port) > 1 && port[0] == '0' {
			return "", false
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || number == 443 || strconv.Itoa(number) != port {
			return "", false
		}
		return host + ":" + port, true
	}
	return host, true
}

func validDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 || host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return !whatwgIPv4Number(labels[len(labels)-1])
}

func whatwgIPv4Number(value string) bool {
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		if len(value) == 2 {
			return false
		}
		for _, character := range []byte(value[2:]) {
			if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
				return false
			}
		}
		return true
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
}

func visibleASCII(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
