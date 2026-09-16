package provider

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
)

const (
	CreateRequestContractID              = "urn:shell-echo:sandbox-runtime:request:create:v1"
	ExecRequestContractID                = "urn:shell-echo:sandbox-runtime:request:exec:v1"
	CancelExecRequestContractID          = "urn:shell-echo:sandbox-runtime:request:cancel-exec:v1"
	RuntimeSessionRequestContractID      = "urn:shell-echo:sandbox-runtime:request:open-runtime-session:v1"
	ArtifactStagingRequestContractID     = "urn:shell-echo:sandbox-runtime:request:stage-artifact:v1"
	StatusDescriptorContractID           = "urn:shell-echo:sandbox-runtime:descriptor:status:v1"
	OperationDescriptorContractID        = "urn:shell-echo:sandbox-runtime:descriptor:operation:v1"
	ExecResultDescriptorContractID       = "urn:shell-echo:sandbox-runtime:descriptor:exec-result:v1"
	UsageDescriptorContractID            = "urn:shell-echo:sandbox-runtime:descriptor:usage-evidence:v1"
	SessionDescriptorContractID          = "urn:shell-echo:sandbox-runtime:descriptor:runtime-session:v1"
	ArtifactEvidenceDescriptorContractID = "urn:shell-echo:sandbox-runtime:descriptor:artifact-staging-evidence:v1"
	MutationDigestProfile                = "rfc8785-request-excluding-request-digest-v1"
	DescriptorDigestProfile              = "rfc8785-full-document-v1"
	AdmissionContextContractID           = "urn:shell-echo:sandbox-runtime:admission-context:v1"
	AdmissionContextDigestProfile        = "rfc8785-full-document-excluding-context-digest-v1"
	AdmissionHeaderName                  = "X-Sandbox-Runtime-Admission-Context"
	JWSHeaderType                        = "agent-sandbox-operation-admission+jwt"
	maxAdmissionContextBytes             = 16384
	maxBearerBytes                       = 8192
)

var (
	audiencePattern   = regexp.MustCompile(`^urn:shell-echo:sandbox-runtime:provider-instance:[A-Za-z0-9._:-]{1,200}$`)
	targetPathPattern = regexp.MustCompile(`^/v1(?:/[A-Za-z0-9._:-]+)+$`)
)

type AdmissionTarget struct {
	Method          string           `json:"method"`
	Path            string           `json:"path"`
	NormalizedQuery []QueryParameter `json:"normalized_query"`
}

func BindExecRequest(request ExecRequest) (ExecRequest, error) {
	digest, err := jcs.DigestExcluding(request, "request_digest")
	if err != nil || request.RequestDigest != "" && request.RequestDigest != digest {
		return ExecRequest{}, ErrInvalidContractDocument
	}
	request.RequestDigest = digest
	if err := ValidateExecRequest(request); err != nil {
		return ExecRequest{}, err
	}
	return request, nil
}

func BindRuntimeSessionOpenRequest(request RuntimeSessionOpenRequest) (RuntimeSessionOpenRequest, error) {
	digest, err := jcs.DigestExcluding(request, "request_digest")
	if err != nil || request.RequestDigest != "" && request.RequestDigest != digest {
		return RuntimeSessionOpenRequest{}, ErrInvalidContractDocument
	}
	request.RequestDigest = digest
	if err := ValidateRuntimeSessionOpenRequest(request); err != nil {
		return RuntimeSessionOpenRequest{}, err
	}
	return request, nil
}

func BindArtifactStagingRequest(request ArtifactStagingRequest) (ArtifactStagingRequest, error) {
	digest, err := jcs.DigestExcluding(request, "request_digest")
	if err != nil || request.RequestDigest != "" && request.RequestDigest != digest {
		return ArtifactStagingRequest{}, ErrInvalidContractDocument
	}
	request.RequestDigest = digest
	if err := ValidateArtifactStagingRequest(request); err != nil {
		return ArtifactStagingRequest{}, err
	}
	return request, nil
}

type QueryParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type AdmissionContext struct {
	ContextContractID        string          `json:"context_contract_id"`
	ContextDigestProfile     string          `json:"context_digest_profile"`
	ContextDigest            string          `json:"context_digest"`
	ControllerSubject        string          `json:"controller_subject"`
	ProviderRevisionID       string          `json:"provider_revision_id"`
	ProviderInstanceAudience string          `json:"provider_instance_audience"`
	TenantID                 string          `json:"tenant_id"`
	WorkOrderID              string          `json:"work_order_id"`
	PolicyDigest             string          `json:"policy_digest"`
	PolicyDecidedAt          string          `json:"policy_decided_at"`
	Operation                string          `json:"operation"`
	SandboxID                string          `json:"sandbox_id"`
	OperationID              string          `json:"operation_id"`
	AttemptID                string          `json:"attempt_id"`
	FencingToken             int64           `json:"fencing_token"`
	DeadlineAt               string          `json:"deadline_at"`
	RequestContractID        string          `json:"request_contract_id"`
	RequestDigestProfile     string          `json:"request_digest_profile"`
	RequestDigest            string          `json:"request_digest"`
	HTTPTarget               AdmissionTarget `json:"http_target"`
}

type JWSHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type JWSClaims struct {
	JTI                           string `json:"jti"`
	Issuer                        string `json:"iss"`
	Subject                       string `json:"sub"`
	Audience                      string `json:"aud"`
	IssuedAt                      int64  `json:"iat"`
	NotBefore                     int64  `json:"nbf"`
	ExpiresAt                     int64  `json:"exp"`
	Operation                     string `json:"operation"`
	ProviderRevisionID            string `json:"provider_revision_id"`
	SandboxID                     string `json:"sandbox_id"`
	OperationID                   string `json:"operation_id"`
	AttemptID                     string `json:"attempt_id"`
	FencingToken                  int64  `json:"fencing_token"`
	TenantID                      string `json:"tenant_id"`
	WorkOrderID                   string `json:"work_order_id"`
	PolicyDigest                  string `json:"policy_digest"`
	PolicyDecidedAt               string `json:"policy_decided_at"`
	RequestContractID             string `json:"request_contract_id"`
	RequestDigestProfile          string `json:"request_digest_profile"`
	RequestDigest                 string `json:"request_digest"`
	DeadlineAt                    string `json:"deadline_at"`
	AdmissionContextContractID    string `json:"admission_context_contract_id"`
	AdmissionContextDigestProfile string `json:"admission_context_digest_profile"`
	AdmissionContextDigest        string `json:"admission_context_digest"`
}

type AdmissionAuthority struct {
	Issuer                   string
	ControllerSubject        string
	ProviderInstanceAudience string
	ProviderRevisionID       string
}

type AdmissionBinding struct {
	JTI                  string
	IssuedAt             time.Time
	NotBefore            time.Time
	ExpiresAt            time.Time
	TenantID             string
	WorkOrderID          string
	PolicyDigest         string
	PolicyDecidedAt      string
	Operation            string
	SandboxID            string
	OperationID          string
	AttemptID            string
	FencingToken         int64
	DeadlineAt           string
	RequestContractID    string
	RequestDigestProfile string
	RequestDigest        string
	HTTPTarget           AdmissionTarget
}

type Admission struct {
	BearerToken   string
	ContextHeader string
	Context       AdmissionContext
	Claims        JWSClaims
	Header        JWSHeader
}

type Signer interface {
	Algorithm() string
	KeyID() string
	Sign([]byte) ([]byte, error)
}

type Ed25519Signer struct {
	keyID string
	key   ed25519.PrivateKey
}

func NewEd25519Signer(keyID string, privateKey ed25519.PrivateKey) (*Ed25519Signer, error) {
	if !boundedString(keyID, 1, 128) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrSigning
	}
	key := append(ed25519.PrivateKey(nil), privateKey...)
	return &Ed25519Signer{keyID: keyID, key: key}, nil
}

func (s *Ed25519Signer) Algorithm() string { return "EdDSA" }
func (s *Ed25519Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

func (s *Ed25519Signer) Sign(input []byte) ([]byte, error) {
	if s == nil || len(s.key) != ed25519.PrivateKeySize {
		return nil, ErrSigning
	}
	return ed25519.Sign(s.key, input), nil
}

// Destroy clears the caller-owned signing key on a best-effort basis. Process
// exit remains the hard lifetime boundary for Go-managed memory.
func (s *Ed25519Signer) Destroy() {
	if s == nil {
		return
	}
	clear(s.key)
	s.key = nil
	s.keyID = ""
}

func BindCreateRequest(request CreateSandboxRequest) (CreateSandboxRequest, error) {
	digest, err := jcs.DigestExcluding(request, "request_digest")
	if err != nil {
		return CreateSandboxRequest{}, ErrInvalidContractDocument
	}
	if request.RequestDigest != "" && request.RequestDigest != digest {
		return CreateSandboxRequest{}, ErrInvalidContractDocument
	}
	request.RequestDigest = digest
	if err := ValidateCreateRequest(request); err != nil {
		return CreateSandboxRequest{}, err
	}
	return request, nil
}

func DigestReadDescriptor(descriptor ReadDescriptor) (string, error) {
	_, digestProfile, ok := operationBinding(descriptor.Operation)
	if !ok || digestProfile != DescriptorDigestProfile || !identifierPattern.MatchString(descriptor.SandboxID) || !identifierPattern.MatchString(descriptor.OperationID) || !identifierPattern.MatchString(descriptor.AttemptID) || descriptor.FencingToken < 1 || descriptor.FencingToken > maxSafeInteger {
		return "", ErrInvalidContractDocument
	}
	digest, err := jcs.Digest(descriptor)
	if err != nil {
		return "", ErrInvalidContractDocument
	}
	return digest, nil
}

func BuildAdmission(authority AdmissionAuthority, binding AdmissionBinding, signer Signer) (Admission, error) {
	if signer == nil {
		return Admission{}, ErrAdmissionBinding
	}
	algorithm, keyID := signer.Algorithm(), signer.KeyID()
	if !oneOf(algorithm, "EdDSA", "ES256") || !boundedString(keyID, 1, 128) || validateAdmissionAuthority(authority) != nil || validateAdmissionBinding(binding) != nil {
		return Admission{}, ErrAdmissionBinding
	}
	target := binding.HTTPTarget
	target.NormalizedQuery = make([]QueryParameter, len(binding.HTTPTarget.NormalizedQuery))
	copy(target.NormalizedQuery, binding.HTTPTarget.NormalizedQuery)
	context := AdmissionContext{
		ContextContractID: AdmissionContextContractID, ContextDigestProfile: AdmissionContextDigestProfile,
		ControllerSubject: authority.ControllerSubject, ProviderRevisionID: authority.ProviderRevisionID, ProviderInstanceAudience: authority.ProviderInstanceAudience,
		TenantID: binding.TenantID, WorkOrderID: binding.WorkOrderID, PolicyDigest: binding.PolicyDigest, PolicyDecidedAt: binding.PolicyDecidedAt,
		Operation: binding.Operation, SandboxID: binding.SandboxID, OperationID: binding.OperationID, AttemptID: binding.AttemptID, FencingToken: binding.FencingToken,
		DeadlineAt: binding.DeadlineAt, RequestContractID: binding.RequestContractID, RequestDigestProfile: binding.RequestDigestProfile, RequestDigest: binding.RequestDigest, HTTPTarget: target,
	}
	contextDigest, err := jcs.DigestExcluding(context, "context_digest")
	if err != nil {
		return Admission{}, ErrAdmissionBinding
	}
	context.ContextDigest = contextDigest
	contextDocument, err := jcs.Marshal(context)
	if err != nil || len(contextDocument) > maxAdmissionContextBytes {
		return Admission{}, ErrAdmissionBinding
	}
	contextHeader := base64.RawURLEncoding.EncodeToString(contextDocument)
	if len(contextHeader) == 0 || len(contextHeader) > maxAdmissionContextBytes || strings.Contains(contextHeader, "=") {
		return Admission{}, ErrAdmissionBinding
	}

	claims := JWSClaims{
		JTI: binding.JTI, Issuer: authority.Issuer, Subject: authority.ControllerSubject, Audience: authority.ProviderInstanceAudience,
		IssuedAt: binding.IssuedAt.Unix(), NotBefore: binding.NotBefore.Unix(), ExpiresAt: binding.ExpiresAt.Unix(), Operation: binding.Operation,
		ProviderRevisionID: authority.ProviderRevisionID, SandboxID: binding.SandboxID, OperationID: binding.OperationID, AttemptID: binding.AttemptID,
		FencingToken: binding.FencingToken, TenantID: binding.TenantID, WorkOrderID: binding.WorkOrderID, PolicyDigest: binding.PolicyDigest, PolicyDecidedAt: binding.PolicyDecidedAt,
		RequestContractID: binding.RequestContractID, RequestDigestProfile: binding.RequestDigestProfile, RequestDigest: binding.RequestDigest, DeadlineAt: binding.DeadlineAt,
		AdmissionContextContractID: AdmissionContextContractID, AdmissionContextDigestProfile: AdmissionContextDigestProfile, AdmissionContextDigest: contextDigest,
	}
	header := JWSHeader{Algorithm: algorithm, KeyID: keyID, Type: JWSHeaderType}
	headerDocument, err := jcs.Marshal(header)
	if err != nil {
		return Admission{}, ErrSigning
	}
	claimsDocument, err := jcs.Marshal(claims)
	if err != nil {
		return Admission{}, ErrSigning
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerDocument)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsDocument)
	signingInput := encodedHeader + "." + encodedClaims
	signature, err := signer.Sign([]byte(signingInput))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Admission{}, ErrSigning
	}
	bearer := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(bearer) > maxBearerBytes {
		return Admission{}, ErrSigning
	}
	return Admission{BearerToken: bearer, ContextHeader: contextHeader, Context: context, Claims: claims, Header: header}, nil
}

func validateAdmissionAuthority(authority AdmissionAuthority) error {
	if !boundedString(authority.Issuer, 1, 200) || !validAbsoluteURI(authority.ControllerSubject) || !audiencePattern.MatchString(authority.ProviderInstanceAudience) || !boundedString(authority.ProviderRevisionID, 1, 200) {
		return ErrAdmissionBinding
	}
	if strings.Contains(authority.Issuer, ":") {
		parsed, err := url.Parse(authority.Issuer)
		if err != nil || !parsed.IsAbs() || parsed.Fragment != "" {
			return ErrAdmissionBinding
		}
	}
	return nil
}

func validAbsoluteURI(value string) bool {
	if !boundedString(value, 1, 200) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Fragment == ""
}

func validateAdmissionBinding(binding AdmissionBinding) error {
	if !boundedString(binding.JTI, 16, 200) || binding.IssuedAt.IsZero() || binding.NotBefore.IsZero() || binding.ExpiresAt.IsZero() || binding.IssuedAt.Unix() < 0 || binding.NotBefore.Before(binding.IssuedAt) || !binding.ExpiresAt.After(binding.NotBefore) || binding.ExpiresAt.Sub(binding.IssuedAt) > 300*time.Second ||
		!identifierPattern.MatchString(binding.TenantID) || !identifierPattern.MatchString(binding.WorkOrderID) || !digestPattern.MatchString(binding.PolicyDigest) || !validDateTime(binding.PolicyDecidedAt) ||
		!identifierPattern.MatchString(binding.SandboxID) || !identifierPattern.MatchString(binding.OperationID) || !identifierPattern.MatchString(binding.AttemptID) || binding.FencingToken < 1 || binding.FencingToken > maxSafeInteger || !validDateTime(binding.DeadlineAt) ||
		!digestPattern.MatchString(binding.RequestDigest) || !validAdmissionTarget(binding.HTTPTarget) {
		return ErrAdmissionBinding
	}
	contractID, digestProfile, ok := operationBinding(binding.Operation)
	if !ok || binding.RequestContractID != contractID || binding.RequestDigestProfile != digestProfile || !targetMatchesOperation(binding.Operation, binding.SandboxID, binding.OperationID, binding.HTTPTarget) {
		return ErrAdmissionBinding
	}
	return nil
}

func validAdmissionTarget(target AdmissionTarget) bool {
	if !oneOf(target.Method, "GET", "POST") || len(target.Path) > 600 || !targetPathPattern.MatchString(target.Path) || target.NormalizedQuery == nil || len(target.NormalizedQuery) > 4 {
		return false
	}
	for _, parameter := range target.NormalizedQuery {
		if parameter.Name == "" || parameter.Value == "" {
			return false
		}
	}
	return true
}

func operationBinding(operation string) (string, string, bool) {
	mutation := map[string]string{
		"create": "create", "restore": "restore", "set_desired_state": "set-desired-state", "extend_lease": "extend-lease", "exec": "exec", "cancel_exec": "cancel-exec",
		"open_runtime_session": "open-runtime-session", "open_browser_session": "open-browser-session", "stage_artifact": "stage-artifact", "snapshot": "snapshot", "terminate": "terminate",
	}
	if name, ok := mutation[operation]; ok {
		return "urn:shell-echo:sandbox-runtime:request:" + name + ":v1", MutationDigestProfile, true
	}
	read := map[string]string{
		"read_sandbox": "status", "read_operation": "operation", "read_result": "exec-result", "read_runtime_session": "runtime-session", "read_browser_session": "browser-session",
		"read_artifact_staging_evidence": "artifact-staging-evidence", "read_usage_evidence": "usage-evidence", "read_snapshot_manifest": "snapshot-manifest", "read_events": "events",
	}
	if operation == "connect_runtime_session" {
		return RuntimeSessionConnectDescriptorContractID, DescriptorDigestProfile, true
	}
	if name, ok := read[operation]; ok {
		return "urn:shell-echo:sandbox-runtime:descriptor:" + name + ":v1", DescriptorDigestProfile, true
	}
	return "", "", false
}

func targetMatchesOperation(operation, sandboxID, operationID string, target AdmissionTarget) bool {
	if len(target.NormalizedQuery) != 0 {
		return false
	}
	wantMethod, wantPath := "", ""
	switch operation {
	case "create":
		wantMethod, wantPath = "POST", "/v1/sandboxes"
	case "read_sandbox":
		wantMethod, wantPath = "GET", "/v1/sandboxes/"+sandboxID
	case "exec":
		wantMethod, wantPath = "POST", "/v1/sandboxes/"+sandboxID+"/exec"
	case "cancel_exec":
		wantMethod, wantPath = "POST", "/v1/sandboxes/"+sandboxID+"/exec:cancel"
	case "open_runtime_session":
		wantMethod, wantPath = "POST", "/v1/sandboxes/"+sandboxID+"/runtime-sessions"
	case "open_browser_session":
		wantMethod, wantPath = "POST", "/v1/sandboxes/"+sandboxID+"/browser-sessions"
	case "stage_artifact":
		wantMethod, wantPath = "POST", "/v1/sandboxes/"+sandboxID+"/artifacts:stage"
	case "read_operation":
		wantMethod, wantPath = "GET", "/v1/operations/"+operationID
	case "read_result":
		wantMethod, wantPath = "GET", "/v1/operations/"+operationID+"/exec-result"
	case "read_runtime_session":
		wantMethod, wantPath = "GET", "/v1/operations/"+operationID+"/runtime-session"
	case "read_browser_session":
		wantMethod, wantPath = "GET", "/v1/operations/"+operationID+"/browser-session"
	case "read_artifact_staging_evidence":
		wantMethod, wantPath = "GET", "/v1/operations/"+operationID+"/artifact-staging-evidence"
	case "read_usage_evidence":
		wantMethod, wantPath = "GET", "/v1/operations/"+operationID+"/usage-evidence"
	case "connect_runtime_session":
		wantMethod, wantPath = "GET", "/v1/runtime-sessions:connect"
	default:
		return false
	}
	return target.Method == wantMethod && target.Path == wantPath
}

func marshalJSON(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidContractDocument
	}
	return document, nil
}

func signingParts(token string) (string, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", nil, errors.New("invalid compact JWS")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", nil, err
	}
	return parts[0], parts[1], signature, nil
}
