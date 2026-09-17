package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoverCapabilitiesSendsEmptyMTLSOnlyRequestAndStrictlyDecodes(t *testing.T) {
	fixture := testCapabilities()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "https://provider.example:8443/v1/capabilities" || request.Body != nil || request.Header.Get("Authorization") != "" || request.Header.Get(AdmissionHeaderName) != "" || request.Header.Get("Content-Type") != "" {
			t.Fatalf("discovery request = %#v, headers %v", request, request.Header)
		}
		return jsonResponse(t, http.StatusOK, fixture), nil
	})
	client, err := NewClient("https://provider.example:8443", transport)
	if err != nil {
		t.Fatal(err)
	}
	got, raw, err := client.DiscoverCapabilitiesDocument(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.ProviderRevisionID != fixture.ProviderRevisionID || len(got.Capabilities) != 2 || len(got.RuntimeProfiles) != 1 {
		t.Fatalf("capabilities = %#v", got)
	}
	wantRaw, err := json.Marshal(fixture)
	if err != nil || !bytes.Equal(raw, wantRaw) {
		t.Fatalf("raw capabilities = %q, want %q, error %v", raw, wantRaw, err)
	}
	raw[0] ^= 1
	again, err := client.DiscoverCapabilities(context.Background())
	if err != nil || again.ProviderRevisionID != fixture.ProviderRevisionID {
		t.Fatalf("raw caller mutation affected client: %#v, %v", again, err)
	}
}

func TestCreateAndLifecycleReadsAreExactlyBound(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	requestDocument, err := BindCreateRequest(testCreateRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := testSigner(t)
	createAdmission, err := BuildAdmission(testAuthority(), testCreateBinding(requestDocument, now), signer)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if len(request.Header.Values("Authorization")) != 1 || len(request.Header.Values(AdmissionHeaderName)) != 1 {
			t.Fatalf("protected headers = %v", request.Header)
		}
		switch request.URL.Path {
		case "/v1/sandboxes":
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" || request.ContentLength <= 0 || request.Header.Get("Authorization") != "Bearer "+createAdmission.BearerToken {
				t.Fatalf("create request method/headers = %s/%v", request.Method, request.Header)
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var sent CreateSandboxRequest
			if err := json.Unmarshal(body, &sent); err != nil || sent.RequestDigest != requestDocument.RequestDigest {
				t.Fatalf("create body = %s, error %v", body, err)
			}
			return jsonResponse(t, http.StatusAccepted, testOperation("accepted", now)), nil
		case "/v1/sandboxes/sandbox-1":
			if request.Method != http.MethodGet || request.Body != nil || request.Header.Get("Content-Type") != "" {
				t.Fatalf("status request = %#v", request)
			}
			return jsonResponse(t, http.StatusOK, testStatus(now)), nil
		case "/v1/operations/operation-create-1":
			return jsonResponse(t, http.StatusOK, testOperation("succeeded", now)), nil
		default:
			t.Fatalf("unexpected request path %q", request.URL.Path)
			return nil, errors.New("unexpected request")
		}
	})
	client, err := NewClient("https://provider.example:8443", transport)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	if _, err := client.CreateSandbox(context.Background(), requestDocument, createAdmission); err != nil {
		t.Fatal(err)
	}

	statusDescriptor := ReadDescriptor{Operation: "read_sandbox", SandboxID: "sandbox-1", OperationID: "operation-create-1", AttemptID: "attempt-create-1", FencingToken: 1}
	statusAdmission := testReadAdmission(t, signer, statusDescriptor, StatusDescriptorContractID, "/v1/sandboxes/sandbox-1", now, "admission-token-0002")
	if _, err := client.GetSandboxStatus(context.Background(), statusDescriptor, statusAdmission); err != nil {
		t.Fatal(err)
	}
	operationDescriptor := statusDescriptor
	operationDescriptor.Operation = "read_operation"
	operationAdmission := testReadAdmission(t, signer, operationDescriptor, OperationDescriptorContractID, "/v1/operations/operation-create-1", now, "admission-token-0003")
	operation, err := client.GetOperation(context.Background(), operationDescriptor, operationAdmission)
	if err != nil || operation.Status != "succeeded" {
		t.Fatalf("GetOperation() = %#v, %v", operation, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("wire call count = %d", calls.Load())
	}
}

func TestCreateAcceptsOnlySuccessfulIdempotencyProgressStates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	requestDocument, err := BindCreateRequest(testCreateRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := testSigner(t)
	admission, err := BuildAdmission(testAuthority(), testCreateBinding(requestDocument, now), signer)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		status string
		valid  bool
	}{
		{status: "accepted", valid: true},
		{status: "running", valid: true},
		{status: "succeeded", valid: true},
		{status: "failed"},
		{status: "cancelled"},
		{status: "outcome_unknown"},
	} {
		t.Run(test.status, func(t *testing.T) {
			client, err := NewClient("https://provider.example", roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(t, http.StatusAccepted, testOperation(test.status, now)), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			client.now = func() time.Time { return now }
			operation, err := client.CreateSandbox(context.Background(), requestDocument, admission)
			if test.valid {
				if err != nil || operation.Status != test.status {
					t.Fatalf("CreateSandbox() = %#v, %v", operation, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidContractDocument) {
				t.Fatalf("CreateSandbox() error = %v", err)
			}
		})
	}
}

func TestClientRejectsTamperingBeforeTransport(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	requestDocument, err := BindCreateRequest(testCreateRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := testSigner(t)
	admission, err := BuildAdmission(testAuthority(), testCreateBinding(requestDocument, now), signer)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	client, err := NewClient("https://provider.example", roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("must not be called")
	}))
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	admission.Context.RequestDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := client.CreateSandbox(context.Background(), requestDocument, admission); !errors.Is(err, ErrAdmissionBinding) {
		t.Fatalf("tampered admission error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("transport called %d times", calls.Load())
	}

	admission, err = BuildAdmission(testAuthority(), testCreateBinding(requestDocument, now), signer)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := client.CreateSandbox(context.Background(), requestDocument, admission); !errors.Is(err, ErrAdmissionBinding) {
		t.Fatalf("expired admission error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("transport called after expiry %d times", calls.Load())
	}
}

func TestClientReturnsOnlyLockedErrorShapeAndRetryAfter(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := jsonResponse(t, http.StatusServiceUnavailable, StandardError{Code: "PROVIDER_UNAVAILABLE", Message: "temporarily unavailable", Retryable: true, TraceID: "trace-1"})
		response.Header.Set("Retry-After", "3")
		return response, nil
	})
	client, err := NewClient("https://provider.example", transport)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DiscoverCapabilities(context.Background())
	var providerError *HTTPError
	if !errors.As(err, &providerError) || providerError.StatusCode != 503 || providerError.Document.Code != "PROVIDER_UNAVAILABLE" || providerError.RetryAfterSeconds == nil || *providerError.RetryAfterSeconds != 3 {
		t.Fatalf("HTTP error = %#v, %v", providerError, err)
	}
}

func TestClientDistinguishesPeerTLSAlertFromGenericTransportFailure(t *testing.T) {
	for name, transportError := range map[string]error{
		"tls rejected":   tls.AlertError(42),
		"network failed": errors.New("synthetic network failure"),
	} {
		t.Run(name, func(t *testing.T) {
			client, err := NewClient("https://provider.example", roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, transportError
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.DiscoverCapabilities(context.Background())
			want := ErrTransport
			if name == "tls rejected" {
				want = ErrTLSRejected
			}
			if !errors.Is(err, want) {
				t.Fatalf("transport error = %v, want %v", err, want)
			}
		})
	}
}

func TestClientRejectsResponseAmbiguityAndLimits(t *testing.T) {
	tests := []struct {
		name     string
		response func(*testing.T) *http.Response
		want     error
	}{
		{name: "wrong success status", response: func(t *testing.T) *http.Response { return jsonResponse(t, http.StatusAccepted, testCapabilities()) }, want: ErrUnexpectedStatus},
		{name: "wrong media type", response: func(t *testing.T) *http.Response {
			response := jsonResponse(t, http.StatusOK, testCapabilities())
			response.Header.Set("Content-Type", "text/plain")
			return response
		}, want: ErrContentType},
		{name: "oversized", response: func(*testing.T) *http.Response {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", maxResponseBytes+1)))}
		}, want: ErrResponseTooLarge},
		{name: "unknown response field", response: func(t *testing.T) *http.Response {
			document, _ := json.Marshal(testCapabilities())
			document = bytes.Replace(document, []byte(`"api_version"`), []byte(`"unknown":true,"api_version"`), 1)
			return rawJSONResponse(http.StatusOK, document)
		}, want: ErrInvalidContractDocument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient("https://provider.example", roundTripFunc(func(*http.Request) (*http.Response, error) { return test.response(t), nil }))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.DiscoverCapabilities(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("DiscoverCapabilities() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewClientRejectsUnsafeOriginAndImplicitTransport(t *testing.T) {
	for _, origin := range []string{"http://provider.example", "https://Provider.example", "https://provider.example/", "https://provider.example:443", "https://provider.1", "https://127.0.0.01"} {
		if _, err := NewClient(origin, roundTripFunc(nil)); !errors.Is(err, ErrInvalidOrigin) {
			t.Errorf("NewClient(%q) error = %v", origin, err)
		}
	}
	if _, err := NewClient("https://provider.example", nil); !errors.Is(err, ErrMissingTransport) {
		t.Fatalf("nil transport error = %v", err)
	}
}

func TestStrictResponseDecodersRejectMissingRequiredFalseAndNullOptional(t *testing.T) {
	if err := decodeStandardError([]byte(`{"code":"PROVIDER_UNAVAILABLE","message":"unavailable","trace_id":"trace-1"}`), &StandardError{}); !errors.Is(err, ErrInvalidContractDocument) {
		t.Fatalf("missing required retryable error = %v", err)
	}
	operation := testOperation("failed", time.Now().UTC())
	document, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	document = bytes.TrimSuffix(document, []byte("}"))
	document = append(document, []byte(`,"error":null}`)...)
	if err := decodeProviderOperation(document, &ProviderOperation{}); !errors.Is(err, ErrInvalidContractDocument) {
		t.Fatalf("null optional error field error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(t *testing.T, status int, value any) *http.Response {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return rawJSONResponse(status, document)
}

func rawJSONResponse(status int, document []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(document))}
}

func testCapabilities() ProviderCapabilities {
	workspace, gpu := int64(1073741824), int64(0)
	return ProviderCapabilities{
		ProviderRevisionID: "provider-revision-local-v1", APIVersion: "v1",
		Capabilities:            []Capability{{ID: "sandbox.exec", Versions: []string{"1.0.0"}, Profiles: []string{"exec-v1"}}, {ID: "sandbox.terminal", Versions: []string{"1.0.0"}, Profiles: []string{"terminal-v1"}}},
		RuntimeProfiles:         []RuntimeProfile{{ID: "sandbox-runtime-coding-shell-v1", IsolationClass: "container", RuntimeClassName: "sandbox-runtime-coding-shell", Architecture: []string{"amd64"}, CapabilityProfileIDs: []string{"exec-v1", "terminal-v1"}}},
		SnapshotRestoreProfiles: []SnapshotRestoreProfile{{ProfileID: "sandbox-snapshot-workspace-v1", Level: "workspace", SuiteID: "sandbox-provider", SuiteVersion: "1.0.0", SuiteDigest: "sha256:b40c932643f4a1e5fd6681e3abf9b64a607609866a6254456970f8b8034cf2a8"}},
		Limits:                  ProviderLimits{MaxCPUMillis: 1000, MaxMemoryBytes: 1073741824, MaxEphemeralStorageBytes: 1073741824, MaxWorkspaceBytes: &workspace, MaxGPUCount: &gpu, MaxLeaseSeconds: 3600, MaxExecSeconds: 300},
	}
}

func testOperation(status string, now time.Time) ProviderOperation {
	return ProviderOperation{OperationID: "operation-create-1", AttemptID: "attempt-create-1", FencingToken: 1, SandboxID: "sandbox-1", Type: "create", Status: status, ObservedAt: now.Format(time.RFC3339)}
}

func testStatus(now time.Time) SandboxStatus {
	return SandboxStatus{
		SandboxID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-order-1", WorkspaceID: "workspace-1", ProviderRevisionID: "provider-revision-local-v1",
		DesiredState: "ready", ObservedState: "ready", Generation: 1, ObservedGeneration: 1, RuntimeProfile: "sandbox-runtime-coding-shell-v1",
		LeaseExpiresAt: now.Add(time.Hour).Format(time.RFC3339), CreatedAt: now.Add(-time.Minute).Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339), SandboxSlotKey: "primary-code",
	}
}

func testReadAdmission(t *testing.T, signer Signer, descriptor ReadDescriptor, contractID, path string, now time.Time, jti string) Admission {
	t.Helper()
	digest, err := DigestReadDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	binding := AdmissionBinding{
		JTI: jti, IssuedAt: now.Add(-time.Second), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), TenantID: "tenant-1", WorkOrderID: "work-order-1",
		PolicyDigest: "sha256:" + strings.Repeat("b", 64), PolicyDecidedAt: now.Add(-time.Minute).Format(time.RFC3339), Operation: descriptor.Operation,
		SandboxID: descriptor.SandboxID, OperationID: descriptor.OperationID, AttemptID: descriptor.AttemptID, FencingToken: descriptor.FencingToken,
		DeadlineAt: now.Add(2 * time.Minute).Format(time.RFC3339), RequestContractID: contractID, RequestDigestProfile: DescriptorDigestProfile, RequestDigest: digest,
		HTTPTarget: AdmissionTarget{Method: "GET", Path: path, NormalizedQuery: []QueryParameter{}},
	}
	admission, err := BuildAdmission(testAuthority(), binding, signer)
	if err != nil {
		t.Fatal(err)
	}
	return admission
}
