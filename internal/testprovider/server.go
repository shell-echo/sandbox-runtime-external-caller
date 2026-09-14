// Package testprovider supplies a local test-only mTLS Provider surface. It is
// never linked into candidate commands and is not interoperability evidence.
package testprovider

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerprovider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

type Counts struct {
	Capabilities int
	Creates      int
	Operations   int
	Statuses     int
}

type Server struct {
	server *httptest.Server
	keys   map[string]ed25519.PublicKey

	mu            sync.Mutex
	counts        Counts
	errors        []string
	request       *provider.CreateSandboxRequest
	seed          *callerstate.State
	seenJTI       map[string]struct{}
	policyDigest  string
	policyDecided string
}

func New(t testing.TB, providerCA *x509.Certificate, serverCertificate tls.Certificate, admissionPublicKeys map[string]ed25519.PublicKey) *Server {
	t.Helper()
	if providerCA == nil || len(serverCertificate.Certificate) == 0 {
		t.Fatal("test Provider identity is incomplete")
	}
	keys := make(map[string]ed25519.PublicKey, len(admissionPublicKeys))
	for actor, publicKey := range admissionPublicKeys {
		keys[actor] = append(ed25519.PublicKey(nil), publicKey...)
	}
	result := &Server{keys: keys, seenJTI: make(map[string]struct{})}
	server := httptest.NewUnstartedServer(http.HandlerFunc(result.serveHTTP))
	roots := x509.NewCertPool()
	roots.AddCert(providerCA)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
	}
	server.StartTLS()
	result.server = server
	t.Cleanup(server.Close)
	return result
}

func (server *Server) Origin() string { return server.server.URL }

func (server *Server) SeedLifecycle(state callerstate.State) {
	server.mu.Lock()
	defer server.mu.Unlock()
	copy := state
	server.seed = &copy
}

func (server *Server) Snapshot() (Counts, []string) {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.counts, append([]string(nil), server.errors...)
}

func Capabilities() provider.ProviderCapabilities {
	workspace := int64(1073741824)
	return provider.ProviderCapabilities{
		ProviderRevisionID: "provider-revision-local-v1", APIVersion: "v1",
		Capabilities: []provider.Capability{
			{ID: "sandbox.exec", Versions: []string{"1.0.0"}, Profiles: []string{callerprovider.ExecProfileID}},
			{ID: "sandbox.terminal", Versions: []string{"1.0.0"}, Profiles: []string{callerprovider.TerminalProfileID}},
		},
		RuntimeProfiles: []provider.RuntimeProfile{{
			ID: callerprovider.RuntimeProfileID, IsolationClass: "container", RuntimeClassName: "sandbox-runtime-coding-shell",
			Architecture: []string{"arm64", "amd64"}, CapabilityProfileIDs: []string{callerprovider.ExecProfileID, callerprovider.TerminalProfileID},
		}},
		SnapshotRestoreProfiles: []provider.SnapshotRestoreProfile{{
			ProfileID: "sandbox-snapshot-workspace-v1", Level: "workspace", SuiteID: "sandbox-provider", SuiteVersion: "1.0.0",
			SuiteDigest: "sha256:bf177a5bd2b4228605b3ebc311d25a1cc348d9548b2b5c2d333a0c69e71ca528",
		}},
		Limits: provider.ProviderLimits{
			MaxCPUMillis: 1000, MaxMemoryBytes: 1073741824, MaxEphemeralStorageBytes: 1073741824,
			MaxWorkspaceBytes: &workspace, MaxLeaseSeconds: 3600, MaxExecSeconds: 300,
		},
	}
}

func CapabilitiesDocument() []byte {
	document, err := json.Marshal(Capabilities())
	if err != nil {
		panic(err)
	}
	return document
}

func (server *Server) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	actor := peerActor(request)
	if actor == "" {
		server.reject(writer, "missing admitted mTLS actor", http.StatusForbidden)
		return
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/v1/capabilities":
		if actor != "controller_a" && actor != "controller_b" {
			server.reject(writer, "unadmitted capability actor", http.StatusForbidden)
			return
		}
		server.mu.Lock()
		server.counts.Capabilities++
		server.mu.Unlock()
		writeJSON(writer, http.StatusOK, CapabilitiesDocument())
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes":
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid create admission", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
		var create provider.CreateSandboxRequest
		if err != nil || len(body) > 1<<20 || json.Unmarshal(body, &create) != nil || provider.ValidateCreateRequest(create) != nil {
			server.reject(writer, "invalid create document", http.StatusBadRequest)
			return
		}
		server.mu.Lock()
		server.counts.Creates++
		copy := create
		server.request = &copy
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusAccepted, operation(create.OperationID, create.AttemptID, create.FencingToken, create.Spec.SandboxID, "accepted"))
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1/operations/"):
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid operation admission", http.StatusForbidden)
			return
		}
		state, ok := server.lifecycle()
		if !ok || request.URL.Path != "/v1/operations/"+state.operationID {
			server.reject(writer, "unknown operation", http.StatusNotFound)
			return
		}
		server.mu.Lock()
		server.counts.Operations++
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusOK, operation(state.operationID, state.attemptID, state.fencingToken, state.sandboxID, "succeeded"))
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1/sandboxes/"):
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid status admission", http.StatusForbidden)
			return
		}
		state, ok := server.lifecycle()
		if !ok || request.URL.Path != "/v1/sandboxes/"+state.sandboxID {
			server.reject(writer, "unknown sandbox", http.StatusNotFound)
			return
		}
		server.mu.Lock()
		server.counts.Statuses++
		server.mu.Unlock()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		writeJSONValue(writer, http.StatusOK, provider.SandboxStatus{
			SandboxID: state.sandboxID, TenantID: state.tenantID, WorkOrderID: state.workOrderID,
			WorkspaceID: state.workspaceID, ProviderRevisionID: Capabilities().ProviderRevisionID,
			DesiredState: "ready", ObservedState: "ready", Generation: 1, ObservedGeneration: 1,
			RuntimeProfile: callerprovider.RuntimeProfileID, LeaseExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
			CreatedAt: now, UpdatedAt: now, SandboxSlotKey: callerprovider.SandboxSlotKey,
		})
	default:
		server.reject(writer, "unexpected Provider route", http.StatusNotFound)
	}
}

type lifecycleState struct {
	operationID, attemptID, sandboxID, tenantID, workOrderID, workspaceID string
	fencingToken                                                          int64
}

func (server *Server) lifecycle() (lifecycleState, bool) {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.request != nil {
		request := server.request
		return lifecycleState{
			operationID: request.OperationID, attemptID: request.AttemptID, fencingToken: request.FencingToken,
			sandboxID: request.Spec.SandboxID, tenantID: request.Spec.TenantID, workOrderID: request.Spec.WorkOrderID, workspaceID: request.Spec.WorkspaceID,
		}, true
	}
	if server.seed != nil && server.seed.Provider != nil && server.seed.Lifecycle != nil {
		state := server.seed
		return lifecycleState{
			operationID: state.Lifecycle.OperationID, attemptID: state.Lifecycle.AttemptID, fencingToken: state.Lifecycle.FencingToken,
			sandboxID: state.Plan.SandboxID, tenantID: state.Plan.TenantAID, workOrderID: state.Plan.WorkOrderAID, workspaceID: state.Plan.WorkspaceID,
		}, true
	}
	return lifecycleState{}, false
}

func (server *Server) verifyAdmission(request *http.Request, actor string) bool {
	token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(token, ".")
	publicKey := server.keys[actor]
	if len(parts) != 3 || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return false
	}
	claimsBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims provider.JWSClaims
	if json.Unmarshal(claimsBytes, &claims) != nil || claims.Subject != "spiffe://provider/"+actor || claims.ProviderRevisionID != Capabilities().ProviderRevisionID {
		return false
	}
	contextBytes, err := base64.RawURLEncoding.Strict().DecodeString(request.Header.Get(provider.AdmissionHeaderName))
	if err != nil {
		return false
	}
	var admissionContext provider.AdmissionContext
	if json.Unmarshal(contextBytes, &admissionContext) != nil || admissionContext.ControllerSubject != claims.Subject || admissionContext.RequestDigest != claims.RequestDigest || admissionContext.HTTPTarget.Path != request.URL.Path {
		return false
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, duplicate := server.seenJTI[claims.JTI]; duplicate {
		return false
	}
	server.seenJTI[claims.JTI] = struct{}{}
	if server.policyDigest == "" {
		server.policyDigest, server.policyDecided = claims.PolicyDigest, claims.PolicyDecidedAt
	}
	return claims.PolicyDigest == server.policyDigest && claims.PolicyDecidedAt == server.policyDecided
}

func peerActor(request *http.Request) string {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || len(request.TLS.PeerCertificates[0].URIs) != 1 {
		return ""
	}
	value := request.TLS.PeerCertificates[0].URIs[0].String()
	return strings.TrimPrefix(value, "spiffe://provider/")
}

func operation(operationID, attemptID string, fencingToken int64, sandboxID, status string) provider.ProviderOperation {
	return provider.ProviderOperation{
		OperationID: operationID, AttemptID: attemptID, FencingToken: fencingToken, SandboxID: sandboxID,
		Type: "create", Status: status, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func (server *Server) reject(writer http.ResponseWriter, message string, status int) {
	server.mu.Lock()
	server.errors = append(server.errors, message)
	server.mu.Unlock()
	writeJSONValue(writer, status, provider.StandardError{Code: "TEST_PROVIDER_REJECTED", Message: message, Retryable: false, TraceID: "test-trace"})
}

func writeJSONValue(writer http.ResponseWriter, status int, value any) {
	document, err := json.Marshal(value)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(writer, status, document)
}

func writeJSON(writer http.ResponseWriter, status int, document []byte) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(document)
}
