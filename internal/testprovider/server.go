// Package testprovider supplies a local test-only mTLS Provider surface. It is
// never linked into candidate commands and is not interoperability evidence.
package testprovider

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerprovider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

type Counts struct {
	Capabilities                       int
	UnadmittedCapabilityGets           int
	CapabilityTransients               int
	Creates                            int
	CreateTransients                   int
	ExactJTIReplays                    int
	IdempotencyReplays                 int
	Operations                         int
	Statuses                           int
	Execs                              int
	StaleExecRejections                int
	CancelExecs                        int
	ExecResults                        int
	UsageReads                         int
	Sessions                           int
	Handoffs                           int
	TerminalConnects                   int
	ArtifactStages                     int
	ArtifactEvidenceReads              int
	CrossTenantArtifactRejections      int
	CrossTenantOperationReadRejections int
	WrongMTLSCallerRejections          int
}

type RetainedEvidence struct {
	ExecResult       provider.ExecResult
	Usage            provider.UsageEvidence
	ArtifactEvidence provider.ArtifactStagingEvidence
	Handoff          provider.RuntimeSessionHandoff
}

type Server struct {
	server *httptest.Server
	keys   map[string]ed25519.PublicKey

	mu                      sync.Mutex
	counts                  Counts
	errors                  []string
	request                 *provider.CreateSandboxRequest
	execRequest             *provider.ExecRequest
	cancelRequest           *provider.CancelExecRequest
	sessionRequest          *provider.RuntimeSessionOpenRequest
	artifactRequest         *provider.ArtifactStagingRequest
	seed                    *callerstate.State
	execResults             map[string]provider.ExecResult
	usageEvidence           map[string]provider.UsageEvidence
	artifactEvidence        map[string]provider.ArtifactStagingEvidence
	retainedHandoff         provider.RuntimeSessionHandoff
	seenJTI                 map[string]struct{}
	policyDigest            string
	policyDecided           string
	terminalCloseAfterWrite bool
	capabilityTransients    map[string]int
	createTransients        int
	firstCreateBearer       string
	firstCreateContext      string
	firstCreateBody         []byte
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
	result := &Server{
		keys: keys, seenJTI: make(map[string]struct{}), capabilityTransients: make(map[string]int),
		execResults: make(map[string]provider.ExecResult), usageEvidence: make(map[string]provider.UsageEvidence), artifactEvidence: make(map[string]provider.ArtifactStagingEvidence),
	}
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

func (server *Server) SetTerminalCloseAfterWrite(value bool) {
	server.mu.Lock()
	server.terminalCloseAfterWrite = value
	server.mu.Unlock()
}

func (server *Server) SetCapabilityTransients(actor string, count int) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.capabilityTransients[actor] = count
}

func (server *Server) SetCreateTransients(count int) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.createTransients = count
}

func (server *Server) SeedLifecycle(state callerstate.State) {
	server.mu.Lock()
	defer server.mu.Unlock()
	copy := state
	server.seed = &copy
}

func (server *Server) SnapshotRetainedEvidence(state callerstate.State) (RetainedEvidence, bool) {
	server.mu.Lock()
	defer server.mu.Unlock()
	if state.Exec == nil || state.Terminal == nil || state.Artifact == nil {
		return RetainedEvidence{}, false
	}
	result, resultOK := server.execResults[state.Exec.Operation.OperationID]
	usage, usageOK := server.usageEvidence[state.Exec.Operation.OperationID]
	artifact, artifactOK := server.artifactEvidence[state.Artifact.Operation.OperationID]
	handoff := server.retainedHandoff
	if !resultOK || !usageOK || !artifactOK || handoff.OperationID == "" {
		return RetainedEvidence{}, false
	}
	return cloneRetainedEvidence(RetainedEvidence{ExecResult: result, Usage: usage, ArtifactEvidence: artifact, Handoff: handoff}), true
}

func (server *Server) SeedRetainedEvidence(state callerstate.State, retained RetainedEvidence) bool {
	if state.Exec == nil || state.Terminal == nil || state.Artifact == nil || retained.ExecResult.OperationID != state.Exec.Operation.OperationID || retained.Usage.OperationID != state.Exec.Operation.OperationID || retained.ArtifactEvidence.OperationID != state.Artifact.Operation.OperationID {
		return false
	}
	handoffExpiry, handoffExpiryErr := time.Parse(time.RFC3339Nano, retained.Handoff.ExpiresAt)
	if handoffExpiryErr != nil || !handoffExpiry.After(time.Now()) || retained.Handoff.OperationID != state.Terminal.Operation.OperationID || retained.Handoff.AttemptID != state.Terminal.Operation.AttemptID ||
		retained.Handoff.FencingToken != state.Terminal.Operation.FencingToken || retained.Handoff.SandboxID != state.Plan.SandboxID || retained.Handoff.RuntimeSessionID != state.Terminal.RuntimeSessionID ||
		retained.Handoff.RuntimeType != "terminal" || retained.Handoff.CapabilityProfileID != callerprovider.TerminalProfileID || retained.Handoff.Protocol != "websocket" ||
		retained.Handoff.InternalEndpointReference != state.Terminal.HandoffReference || jcs.DigestBytes([]byte(retained.Handoff.InternalEndpointReference)) != state.Terminal.HandoffReferenceDigest || retained.Handoff.ConnectionGeneration < 1 {
		return false
	}
	resultDigest, resultErr := jcs.Digest(retained.ExecResult)
	usageDigest, usageErr := jcs.Digest(retained.Usage)
	artifactDigest, artifactErr := jcs.Digest(retained.ArtifactEvidence)
	if resultErr != nil || usageErr != nil || artifactErr != nil || resultDigest != state.Exec.ResultDigest || usageDigest != state.Exec.UsageEvidenceDigest || artifactDigest != state.Artifact.EvidenceDigest {
		return false
	}
	copy := cloneRetainedEvidence(retained)
	server.mu.Lock()
	defer server.mu.Unlock()
	stateCopy := state
	server.seed = &stateCopy
	server.execResults[copy.ExecResult.OperationID] = copy.ExecResult
	server.usageEvidence[copy.Usage.OperationID] = copy.Usage
	server.artifactEvidence[copy.ArtifactEvidence.OperationID] = copy.ArtifactEvidence
	server.retainedHandoff = copy.Handoff
	return true
}

func cloneRetainedEvidence(value RetainedEvidence) RetainedEvidence {
	result := value
	if value.ExecResult.ExitCode != nil {
		exitCode := *value.ExecResult.ExitCode
		result.ExecResult.ExitCode = &exitCode
	}
	result.Usage.Entries = append([]provider.UsageEntry(nil), value.Usage.Entries...)
	return result
}

func retainedRuntimeSessionHandoff(session *provider.RuntimeSessionOpenRequest, retained provider.RuntimeSessionHandoff, sandboxID string) (provider.RuntimeSessionHandoff, bool) {
	if retained.OperationID != "" {
		return retained, true
	}
	if session == nil {
		return provider.RuntimeSessionHandoff{}, false
	}
	return provider.RuntimeSessionHandoff{
		OperationID: session.OperationID, AttemptID: session.AttemptID, FencingToken: session.FencingToken, SandboxID: sandboxID,
		RuntimeSessionID: session.RuntimeSessionID, RuntimeType: "terminal", CapabilityProfileID: session.CapabilityProfileID,
		Protocol: "websocket", InternalEndpointReference: "ref:session:synthetic", ConnectionGeneration: 1, ExpiresAt: session.ExpiresAt,
	}, true
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
			{ID: "sandbox.terminal-connect", Versions: []string{"1.0.0"}, Profiles: []string{callerprovider.TerminalConnectProfileID}},
		},
		RuntimeProfiles: []provider.RuntimeProfile{{
			ID: callerprovider.RuntimeProfileID, IsolationClass: "container", RuntimeClassName: "sandbox-runtime-coding-shell",
			Architecture: []string{"arm64", "amd64"}, CapabilityProfileIDs: []string{callerprovider.ExecProfileID, callerprovider.TerminalProfileID, callerprovider.TerminalConnectProfileID},
		}},
		SnapshotRestoreProfiles: []provider.SnapshotRestoreProfile{{
			ProfileID: "sandbox-snapshot-workspace-v1", Level: "workspace", SuiteID: "sandbox-provider", SuiteVersion: "1.0.0",
			SuiteDigest: "sha256:b40c932643f4a1e5fd6681e3abf9b64a607609866a6254456970f8b8034cf2a8",
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
		server.mu.Lock()
		remaining := server.capabilityTransients[actor]
		if remaining > 0 {
			server.capabilityTransients[actor] = remaining - 1
			server.counts.CapabilityTransients++
		}
		server.mu.Unlock()
		if remaining > 0 {
			writeJSONValue(writer, http.StatusServiceUnavailable, provider.StandardError{Code: "TEST_PROVIDER_UNAVAILABLE", Message: "temporary capability failure", Retryable: true, TraceID: "test-trace"})
			return
		}
		if actor != "controller_a" && actor != "controller_b" {
			server.mu.Lock()
			server.counts.UnadmittedCapabilityGets++
			server.mu.Unlock()
			writeJSONValue(writer, http.StatusForbidden, provider.StandardError{Code: "TEST_PROVIDER_REJECTED", Message: "unadmitted capability actor", Retryable: false, TraceID: "test-trace"})
			return
		}
		server.mu.Lock()
		server.counts.Capabilities++
		server.mu.Unlock()
		writeJSON(writer, http.StatusOK, CapabilitiesDocument())
	case request.Method == http.MethodGet && request.URL.Path == "/v1/runtime-sessions:connect":
		if actor != "controller_a" || request.Header.Get("Origin") != "" || request.Header.Get("Sec-WebSocket-Extensions") != "" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid terminal connect admission", http.StatusForbidden)
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(request.Header.Get("X-Sandbox-Runtime-Session-Handoff"))
		var descriptor provider.RuntimeSessionHandoff
		server.mu.Lock()
		session := server.sessionRequest
		retained := server.retainedHandoff
		server.mu.Unlock()
		expected, expectedOK := retainedRuntimeSessionHandoff(session, retained, stateSandbox(server))
		if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &descriptor) != nil || !expectedOK || !reflect.DeepEqual(descriptor, expected) {
			server.reject(writer, "invalid terminal connect descriptor", http.StatusForbidden)
			return
		}
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{"sandbox-runtime-terminal.v1"}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		connection.SetReadLimit(65536)
		server.mu.Lock()
		server.counts.TerminalConnects++
		server.mu.Unlock()
		for {
			typ, payload, err := connection.Read(request.Context())
			if err != nil {
				return
			}
			if typ != websocket.MessageBinary || len(payload) > 65536 {
				_ = connection.Close(websocket.StatusUnsupportedData, "unsupported data")
				return
			}
			if err := connection.Write(request.Context(), websocket.MessageBinary, payload); err != nil {
				return
			}
			server.mu.Lock()
			closeAfterWrite := server.terminalCloseAfterWrite
			server.mu.Unlock()
			if closeAfterWrite {
				_ = connection.Close(websocket.StatusNormalClosure, "")
				return
			}
		}
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes":
		if actor != "controller_a" {
			server.reject(writer, "invalid create admission", http.StatusForbidden)
			return
		}
		server.mu.Lock()
		remaining := server.createTransients
		if remaining > 0 {
			server.createTransients = remaining - 1
			server.counts.CreateTransients++
		}
		server.mu.Unlock()
		if remaining > 0 {
			writer.Header().Set("Retry-After", "1")
			writeJSONValue(writer, http.StatusServiceUnavailable, provider.StandardError{Code: "TEST_PROVIDER_UNAVAILABLE", Message: "temporary create failure", Retryable: true, TraceID: "test-trace"})
			return
		}
		admission := server.verifyAdmissionStatus(request, actor)
		if admission == admissionDuplicate {
			body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
			server.mu.Lock()
			exact := err == nil && len(body) <= 1<<20 && request.Header.Get("Authorization") == server.firstCreateBearer && request.Header.Get(provider.AdmissionHeaderName) == server.firstCreateContext && bytes.Equal(body, server.firstCreateBody)
			if exact {
				server.counts.ExactJTIReplays++
			}
			server.mu.Unlock()
			if !exact {
				server.reject(writer, "JTI replay did not preserve exact create authority", http.StatusForbidden)
				return
			}
			writeJSONValue(writer, http.StatusConflict, provider.StandardError{Code: "JTI_REPLAY", Message: "admission JTI was already consumed", Retryable: false, TraceID: "test-trace"})
			return
		}
		if admission != admissionAccepted {
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
		first := server.request == nil
		idempotent := !first && reflect.DeepEqual(*server.request, create)
		if first {
			server.counts.Creates++
			copy := create
			server.request = &copy
			server.firstCreateBearer = request.Header.Get("Authorization")
			server.firstCreateContext = request.Header.Get(provider.AdmissionHeaderName)
			server.firstCreateBody = append([]byte(nil), body...)
		} else if idempotent {
			server.counts.IdempotencyReplays++
		}
		server.mu.Unlock()
		if !first && !idempotent {
			server.reject(writer, "conflicting create replay", http.StatusConflict)
			return
		}
		writeJSONValue(writer, http.StatusAccepted, operation(create.OperationID, create.AttemptID, create.FencingToken, create.Spec.SandboxID, "accepted"))
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes/"+stateSandbox(server)+"/exec":
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid exec admission", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
		var exec provider.ExecRequest
		if err != nil || len(body) > 262144 || json.Unmarshal(body, &exec) != nil || provider.ValidateExecRequest(exec) != nil {
			server.reject(writer, "invalid exec document", http.StatusBadRequest)
			return
		}
		server.mu.Lock()
		if server.execRequest != nil && exec.FencingToken < server.execRequest.FencingToken {
			server.counts.StaleExecRejections++
			server.mu.Unlock()
			writeJSONValue(writer, http.StatusConflict, provider.StandardError{
				Code: "SANDBOX_STALE_FENCING_TOKEN", Message: "stale exec fencing token", Retryable: false, TraceID: "test-trace",
			})
			return
		}
		copy := exec
		server.execRequest = &copy
		server.counts.Execs++
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusAccepted, operationWithType(exec.OperationID, exec.AttemptID, exec.FencingToken, request.URL.Path[len("/v1/sandboxes/"):len(request.URL.Path)-len("/exec")], "exec", "accepted"))
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes/"+stateSandbox(server)+"/exec:cancel":
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid cancel exec admission", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 65537))
		var cancel provider.CancelExecRequest
		if err != nil || len(body) > 65536 || json.Unmarshal(body, &cancel) != nil || provider.ValidateCancelExecRequest(cancel) != nil {
			server.reject(writer, "invalid cancel exec document", http.StatusBadRequest)
			return
		}
		server.mu.Lock()
		target := server.execRequest
		if target == nil || cancel.TargetOperationID != target.OperationID || cancel.TargetAttemptID != target.AttemptID || cancel.FencingToken <= target.FencingToken {
			server.mu.Unlock()
			server.reject(writer, "invalid cancel exec target", http.StatusConflict)
			return
		}
		copy := cancel
		server.cancelRequest = &copy
		server.counts.CancelExecs++
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusAccepted, operationWithType(cancel.OperationID, cancel.AttemptID, cancel.FencingToken, stateSandbox(server), "cancel_exec", "accepted"))
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes/"+stateSandbox(server)+"/runtime-sessions":
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid runtime session admission", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
		var session provider.RuntimeSessionOpenRequest
		if err != nil || len(body) > 65536 || json.Unmarshal(body, &session) != nil || provider.ValidateRuntimeSessionOpenRequest(session) != nil {
			server.reject(writer, "invalid runtime session document", http.StatusBadRequest)
			return
		}
		server.mu.Lock()
		copy := session
		server.sessionRequest = &copy
		server.counts.Sessions++
		server.mu.Unlock()
		sandboxID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/sandboxes/"), "/runtime-sessions")
		writeJSONValue(writer, http.StatusAccepted, operationWithType(session.OperationID, session.AttemptID, session.FencingToken, sandboxID, "open_runtime_session", "accepted"))
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes/"+stateSandbox(server)+"/artifacts:stage":
		if actor == "controller_b" {
			claims, admission := server.verifyAdmissionStatusAndClaims(request, actor, false)
			body, err := io.ReadAll(io.LimitReader(request.Body, 65537))
			var artifact provider.ArtifactStagingRequest
			state, stateOK := server.lifecycle()
			server.mu.Lock()
			var retainedArtifact provider.ArtifactStagingRequest
			retainedArtifactPresent := server.artifactRequest != nil
			if retainedArtifactPresent {
				retainedArtifact = *server.artifactRequest
			}
			server.mu.Unlock()
			if admission != admissionAccepted || err != nil || len(body) > 65536 || json.Unmarshal(body, &artifact) != nil || provider.ValidateArtifactStagingRequest(artifact) != nil || !stateOK ||
				claims.Operation != "stage_artifact" || claims.SandboxID != state.sandboxID || claims.TenantID == state.tenantID || claims.WorkOrderID == state.workOrderID ||
				artifact.OperationID != claims.OperationID || artifact.AttemptID != claims.AttemptID || artifact.FencingToken != claims.FencingToken || artifact.RequestDigest != claims.RequestDigest || !retainedArtifactPresent || !reflect.DeepEqual(retainedArtifact, artifact) {
				server.reject(writer, "invalid cross-tenant artifact staging admission", http.StatusForbidden)
				return
			}
			server.mu.Lock()
			server.counts.CrossTenantArtifactRejections++
			server.mu.Unlock()
			writeJSONValue(writer, http.StatusForbidden, provider.StandardError{Code: "SANDBOX_FORBIDDEN", Message: "cross-tenant artifact staging forbidden", Retryable: false, TraceID: "test-trace"})
			return
		}
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid artifact staging admission", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 65537))
		var artifact provider.ArtifactStagingRequest
		if err != nil || len(body) > 65536 || json.Unmarshal(body, &artifact) != nil || provider.ValidateArtifactStagingRequest(artifact) != nil || artifact.SourcePath != "/outputs/external-caller.txt" || artifact.ExpectedDigest != "sha256:1dce5c90668d52fd4ff471e7bc3faab6c6eeb4dd35212ca56c3f6450de230dbe" || artifact.ExpectedMediaType != "text/plain" || artifact.MaxBytes != 24 {
			server.reject(writer, "invalid artifact staging document", http.StatusBadRequest)
			return
		}
		server.mu.Lock()
		if server.sessionRequest == nil || artifact.FencingToken <= server.sessionRequest.FencingToken {
			server.mu.Unlock()
			server.reject(writer, "artifact staging fence did not advance", http.StatusConflict)
			return
		}
		copy := artifact
		server.artifactRequest = &copy
		server.counts.ArtifactStages++
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusAccepted, operationWithType(artifact.OperationID, artifact.AttemptID, artifact.FencingToken, stateSandbox(server), "artifact_stage", "accepted"))
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1/operations/") && strings.Count(request.URL.Path, "/") == 3:
		if actor == "controller_b" {
			claims, admission := server.verifyAdmissionStatusAndClaims(request, actor, false)
			server.mu.Lock()
			var artifact provider.ArtifactStagingRequest
			artifactPresent := server.artifactRequest != nil
			if artifactPresent {
				artifact = *server.artifactRequest
			}
			server.mu.Unlock()
			state, stateOK := server.lifecycle()
			if admission != admissionAccepted || !stateOK || !artifactPresent || request.URL.Path != "/v1/operations/"+artifact.OperationID ||
				claims.Operation != "read_operation" || claims.SandboxID != state.sandboxID || claims.TenantID == state.tenantID || claims.WorkOrderID == state.workOrderID ||
				claims.OperationID != artifact.OperationID || claims.AttemptID != artifact.AttemptID || claims.FencingToken != artifact.FencingToken {
				server.reject(writer, "invalid cross-tenant operation admission", http.StatusForbidden)
				return
			}
			server.mu.Lock()
			server.counts.CrossTenantOperationReadRejections++
			server.mu.Unlock()
			writeJSONValue(writer, http.StatusNotFound, provider.StandardError{Code: "SANDBOX_NOT_FOUND", Message: "cross-tenant operation not found", Retryable: false, TraceID: "test-trace"})
			return
		}
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid operation admission", http.StatusForbidden)
			return
		}
		state, ok := server.lifecycle()
		server.mu.Lock()
		known := ok && request.URL.Path == "/v1/operations/"+state.operationID
		if server.execRequest != nil {
			known = known || request.URL.Path == "/v1/operations/"+server.execRequest.OperationID
		}
		if server.cancelRequest != nil {
			known = known || request.URL.Path == "/v1/operations/"+server.cancelRequest.OperationID
		}
		if server.sessionRequest != nil {
			known = known || request.URL.Path == "/v1/operations/"+server.sessionRequest.OperationID
		}
		if server.artifactRequest != nil {
			known = known || request.URL.Path == "/v1/operations/"+server.artifactRequest.OperationID
		}
		server.mu.Unlock()
		if !known {
			server.reject(writer, "unknown operation", http.StatusNotFound)
			return
		}
		server.mu.Lock()
		server.counts.Operations++
		server.mu.Unlock()
		status := "succeeded"
		typ := "create"
		opID := state.operationID
		attemptID := state.attemptID
		fence := state.fencingToken
		server.mu.Lock()
		if server.execRequest != nil && request.URL.Path == "/v1/operations/"+server.execRequest.OperationID {
			opID, attemptID, fence, typ = server.execRequest.OperationID, server.execRequest.AttemptID, server.execRequest.FencingToken, "exec"
			if server.cancelRequest != nil && server.cancelRequest.TargetOperationID == server.execRequest.OperationID && server.cancelRequest.TargetAttemptID == server.execRequest.AttemptID {
				status = "cancelled"
			}
		}
		if server.cancelRequest != nil && request.URL.Path == "/v1/operations/"+server.cancelRequest.OperationID {
			opID, attemptID, fence, typ, status = server.cancelRequest.OperationID, server.cancelRequest.AttemptID, server.cancelRequest.FencingToken, "cancel_exec", "succeeded"
		}
		if server.sessionRequest != nil && request.URL.Path == "/v1/operations/"+server.sessionRequest.OperationID {
			opID, attemptID, fence, typ = server.sessionRequest.OperationID, server.sessionRequest.AttemptID, server.sessionRequest.FencingToken, "open_runtime_session"
		}
		if server.artifactRequest != nil && request.URL.Path == "/v1/operations/"+server.artifactRequest.OperationID {
			opID, attemptID, fence, typ = server.artifactRequest.OperationID, server.artifactRequest.AttemptID, server.artifactRequest.FencingToken, "artifact_stage"
		}
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusOK, operationWithType(opID, attemptID, fence, state.sandboxID, typ, status))
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/exec-result"):
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid exec result admission", http.StatusForbidden)
			return
		}
		operationID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/operations/"), "/exec-result")
		server.mu.Lock()
		server.counts.ExecResults++
		retained, retainedOK := server.execResults[operationID]
		exec := server.execRequest
		server.mu.Unlock()
		if retainedOK {
			writeJSONValue(writer, http.StatusOK, retained)
			return
		}
		if exec == nil || operationID != exec.OperationID {
			server.reject(writer, "unknown exec", http.StatusNotFound)
			return
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		zero := 0
		status := "completed"
		var exitCode *int = &zero
		stdoutReference := "ref:stdout:synthetic"
		server.mu.Lock()
		if server.cancelRequest != nil && server.cancelRequest.TargetOperationID == exec.OperationID && server.cancelRequest.TargetAttemptID == exec.AttemptID {
			status, exitCode, stdoutReference = "cancelled", nil, ""
		}
		server.mu.Unlock()
		result := provider.ExecResult{OperationID: exec.OperationID, AttemptID: exec.AttemptID, FencingToken: exec.FencingToken, SandboxID: stateSandbox(server), Status: status, ExitCode: exitCode, StdoutReference: stdoutReference, StartedAt: now, CompletedAt: now, RetainedUntil: time.Now().Add(time.Duration(exec.ResultRetentionSeconds) * time.Second).UTC().Format(time.RFC3339Nano)}
		server.mu.Lock()
		server.execResults[exec.OperationID] = cloneRetainedEvidence(RetainedEvidence{ExecResult: result}).ExecResult
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusOK, result)
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/usage-evidence"):
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid usage admission", http.StatusForbidden)
			return
		}
		operationID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/operations/"), "/usage-evidence")
		server.mu.Lock()
		exec := server.execRequest
		server.counts.UsageReads++
		retained, retainedOK := server.usageEvidence[operationID]
		server.mu.Unlock()
		if retainedOK {
			writeJSONValue(writer, http.StatusOK, retained)
			return
		}
		if exec == nil || operationID != exec.OperationID {
			server.reject(writer, "unknown usage", http.StatusNotFound)
			return
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		usage := provider.UsageEvidence{
			EvidenceID: "synthetic-usage", SandboxID: stateSandbox(server), OperationID: exec.OperationID, AttemptID: exec.AttemptID, FencingToken: exec.FencingToken,
			Entries:              []provider.UsageEntry{{EntryID: "synthetic-exec-count", SandboxID: stateSandbox(server), OperationID: exec.OperationID, Meter: "sandbox.exec_count", Unit: "count", Quantity: 1, MeterSource: "reconciled", EvidenceReference: "ref:usage:synthetic", OccurredAt: now}},
			ReconciliationStatus: "partial", ObservedAt: now, RetainedUntil: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
			EvidenceDigest: jcs.DigestBytes([]byte("synthetic provider evidence")),
		}
		server.mu.Lock()
		server.usageEvidence[exec.OperationID] = cloneRetainedEvidence(RetainedEvidence{Usage: usage}).Usage
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusOK, usage)
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/runtime-session"):
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid runtime handoff admission", http.StatusForbidden)
			return
		}
		server.mu.Lock()
		server.counts.Handoffs++
		session := server.sessionRequest
		retained := server.retainedHandoff
		server.mu.Unlock()
		handoff, ok := retainedRuntimeSessionHandoff(session, retained, stateSandbox(server))
		if !ok || request.URL.Path != "/v1/operations/"+handoff.OperationID+"/runtime-session" {
			server.reject(writer, "unknown runtime session", http.StatusNotFound)
			return
		}
		server.mu.Lock()
		server.retainedHandoff = handoff
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusOK, handoff)
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/artifact-staging-evidence"):
		if actor != "controller_a" || !server.verifyAdmission(request, actor) {
			server.reject(writer, "invalid artifact evidence admission", http.StatusForbidden)
			return
		}
		operationID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/operations/"), "/artifact-staging-evidence")
		server.mu.Lock()
		artifact := server.artifactRequest
		server.counts.ArtifactEvidenceReads++
		retained, retainedOK := server.artifactEvidence[operationID]
		server.mu.Unlock()
		if retainedOK {
			writeJSONValue(writer, http.StatusOK, retained)
			return
		}
		if artifact == nil || operationID != artifact.OperationID {
			server.reject(writer, "unknown artifact evidence", http.StatusNotFound)
			return
		}
		now := time.Now().UTC()
		check := func(reference string) provider.ArtifactCheck {
			return provider.ArtifactCheck{Status: "passed", CheckedAt: now.Format(time.RFC3339Nano), EvidenceReference: reference}
		}
		evidence := provider.ArtifactStagingEvidence{
			OperationID: artifact.OperationID, AttemptID: artifact.AttemptID, FencingToken: artifact.FencingToken, SandboxID: stateSandbox(server),
			ArtifactReference: artifact.ArtifactReference, StagingReference: "ref:staging:synthetic", Status: "staged", ContentDigest: artifact.ExpectedDigest,
			MediaType: artifact.ExpectedMediaType, SizeBytes: artifact.MaxBytes, TenantBindingCheck: check("ref:check:tenant"), ActiveContentCheck: check("ref:check:active"), MalwareCheck: check("ref:check:malware"),
			ObservedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Duration(artifact.RetentionSeconds) * time.Second).Format(time.RFC3339Nano), EvidenceDigest: jcs.DigestBytes([]byte("synthetic artifact evidence")),
		}
		server.mu.Lock()
		server.artifactEvidence[artifact.OperationID] = evidence
		server.mu.Unlock()
		writeJSONValue(writer, http.StatusOK, evidence)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1/sandboxes/"):
		if actor == "controller_b" {
			claims, admission := server.verifyAdmissionStatusAndClaims(request, "controller_a", true)
			state, stateOK := server.lifecycle()
			if admission != admissionAccepted || !stateOK || request.URL.Path != "/v1/sandboxes/"+state.sandboxID || claims.Operation != "read_sandbox" || claims.SandboxID != state.sandboxID || claims.TenantID != state.tenantID || claims.WorkOrderID != state.workOrderID {
				server.reject(writer, "invalid mismatched mTLS caller admission", http.StatusForbidden)
				return
			}
			server.mu.Lock()
			server.counts.WrongMTLSCallerRejections++
			server.mu.Unlock()
			writeJSONValue(writer, http.StatusForbidden, provider.StandardError{Code: "SANDBOX_FORBIDDEN", Message: "mTLS caller and signed subject differ", Retryable: false, TraceID: "test-trace"})
			return
		}
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

type admissionStatus int

const (
	admissionInvalid admissionStatus = iota
	admissionAccepted
	admissionDuplicate
)

func (server *Server) verifyAdmission(request *http.Request, actor string) bool {
	return server.verifyAdmissionStatus(request, actor) == admissionAccepted
}

func (server *Server) verifyAdmissionStatus(request *http.Request, actor string) admissionStatus {
	_, status := server.verifyAdmissionStatusAndClaims(request, actor, true)
	return status
}

func (server *Server) verifyAdmissionStatusAndClaims(request *http.Request, actor string, enforceLifecycleBinding bool) (provider.JWSClaims, admissionStatus) {
	token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(token, ".")
	publicKey := server.keys[actor]
	if len(parts) != 3 || len(publicKey) != ed25519.PublicKeySize {
		return provider.JWSClaims{}, admissionInvalid
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return provider.JWSClaims{}, admissionInvalid
	}
	claimsBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return provider.JWSClaims{}, admissionInvalid
	}
	var claims provider.JWSClaims
	if json.Unmarshal(claimsBytes, &claims) != nil || claims.Subject != "spiffe://provider/"+actor || claims.ProviderRevisionID != Capabilities().ProviderRevisionID {
		return provider.JWSClaims{}, admissionInvalid
	}
	contextBytes, err := base64.RawURLEncoding.Strict().DecodeString(request.Header.Get(provider.AdmissionHeaderName))
	if err != nil {
		return provider.JWSClaims{}, admissionInvalid
	}
	var admissionContext provider.AdmissionContext
	if json.Unmarshal(contextBytes, &admissionContext) != nil || !boundAdmission(request, claims, admissionContext) {
		return provider.JWSClaims{}, admissionInvalid
	}
	if enforceLifecycleBinding && claims.Operation != "create" {
		state, ok := server.lifecycle()
		if !ok || claims.SandboxID != state.sandboxID || claims.TenantID != state.tenantID || claims.WorkOrderID != state.workOrderID {
			return provider.JWSClaims{}, admissionInvalid
		}
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if enforceLifecycleBinding {
		if server.policyDigest == "" {
			server.policyDigest, server.policyDecided = claims.PolicyDigest, claims.PolicyDecidedAt
		}
		if claims.PolicyDigest != server.policyDigest || claims.PolicyDecidedAt != server.policyDecided {
			return provider.JWSClaims{}, admissionInvalid
		}
	}
	if _, duplicate := server.seenJTI[claims.JTI]; duplicate {
		return claims, admissionDuplicate
	}
	server.seenJTI[claims.JTI] = struct{}{}
	return claims, admissionAccepted
}

func peerActor(request *http.Request) string {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || len(request.TLS.PeerCertificates[0].URIs) != 1 {
		return ""
	}
	value := request.TLS.PeerCertificates[0].URIs[0].String()
	return strings.TrimPrefix(value, "spiffe://provider/")
}

func operation(operationID, attemptID string, fencingToken int64, sandboxID, status string) provider.ProviderOperation {
	return operationWithType(operationID, attemptID, fencingToken, sandboxID, "create", status)
}

func operationWithType(operationID, attemptID string, fencingToken int64, sandboxID, typ, status string) provider.ProviderOperation {
	return provider.ProviderOperation{
		OperationID: operationID, AttemptID: attemptID, FencingToken: fencingToken, SandboxID: sandboxID,
		Type: typ, Status: status, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func stateSandbox(server *Server) string {
	state, ok := server.lifecycle()
	if !ok {
		return "sandbox-unknown"
	}
	return state.sandboxID
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
