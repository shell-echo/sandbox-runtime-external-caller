package gateway

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
)

func TestMTLSLoopbackAuthorizesBeforeResolutionAndForwardsBytes(t *testing.T) {
	resolver := newStatefulResolver()
	core := newTestGateway(t, resolver)
	pki := newLoopbackPKI(t)
	server := startLoopbackGateway(t, core, pki.server)
	token := issueTestGrant(t, core, time.Now().Add(time.Minute))

	if connection, err := DialTunnel(context.Background(), server.endpoint, token, pki.controllerB); connection != nil || !errors.Is(err, ErrUpgradeRejected) {
		t.Fatalf("wrong caller DialTunnel() = %v, %v", connection, err)
	}
	if resolver.Calls() != 0 {
		t.Fatal("wrong caller reached backend resolver")
	}
	if connection, err := DialTunnelWithoutClientCertificate(context.Background(), server.endpoint, token, pki.anonymous); connection != nil || !errors.Is(err, ErrUpgradeRejected) {
		t.Fatalf("unauthenticated DialTunnel() = %v, %v", connection, err)
	}
	if resolver.Calls() != 0 {
		t.Fatal("unauthenticated caller reached backend resolver")
	}

	connection, err := DialTunnel(context.Background(), server.endpoint, token, pki.controllerA)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if response := tunnelCommand(t, connection, "ECHO candidate-owned-bytes"); response != "candidate-owned-bytes" {
		t.Fatalf("round-trip response = %q", response)
	}
	if resolver.Calls() != 1 || resolver.LastReference() != "ref:session:opaque-1" {
		t.Fatalf("backend resolutions = %d, last reference = %q", resolver.Calls(), resolver.LastReference())
	}
}

func TestLiveTunnelClosesOnExpiryAndAuthorizedRevocation(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		resolver := newStatefulResolver()
		core := newTestGateway(t, resolver)
		pki := newLoopbackPKI(t)
		server := startLoopbackGateway(t, core, pki.server)
		token := issueTestGrant(t, core, time.Now().Add(200*time.Millisecond))
		connection, err := DialTunnel(context.Background(), server.endpoint, token, pki.controllerA)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		assertConnectionCloses(t, connection)
	})

	t.Run("revocation", func(t *testing.T) {
		resolver := newStatefulResolver()
		core := newTestGateway(t, resolver)
		pki := newLoopbackPKI(t)
		server := startLoopbackGateway(t, core, pki.server)
		token := issueTestGrant(t, core, time.Now().Add(time.Minute))
		connection, err := DialTunnel(context.Background(), server.endpoint, token, pki.controllerA)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := core.Revoke(context.Background(), token, controllerBSubject); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("wrong-subject Revoke() error = %v", err)
		}
		if response := tunnelCommand(t, connection, "ECHO still-open"); response != "still-open" {
			t.Fatalf("wrong-subject revocation response = %q", response)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := core.Revoke(ctx, token, controllerASubject); err != nil {
			t.Fatal(err)
		}
		assertConnectionClosed(t, connection)
	})
}

func TestNewGatewayUsesReconstructedCallerStateForTerminalContinuity(t *testing.T) {
	stateRoot := newCompleteCallerState(t)
	reconstructed, err := callerstate.OpenReconstruction(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	state := reconstructed.Snapshot()
	if err := reconstructed.Close(); err != nil {
		t.Fatal(err)
	}

	resolver := newStatefulResolver()
	pki := newLoopbackPKI(t)
	policy := map[string]string{controllerASubject: state.Plan.TenantAID, controllerBSubject: state.Plan.TenantBID}
	first, err := New(policy, resolver)
	if err != nil {
		t.Fatal(err)
	}
	firstServer := startLoopbackGateway(t, first, pki.server)
	firstToken := issueStateGrant(t, first, state)
	firstConnection, err := DialTunnel(context.Background(), firstServer.endpoint, firstToken, pki.controllerA)
	if err != nil {
		t.Fatal(err)
	}
	if response := tunnelCommand(t, firstConnection, "SET restart-marker"); response != "OK" {
		t.Fatalf("SET response = %q", response)
	}
	_ = firstConnection.Close()
	firstServer.stop(t)

	reloaded, err := callerstate.OpenReconstruction(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	reloadedState := reloaded.Snapshot()
	if err := reloaded.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := New(policy, resolver)
	if err != nil {
		t.Fatal(err)
	}
	secondServer := startLoopbackGateway(t, second, pki.server)
	secondToken := issueStateGrant(t, second, reloadedState)
	secondConnection, err := DialTunnel(context.Background(), secondServer.endpoint, secondToken, pki.controllerA)
	if err != nil {
		t.Fatal(err)
	}
	defer secondConnection.Close()
	if response := tunnelCommand(t, secondConnection, "GET"); response != "restart-marker" {
		t.Fatalf("reconstructed terminal response = %q", response)
	}
	if resolver.Calls() != 2 || resolver.LastReference() != state.Terminal.HandoffReference || reloadedState.Terminal.HandoffReference != state.Terminal.HandoffReference {
		t.Fatalf("reconstruction binding mismatch: calls=%d reference=%q", resolver.Calls(), resolver.LastReference())
	}
}

type loopbackPKI struct {
	server      *tls.Config
	controllerA *tls.Config
	controllerB *tls.Config
	anonymous   *tls.Config
}

func newLoopbackPKI(t *testing.T) loopbackPKI {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway loopback root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCertificate)

	serverCertificate := issueLoopbackCertificate(t, caCertificate, caKey, big.NewInt(2), "gateway loopback server", nil, []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth)
	controllerAURI, _ := url.Parse(controllerASubject)
	controllerBURI, _ := url.Parse(controllerBSubject)
	controllerACertificate := issueLoopbackCertificate(t, caCertificate, caKey, big.NewInt(3), "gateway controller A", []*url.URL{controllerAURI}, nil, x509.ExtKeyUsageClientAuth)
	controllerBCertificate := issueLoopbackCertificate(t, caCertificate, caKey, big.NewInt(4), "gateway controller B", []*url.URL{controllerBURI}, nil, x509.ExtKeyUsageClientAuth)
	clientConfig := func(certificate *tls.Certificate) *tls.Config {
		config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1", RootCAs: rootPool, NextProtos: []string{"http/1.1"}}
		if certificate != nil {
			config.Certificates = []tls.Certificate{*certificate}
		}
		return config
	}
	return loopbackPKI{
		server: &tls.Config{
			MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCertificate}, ClientCAs: rootPool,
			ClientAuth: tls.VerifyClientCertIfGiven, NextProtos: []string{"http/1.1"},
		},
		controllerA: clientConfig(&controllerACertificate), controllerB: clientConfig(&controllerBCertificate), anonymous: clientConfig(nil),
	}
}

func issueLoopbackCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial *big.Int, commonName string, uris []*url.URL, addresses []net.IP, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: uris, IPAddresses: addresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

type loopbackGateway struct {
	endpoint string
	server   *http.Server
	listener net.Listener
	done     chan error
	once     sync.Once
}

func startLoopbackGateway(t *testing.T, core *Gateway, tlsConfig *tls.Config) *loopbackGateway {
	t.Helper()
	handler, err := NewHandler(core, "/tunnel")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, tlsConfig.Clone())
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second}
	running := &loopbackGateway{
		endpoint: "https://" + listener.Addr().String() + "/tunnel", server: server, listener: tlsListener, done: make(chan error, 1),
	}
	go func() { running.done <- server.Serve(tlsListener) }()
	t.Cleanup(func() { running.stop(t) })
	return running
}

func (server *loopbackGateway) stop(t *testing.T) {
	t.Helper()
	server.once.Do(func() {
		_ = server.server.Close()
		_ = server.listener.Close()
		select {
		case err := <-server.done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Gateway server stopped with error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Gateway server did not stop")
		}
	})
}

type statefulResolver struct {
	mu         sync.Mutex
	calls      int
	lastRef    string
	terminalBy map[string]string
}

func newStatefulResolver() *statefulResolver {
	return &statefulResolver{terminalBy: make(map[string]string)}
}

func (resolver *statefulResolver) Open(ctx context.Context, reference string) (io.ReadWriteCloser, error) {
	resolver.mu.Lock()
	resolver.calls++
	resolver.lastRef = reference
	resolver.mu.Unlock()
	frontend, backend := net.Pipe()
	go resolver.serve(ctx, reference, backend)
	return frontend, nil
}

func (resolver *statefulResolver) serve(ctx context.Context, reference string, connection net.Conn) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer connection.Close()
	scanner := bufio.NewScanner(connection)
	for scanner.Scan() {
		command := scanner.Text()
		response := ""
		resolver.mu.Lock()
		switch {
		case strings.HasPrefix(command, "ECHO "):
			response = strings.TrimPrefix(command, "ECHO ")
		case strings.HasPrefix(command, "SET "):
			resolver.terminalBy[reference] = strings.TrimPrefix(command, "SET ")
			response = "OK"
		case command == "GET":
			response = resolver.terminalBy[reference]
		default:
			response = "UNKNOWN"
		}
		resolver.mu.Unlock()
		if _, err := io.WriteString(connection, response+"\n"); err != nil {
			return
		}
	}
}

func (resolver *statefulResolver) Calls() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.calls
}

func (resolver *statefulResolver) LastReference() string {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.lastRef
}

func tunnelCommand(t *testing.T, connection net.Conn, command string) string {
	t.Helper()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, command+"\n"); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(response, "\n")
}

func assertConnectionCloses(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("expired connection remained readable")
	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		t.Fatal("expired connection was not closed before timeout")
	}
}

func assertConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("revoked connection remained readable")
	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		t.Fatal("revoked connection was not closed")
	}
}

func newCompleteCallerState(t *testing.T) string {
	t.Helper()
	temporaryRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(temporaryRoot, "caller-state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := callerstate.CreateInitial(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, transition := range []func() error{
		func() error {
			return store.BindCapabilities("provider-revision-1", []byte(`{"api_version":"v1"}`), "sha256:"+strings.Repeat("f", 64), "2026-09-12T00:00:00Z")
		},
		func() error { return store.BindLifecycle(1) },
		func() error { return store.BindExec(2, testDigest('a'), testDigest('b')) },
		func() error { return store.BindTerminal(3, "runtime-session-1", "ref:session:caller-owned-opaque") },
		func() error { return store.BindArtifact(4, testDigest('c')) },
	} {
		if err := transition(); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return stateRoot
}

func issueStateGrant(t *testing.T, core *Gateway, state callerstate.State) string {
	t.Helper()
	token, err := core.IssueGrant(GrantRequest{
		ControllerSubject: controllerASubject, TenantID: state.Plan.TenantAID,
		RuntimeSessionID: state.Terminal.RuntimeSessionID, HandoffReference: state.Terminal.HandoffReference,
		ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func testDigest(character byte) string {
	return fmt.Sprintf("sha256:%s", strings.Repeat(string(character), 64))
}
