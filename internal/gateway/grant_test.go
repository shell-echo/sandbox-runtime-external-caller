package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

const (
	controllerASubject = "spiffe://gateway/controller-a"
	controllerBSubject = "spiffe://gateway/controller-b"
	tenantA            = "tenant-a"
	tenantB            = "tenant-b"
)

func TestGatewayPolicyAndGrantBinding(t *testing.T) {
	resolver := &recordingResolver{}
	if _, err := New(map[string]string{controllerASubject: tenantA}, resolver); !errors.Is(err, ErrPolicy) {
		t.Fatalf("New(one actor) error = %v", err)
	}
	if _, err := New(map[string]string{controllerASubject: tenantA, controllerBSubject: tenantA}, resolver); !errors.Is(err, ErrPolicy) {
		t.Fatalf("New(shared tenant) error = %v", err)
	}
	gateway := newTestGateway(t, resolver)
	expiresAt := time.Now().Add(time.Minute)
	token, err := gateway.IssueGrant(GrantRequest{
		ControllerSubject: controllerASubject, TenantID: tenantA, RuntimeSessionID: "session-1",
		HandoffReference: "ref:session:opaque-1", ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != grantTokenBytes {
		t.Fatalf("grant token shape = %q, %v", token, err)
	}
	if _, err := gateway.IssueGrant(GrantRequest{
		ControllerSubject: controllerASubject, TenantID: tenantB, RuntimeSessionID: "session-1",
		HandoffReference: "ref:session:opaque-1", ExpiresAt: expiresAt,
	}); !errors.Is(err, ErrGrantRequest) {
		t.Fatalf("cross-tenant IssueGrant error = %v", err)
	}
	if _, err := gateway.IssueGrant(GrantRequest{
		ControllerSubject: controllerASubject, TenantID: tenantA, RuntimeSessionID: "session-1",
		HandoffReference: "ref:session:opaque-1", ExpiresAt: time.Now().Add(maxGrantTTL + time.Second),
	}); !errors.Is(err, ErrGrantRequest) {
		t.Fatalf("oversized TTL error = %v", err)
	}
	permit, err := gateway.BeginConnect(context.Background(), token, controllerASubject)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()
	if binding := permit.Binding(); binding.ControllerSubject != controllerASubject || binding.TenantID != tenantA || binding.RuntimeSessionID != "session-1" || binding.HandoffReference != "ref:session:opaque-1" {
		t.Fatalf("permit binding = %#v", binding)
	}
	if _, err := gateway.BeginConnect(context.Background(), token, controllerASubject); !errors.Is(err, ErrGrantAlreadyUsed) {
		t.Fatalf("grant replay error = %v", err)
	}
}

func TestGatewayRejectsWrongCallerBeforeBackendResolution(t *testing.T) {
	resolver := &recordingResolver{}
	gateway := newTestGateway(t, resolver)
	token := issueTestGrant(t, gateway, time.Now().Add(time.Minute))
	if _, err := gateway.BeginConnect(context.Background(), token, controllerBSubject); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong-caller BeginConnect error = %v", err)
	}
	if resolver.Calls() != 0 {
		t.Fatal("wrong caller reached backend resolver")
	}
}

func TestGatewayExpiryClosesAttachedTransports(t *testing.T) {
	gateway := newTestGateway(t, &recordingResolver{})
	token := issueTestGrant(t, gateway, time.Now().Add(80*time.Millisecond))
	permit, err := gateway.BeginConnect(context.Background(), token, controllerASubject)
	if err != nil {
		t.Fatal(err)
	}
	frontend, backend := &trackingCloser{}, &trackingCloser{}
	if err := permit.Attach(frontend, backend); err != nil {
		t.Fatal(err)
	}
	select {
	case <-permit.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("permit did not expire")
	}
	if !errors.Is(context.Cause(permit.Context()), ErrGrantExpired) {
		t.Fatalf("expiry cause = %v", context.Cause(permit.Context()))
	}
	deadline := time.Now().Add(time.Second)
	for (!frontend.Closed() || !backend.Closed()) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !frontend.Closed() || !backend.Closed() {
		t.Fatal("expiry did not close both transports")
	}
	_ = permit.Close()
}

func TestGatewayRevocationWaitsForPermitClosure(t *testing.T) {
	gateway := newTestGateway(t, &recordingResolver{})
	token := issueTestGrant(t, gateway, time.Now().Add(time.Minute))
	permit, err := gateway.BeginConnect(context.Background(), token, controllerASubject)
	if err != nil {
		t.Fatal(err)
	}
	frontend, backend := &trackingCloser{}, &trackingCloser{}
	if err := permit.Attach(frontend, backend); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Revoke(context.Background(), token, controllerBSubject); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong-caller Revoke error = %v", err)
	}
	if frontend.Closed() || backend.Closed() {
		t.Fatal("wrong-caller revocation closed transports")
	}
	go func() {
		<-permit.Context().Done()
		_ = permit.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gateway.Revoke(ctx, token, controllerASubject); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(context.Cause(permit.Context()), ErrGrantRevoked) || !frontend.Closed() || !backend.Closed() {
		t.Fatalf("revocation state = cause %v front %v back %v", context.Cause(permit.Context()), frontend.Closed(), backend.Closed())
	}
	if _, err := gateway.BeginConnect(context.Background(), token, controllerASubject); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("revoked BeginConnect error = %v", err)
	}
}

func TestPermitAttachAfterCancellationClosesInputs(t *testing.T) {
	gateway := newTestGateway(t, &recordingResolver{})
	token := issueTestGrant(t, gateway, time.Now().Add(time.Minute))
	parent, cancel := context.WithCancel(context.Background())
	permit, err := gateway.BeginConnect(parent, token, controllerASubject)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	frontend, backend := &trackingCloser{}, &trackingCloser{}
	if err := permit.Attach(frontend, backend); !errors.Is(err, ErrPermitClosed) {
		t.Fatalf("Attach after cancel error = %v", err)
	}
	if !frontend.Closed() || !backend.Closed() {
		t.Fatal("rejected Attach did not close supplied transports")
	}
	_ = permit.Close()
}

func newTestGateway(t *testing.T, resolver Resolver) *Gateway {
	t.Helper()
	gateway, err := New(map[string]string{controllerASubject: tenantA, controllerBSubject: tenantB}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func issueTestGrant(t *testing.T, gateway *Gateway, expiresAt time.Time) string {
	t.Helper()
	token, err := gateway.IssueGrant(GrantRequest{
		ControllerSubject: controllerASubject, TenantID: tenantA, RuntimeSessionID: "session-1",
		HandoffReference: "ref:session:opaque-1", ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type recordingResolver struct {
	mu    sync.Mutex
	calls int
}

func (r *recordingResolver) Open(context.Context, string) (io.ReadWriteCloser, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return nil, errors.New("synthetic unavailable backend")
}

func (r *recordingResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type trackingCloser struct {
	mu     sync.Mutex
	closed bool
}

func (c *trackingCloser) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *trackingCloser) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}
