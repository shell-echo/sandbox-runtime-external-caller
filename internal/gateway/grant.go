// Package gateway implements the candidate-owned terminal Gateway. Its grant
// and tunnel protocol is private consumer behavior, not Provider wire API.
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	grantTokenBytes = 32
	maxGrantTTL     = 5 * time.Minute
	maxGrants       = 64
)

var (
	ErrPolicy             = errors.New("gateway identity policy is invalid")
	ErrGrantRequest       = errors.New("gateway grant request is invalid")
	ErrGrantCapacity      = errors.New("gateway grant capacity exceeded")
	ErrUnauthorized       = errors.New("gateway authorization rejected")
	ErrGrantExpired       = errors.New("gateway grant expired")
	ErrGrantRevoked       = errors.New("gateway grant revoked")
	ErrGrantAlreadyUsed   = errors.New("gateway grant is already used")
	ErrPermitClosed       = errors.New("gateway connection permit is closed")
	ErrBackendUnavailable = errors.New("gateway backend is unavailable")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
)

type Resolver interface {
	Open(context.Context, string) (io.ReadWriteCloser, error)
}

type GrantRequest struct {
	ControllerSubject string
	TenantID          string
	RuntimeSessionID  string
	HandoffReference  string
	ExpiresAt         time.Time
}

type Binding struct {
	ControllerSubject string
	TenantID          string
	RuntimeSessionID  string
	HandoffReference  string
	ExpiresAt         time.Time
}

type Gateway struct {
	mu         sync.Mutex
	policy     map[string]string
	resolver   Resolver
	grants     map[[sha256.Size]byte]*grant
	connection uint64
	now        func() time.Time
}

type grant struct {
	binding Binding
	used    bool
	revoked bool
	permits map[uint64]*Permit
}

func New(identityPolicy map[string]string, resolver Resolver) (*Gateway, error) {
	if resolver == nil || len(identityPolicy) != 2 {
		return nil, ErrPolicy
	}
	policy := make(map[string]string, len(identityPolicy))
	seenTenants := make(map[string]struct{}, len(identityPolicy))
	for subject, tenant := range identityPolicy {
		if !validSubject(subject) || !identifierPattern.MatchString(tenant) {
			return nil, ErrPolicy
		}
		if _, duplicate := seenTenants[tenant]; duplicate {
			return nil, ErrPolicy
		}
		seenTenants[tenant] = struct{}{}
		policy[subject] = tenant
	}
	return &Gateway{
		policy: policy, resolver: resolver, grants: make(map[[sha256.Size]byte]*grant), now: time.Now,
	}, nil
}

// IssueGrant creates a one-connection bearer capability. Only an identity and
// tenant pair present in the immutable Gateway policy may receive one.
func (g *Gateway) IssueGrant(request GrantRequest) (string, error) {
	if g == nil || !validSubject(request.ControllerSubject) || !identifierPattern.MatchString(request.TenantID) || !identifierPattern.MatchString(request.RuntimeSessionID) || !validOpaqueReference(request.HandoffReference) || request.ExpiresAt.IsZero() {
		return "", ErrGrantRequest
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if tenant, ok := g.policy[request.ControllerSubject]; !ok || subtle.ConstantTimeCompare([]byte(tenant), []byte(request.TenantID)) != 1 || !request.ExpiresAt.After(now) || request.ExpiresAt.Sub(now) > maxGrantTTL {
		return "", ErrGrantRequest
	}
	g.purge(now)
	if len(g.grants) >= maxGrants {
		return "", ErrGrantCapacity
	}
	for attempt := 0; attempt < 4; attempt++ {
		rawToken := make([]byte, grantTokenBytes)
		if _, err := rand.Read(rawToken); err != nil {
			return "", ErrGrantRequest
		}
		token := base64.RawURLEncoding.EncodeToString(rawToken)
		key := sha256.Sum256([]byte(token))
		clear(rawToken)
		if _, collision := g.grants[key]; collision {
			continue
		}
		g.grants[key] = &grant{binding: Binding{
			ControllerSubject: request.ControllerSubject, TenantID: request.TenantID,
			RuntimeSessionID: request.RuntimeSessionID, HandoffReference: request.HandoffReference, ExpiresAt: request.ExpiresAt,
		}, permits: make(map[uint64]*Permit)}
		return token, nil
	}
	return "", ErrGrantCapacity
}

// BeginConnect consumes a grant and reserves a connection before any backend
// resolution. Revocation or expiry cancels its context.
func (g *Gateway) BeginConnect(parent context.Context, token, controllerSubject string) (*Permit, error) {
	if g == nil || !validSubject(controllerSubject) {
		return nil, ErrUnauthorized
	}
	key, ok := tokenKey(token)
	if !ok {
		return nil, ErrUnauthorized
	}
	if parent == nil {
		parent = context.Background()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	grant, ok := g.grants[key]
	if !ok || subtle.ConstantTimeCompare([]byte(grant.binding.ControllerSubject), []byte(controllerSubject)) != 1 {
		return nil, ErrUnauthorized
	}
	now := g.now()
	if grant.revoked {
		return nil, ErrGrantRevoked
	}
	if !now.Before(grant.binding.ExpiresAt) {
		return nil, ErrGrantExpired
	}
	if grant.used {
		return nil, ErrGrantAlreadyUsed
	}
	grant.used = true
	g.connection++
	deadlineContext, deadlineCancel := context.WithDeadlineCause(parent, grant.binding.ExpiresAt, ErrGrantExpired)
	permitContext, cancel := context.WithCancelCause(deadlineContext)
	permit := &Permit{
		gateway: g, key: key, connectionID: g.connection, binding: grant.binding,
		context: permitContext, cancel: cancel, deadlineCancel: deadlineCancel, done: make(chan struct{}),
	}
	grant.permits[permit.connectionID] = permit
	go permit.closeOnCancellation()
	return permit, nil
}

// Revoke is acknowledged only after every reserved or active permit has
// finished. A bounded caller context prevents an uncooperative Resolver from
// turning revocation into an unbounded wait.
func (g *Gateway) Revoke(ctx context.Context, token, controllerSubject string) error {
	if g == nil || !validSubject(controllerSubject) {
		return ErrUnauthorized
	}
	key, ok := tokenKey(token)
	if !ok {
		return ErrUnauthorized
	}
	if ctx == nil {
		ctx = context.Background()
	}
	g.mu.Lock()
	grant, ok := g.grants[key]
	if !ok || subtle.ConstantTimeCompare([]byte(grant.binding.ControllerSubject), []byte(controllerSubject)) != 1 {
		g.mu.Unlock()
		return ErrUnauthorized
	}
	grant.revoked = true
	permits := make([]*Permit, 0, len(grant.permits))
	for _, permit := range grant.permits {
		permits = append(permits, permit)
		permit.cancel(ErrGrantRevoked)
	}
	g.mu.Unlock()
	for _, permit := range permits {
		select {
		case <-permit.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (g *Gateway) openBackend(ctx context.Context, reference string) (io.ReadWriteCloser, error) {
	backend, err := g.resolver.Open(ctx, reference)
	if err != nil || backend == nil {
		if backend != nil {
			_ = backend.Close()
		}
		return nil, ErrBackendUnavailable
	}
	return backend, nil
}

func (g *Gateway) purge(now time.Time) {
	for key, grant := range g.grants {
		if len(grant.permits) == 0 && (grant.revoked || !now.Before(grant.binding.ExpiresAt)) {
			delete(g.grants, key)
		}
	}
}

type Permit struct {
	gateway        *Gateway
	key            [sha256.Size]byte
	connectionID   uint64
	binding        Binding
	context        context.Context
	cancel         context.CancelCauseFunc
	deadlineCancel context.CancelFunc
	done           chan struct{}

	mu               sync.Mutex
	frontend         io.Closer
	backend          io.Closer
	transportsClosed bool
	finishOnce       sync.Once
}

func (p *Permit) Context() context.Context { return p.context }

func (p *Permit) Binding() Binding { return p.binding }

func (p *Permit) Attach(frontend, backend io.Closer) error {
	if frontend == nil || backend == nil {
		return ErrPermitClosed
	}
	p.mu.Lock()
	if p.transportsClosed || p.context.Err() != nil || p.frontend != nil || p.backend != nil {
		p.mu.Unlock()
		_ = frontend.Close()
		_ = backend.Close()
		return ErrPermitClosed
	}
	p.frontend = frontend
	p.backend = backend
	p.mu.Unlock()
	return nil
}

func (p *Permit) closeOnCancellation() {
	<-p.context.Done()
	p.closeTransports()
}

func (p *Permit) closeTransports() {
	p.mu.Lock()
	if p.transportsClosed {
		p.mu.Unlock()
		return
	}
	p.transportsClosed = true
	frontend, backend := p.frontend, p.backend
	p.mu.Unlock()
	if frontend != nil {
		_ = frontend.Close()
	}
	if backend != nil {
		_ = backend.Close()
	}
}

func (p *Permit) Close() error {
	if p == nil {
		return nil
	}
	p.finishOnce.Do(func() {
		p.cancel(ErrPermitClosed)
		p.deadlineCancel()
		p.closeTransports()
		p.gateway.mu.Lock()
		if grant, ok := p.gateway.grants[p.key]; ok {
			delete(grant.permits, p.connectionID)
		}
		p.gateway.mu.Unlock()
		close(p.done)
	})
	return nil
}

func tokenKey(token string) ([sha256.Size]byte, bool) {
	var zero [sha256.Size]byte
	if token == "" || len(token) > 128 {
		return zero, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != grantTokenBytes || base64.RawURLEncoding.EncodeToString(decoded) != token {
		clear(decoded)
		return zero, false
	}
	clear(decoded)
	return sha256.Sum256([]byte(token)), true
}

func validSubject(value string) bool {
	if len(value) < 1 || len(value) > 200 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Fragment == ""
}

func validOpaqueReference(value string) bool {
	return len(value) >= 1 && len(value) <= 1024 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}
