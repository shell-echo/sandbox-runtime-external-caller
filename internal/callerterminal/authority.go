// Package callerterminal owns caller policy for a freshly validated terminal
// handoff. These values are private, transient authority, not Provider DTOs or
// durable qualification evidence.
package callerterminal

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
)

var ErrAuthority = errors.New("caller terminal authority is invalid")

// Authority is returned only after the Provider handoff has been checked
// against the requested session, profile, operation and lease. It must never
// be reconstructed from a retained reference alone.
type Authority struct {
	ProviderRevisionID   string
	SandboxID            string
	OperationID          string
	AttemptID            string
	FencingToken         int64
	RuntimeSessionID     string
	HandoffReference     string
	ConnectionGeneration int64
	ExpiresAt            time.Time

	mu     sync.Mutex
	opener BackendOpener
	closer func()
	closed bool
}

type BackendOpener func(context.Context, string) (io.ReadWriteCloser, error)

func (a *Authority) BindBackend(opener BackendOpener, closer func()) error {
	if a == nil || opener == nil || closer == nil {
		return ErrAuthority
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.opener != nil || a.closer != nil {
		return ErrAuthority
	}
	a.opener, a.closer = opener, closer
	return nil
}

func (a *Authority) Open(ctx context.Context, reference string) (io.ReadWriteCloser, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || reference != a.HandoffReference || !time.Now().Before(a.ExpiresAt) {
		return nil, ErrAuthority
	}
	a.mu.Lock()
	opener, closed := a.opener, a.closed
	a.mu.Unlock()
	if closed || opener == nil {
		return nil, ErrAuthority
	}
	return opener(ctx, reference)
}

func (a *Authority) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	closer := a.closer
	a.opener, a.closer = nil, nil
	a.mu.Unlock()
	if closer != nil {
		closer()
	}
}

type Gateway interface {
	SetBackend(BackendOpener) error
	IssueGrant(context.Context, string, string, string, string, time.Time) (string, error)
	Revoke(context.Context, string, string) error
}

// GrantAndRevoke installs the credential-owning backend opener before issuing
// one grant. Scenario code may consume it while IssueGrant is observed; this
// function itself does not claim a connection result. The phase owner must
// stop/reap the Gateway on any failure, including an ambiguous issue/revoke
// response; neither mutation is retried.
func GrantAndRevoke(ctx context.Context, state callerstate.State, authority *Authority, gateway Gateway) error {
	if ctx == nil || gateway == nil || authority == nil {
		return ErrAuthority
	}
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	deadline, ok := ctx.Deadline()
	if !ok || state.Stage != callerstate.StageTerminalBound || state.Provider == nil || state.Terminal == nil ||
		authority.ProviderRevisionID != state.Provider.ProviderRevisionID || authority.SandboxID != state.Plan.SandboxID ||
		authority.OperationID != state.Terminal.Operation.OperationID || authority.AttemptID != state.Terminal.Operation.AttemptID ||
		authority.FencingToken != state.Terminal.Operation.FencingToken || authority.RuntimeSessionID != state.Terminal.RuntimeSessionID ||
		authority.HandoffReference != state.Terminal.HandoffReference {
		return ErrAuthority
	}
	expiresAt := authority.ExpiresAt
	if deadline.Before(expiresAt) {
		expiresAt = deadline
	}
	if !expiresAt.After(time.Now()) {
		return ErrAuthority
	}
	if err := gateway.SetBackend(authority.Open); err != nil {
		return err
	}
	// Only controller A owns the session opened in this initial flow. Neither
	// the Provider nor the transient handoff selects the business actor/tenant.
	token, err := gateway.IssueGrant(ctx, "controller_a", state.Plan.TenantAID, authority.RuntimeSessionID, authority.HandoffReference, expiresAt)
	if err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	valid := err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == token
	clear(raw)
	if !valid {
		return ErrAuthority
	}
	return gateway.Revoke(ctx, "controller_a", token)
}
