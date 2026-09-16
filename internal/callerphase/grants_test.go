//go:build darwin || linux

package callerphase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerterminal"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
)

func TestInitialGrantUsesCallerOwnershipAndEarliestExpiry(t *testing.T) {
	for _, limit := range []string{"handoff", "phase", "parent"} {
		t.Run(limit, func(t *testing.T) {
			root := newPrivateRoot(t)
			bundle := testBundle(t)
			defer bundle.Destroy()
			request := testRequest("initial", root)
			ctx, cancel := context.WithDeadline(context.Background(), request.Deadline.Add(time.Second))
			defer cancel()
			wantExpiry := request.Deadline
			if limit == "parent" {
				var parentCancel context.CancelFunc
				wantExpiry = time.Now().Add(5 * time.Second)
				ctx, parentCancel = context.WithDeadline(ctx, wantExpiry)
				defer parentCancel()
			}
			service := &recordingService{}
			token := strings.Repeat("A", 43)
			service.grantHook = func(grantCtx context.Context, actor, tenant, session, handoff string, expiry time.Time) (string, error) {
				state := readState(t, root)
				if !service.installed || service.revoked || service.stopped || actor != "controller_a" || tenant != state.Plan.TenantAID || session != state.Terminal.RuntimeSessionID || handoff != state.Terminal.HandoffReference || !expiry.Equal(wantExpiry) {
					t.Fatal("grant did not preserve caller ownership, terminal binding, expiry or ordering")
				}
				deadline, _ := grantCtx.Deadline()
				if expiry.After(deadline) {
					t.Fatal("grant extended phase authority")
				}
				return token, nil
			}
			service.revokeHook = func(_ context.Context, actor, gotToken string) error {
				if !service.granted || service.stopped || actor != "controller_a" || gotToken != token {
					t.Fatal("revocation did not precede stop with the exact owner/token")
				}
				return nil
			}
			provider := func(ctx context.Context, phase, origin string, bundle *credentials.Bundle, store *callerstate.Store) (*callerterminal.Authority, error) {
				authority, err := fakeProvider(ctx, phase, origin, bundle, store)
				if err == nil && limit == "handoff" {
					wantExpiry = time.Now().Add(5 * time.Second)
					authority.ExpiresAt = wantExpiry
				}
				return authority, err
			}
			if err := Coordinate(ctx, request, bundle, func(context.Context, string, string, *credentials.Bundle) (GatewayService, error) {
				return service, nil
			}, provider); err != nil {
				t.Fatal(err)
			}
			if !service.granted || !service.revoked || !service.stopped || service.waited {
				t.Fatal("grant lifecycle incomplete")
			}
		})
	}
}

func TestInitialRejectsMissingExpiredOrMismatchedTerminalAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*callerterminal.Authority) *callerterminal.Authority
	}{
		{"missing", func(*callerterminal.Authority) *callerterminal.Authority { return nil }},
		{"expired", func(a *callerterminal.Authority) *callerterminal.Authority {
			a.ExpiresAt = time.Now().Add(-time.Second)
			return a
		}},
		{"zero_expiry", func(a *callerterminal.Authority) *callerterminal.Authority { a.ExpiresAt = time.Time{}; return a }},
		{"provider", func(a *callerterminal.Authority) *callerterminal.Authority { a.ProviderRevisionID += "other"; return a }},
		{"sandbox", func(a *callerterminal.Authority) *callerterminal.Authority { a.SandboxID += "other"; return a }},
		{"operation", func(a *callerterminal.Authority) *callerterminal.Authority { a.OperationID += "other"; return a }},
		{"attempt", func(a *callerterminal.Authority) *callerterminal.Authority { a.AttemptID += "other"; return a }},
		{"fence", func(a *callerterminal.Authority) *callerterminal.Authority { a.FencingToken++; return a }},
		{"session", func(a *callerterminal.Authority) *callerterminal.Authority { a.RuntimeSessionID += "other"; return a }},
		{"handoff", func(a *callerterminal.Authority) *callerterminal.Authority { a.HandoffReference += "other"; return a }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := newPrivateRoot(t)
			bundle := testBundle(t)
			defer bundle.Destroy()
			service := &recordingService{}
			provider := func(ctx context.Context, phase, origin string, bundle *credentials.Bundle, store *callerstate.Store) (*callerterminal.Authority, error) {
				authority, err := fakeProvider(ctx, phase, origin, bundle, store)
				if err != nil {
					return nil, err
				}
				return test.change(authority), nil
			}
			err := Coordinate(context.Background(), testRequest("initial", root), bundle, func(context.Context, string, string, *credentials.Bundle) (GatewayService, error) {
				return service, nil
			}, provider)
			if err != ErrGatewayLifecycle || service.granted || service.revoked || service.stopped || !service.waited || readState(t, root).Stage != callerstate.StageTerminalBound {
				t.Fatalf("invalid authority did not fail closed: %v", err)
			}
		})
	}
}

func TestGrantFailuresCancelAndReapWithoutRetryOrSuccessfulStop(t *testing.T) {
	for _, failure := range []string{"issue", "malformed_token", "revoke", "cancel_issue", "cancel_revoke"} {
		t.Run(failure, func(t *testing.T) {
			root := newPrivateRoot(t)
			bundle := testBundle(t)
			defer bundle.Destroy()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			service := &recordingService{}
			issues, revokes := 0, 0
			var serviceContext context.Context
			service.grantHook = func(ctx context.Context, _, _, _, _ string, _ time.Time) (string, error) {
				issues++
				switch failure {
				case "issue":
					return "", errors.New("synthetic issue failure")
				case "malformed_token":
					return "invalid", nil
				case "cancel_issue":
					cancel()
					return "", context.Cause(ctx)
				}
				return strings.Repeat("A", 43), nil
			}
			service.revokeHook = func(ctx context.Context, _, _ string) error {
				revokes++
				if failure == "cancel_revoke" {
					cancel()
					return context.Cause(ctx)
				}
				return errors.New("synthetic revoke failure")
			}
			err := Coordinate(ctx, testRequest("initial", root), bundle, func(ctx context.Context, _, _ string, _ *credentials.Bundle) (GatewayService, error) {
				serviceContext = ctx
				return service, nil
			}, fakeProvider)
			want := ErrGatewayLifecycle
			if strings.HasPrefix(failure, "cancel_") {
				want = context.Canceled
			}
			wantRevokes := 0
			if failure == "revoke" || failure == "cancel_revoke" {
				wantRevokes = 1
			}
			if !errors.Is(err, want) || issues != 1 || revokes != wantRevokes || serviceContext.Err() == nil || !service.waited || service.stopped || readState(t, root).StoreRevision != 5 {
				t.Fatalf("failure cleanup = %v, issue/revoke attempts %d/%d", err, issues, revokes)
			}
		})
	}
}
