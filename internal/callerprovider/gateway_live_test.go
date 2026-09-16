//go:build darwin || linux

package callerprovider_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callercontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerphase"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerprovider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerterminal"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayprocess"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testprovider"
)

type probingService struct {
	*gatewayprocess.Service
	afterIssue      func(context.Context, string, string, string, string, time.Time)
	afterRevoke     func(context.Context, string)
	issues, revokes int
	failRevoke      bool
}

func (s *probingService) IssueGrant(ctx context.Context, actor, tenant, session, handoff string, expiry time.Time) (string, error) {
	s.issues++
	token, err := s.Service.IssueGrant(ctx, actor, tenant, session, handoff, expiry)
	if err == nil {
		s.afterIssue(ctx, token, tenant, session, handoff, expiry)
	}
	return token, err
}

func (s *probingService) Revoke(ctx context.Context, actor, token string) error {
	s.revokes++
	if s.failRevoke {
		return errors.New("synthetic ambiguous revocation")
	}
	err := s.Service.Revoke(ctx, actor, token)
	if err == nil {
		s.afterRevoke(ctx, token)
	}
	return err
}

// The synthetic Provider supplies the real HTTP handoff document; the built
// production Gateway receives its exact reference through private control.
// The Caller retains Provider credentials and bridges only the connected byte
// stream to the Gateway process.
func TestInitialPhaseWithLiveGatewayGrantExpiryAndRevocation(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "caller-gateway")
	buildCtx, buildCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer buildCancel()
	build := exec.CommandContext(buildCtx, "go", "build", "-o", executable, "../../cmd/caller-gateway")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Gateway: %v: %s", err, output)
	}
	for _, mode := range []string{"consumed", "terminal_eof", "revoked_unused", "expired", "revoke_failure", "cancel_after_issue"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			endpoint := "https://" + listener.Addr().String() + "/tunnel"
			_ = listener.Close()
			fixture := testcredentials.NewForGatewayHost(t, "127.0.0.1")
			provider := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
			provider.SetTerminalCloseAfterWrite(mode == "terminal_eof")
			bundle := readBundle(t, fixture.Payloads)
			defer bundle.Destroy()
			configs := make(map[string]*tls.Config)
			for _, actor := range []string{"controller_a", "controller_b"} {
				access, err := credentials.BuildGatewayAccessFromBundle(bundle, endpoint, actor)
				if err != nil {
					t.Fatal(err)
				}
				configs[actor] = access.TLSConfig
			}
			root := privateRoot(t)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			request := callercontrol.Request{Phase: "initial", Deadline: deadline, ProviderOrigin: provider.Origin(), GatewayProbeEndpoint: endpoint, CallerStateRoot: root}
			runner := gatewayprocess.NewServiceRunner(executable)
			var observed *probingService
			var authority *callerterminal.Authority
			var privateToken string
			var forwarded bool
			start := func(ctx context.Context, phase, endpoint string, bundle *credentials.Bundle) (callerphase.GatewayService, error) {
				service, err := runner.Start(ctx, phase, endpoint, bundle)
				if err != nil {
					return nil, err
				}
				observed = &probingService{Service: service, failRevoke: mode == "revoke_failure"}
				observed.afterIssue = func(ctx context.Context, token, tenant, session, handoff string, expiry time.Time) {
					privateToken = token
					if authority == nil || session != authority.RuntimeSessionID || handoff != authority.HandoffReference || !expiry.Equal(authority.ExpiresAt) {
						t.Fatal("control grant changed the freshly checked Provider authority")
					}
					if _, err := service.IssueGrant(ctx, "controller_b", tenant, session, handoff, expiry); err == nil {
						t.Fatal("cross-tenant grant was accepted")
					}
					if err := service.Revoke(ctx, "controller_b", token); err == nil {
						t.Fatal("cross-controller revocation was accepted")
					}
					probeGatewayStatus(t, ctx, endpoint, token, configs["controller_b"], http.StatusForbidden)
					switch mode {
					case "consumed", "terminal_eof":
						connection, err := gateway.DialTunnel(ctx, endpoint, token, configs["controller_a"])
						if err != nil {
							t.Fatalf("authorized terminal tunnel: %v", err)
						}
						payload := []byte{0, 'c', 'a', 'l', 'l', 'e', 'r', 0xff, '\n'}
						if _, err := connection.Write(payload); err != nil {
							t.Fatal("terminal input write failed")
						}
						got := make([]byte, len(payload))
						if _, err := io.ReadFull(connection, got); err != nil || !bytes.Equal(got, payload) {
							t.Fatal("terminal bytes did not round trip exactly")
						}
						if mode == "terminal_eof" {
							_ = connection.SetReadDeadline(time.Now().Add(time.Second))
							if n, err := connection.Read(make([]byte, 1)); err == nil || n != 0 {
								t.Fatal("Provider terminal EOF did not close the Gateway tunnel")
							}
						}
						_ = connection.Close()
						forwarded = true
						probeGatewayStatus(t, ctx, endpoint, token, configs["controller_a"], http.StatusForbidden)
					case "expired":
						timer := time.NewTimer(time.Until(expiry))
						defer timer.Stop()
						select {
						case <-timer.C:
						case <-ctx.Done():
							t.Fatal("phase expired before grant")
						}
						probeGatewayStatus(t, ctx, endpoint, token, configs["controller_a"], http.StatusForbidden)
					case "cancel_after_issue":
						cancel()
					}
				}
				observed.afterRevoke = func(ctx context.Context, token string) {
					probeGatewayStatus(t, ctx, endpoint, token, configs["controller_a"], http.StatusForbidden)
				}
				return observed, nil
			}
			runProvider := func(ctx context.Context, phase, origin string, bundle *credentials.Bundle, store *callerstate.Store) (*callerterminal.Authority, error) {
				var err error
				authority, err = callerprovider.Run(ctx, phase, origin, bundle, store)
				if err == nil && mode == "expired" {
					// A test-only shorter caller lifetime exercises actual expiry
					// without extending the Provider's validated authority.
					shorter := time.Now().Add(time.Second)
					if !shorter.Before(authority.ExpiresAt) {
						t.Fatal("insufficient Provider lifetime")
					}
					authority.ExpiresAt = shorter
				}
				return authority, err
			}
			err = callerphase.Coordinate(ctx, request, bundle, start, runProvider)
			var wantErr error
			if mode == "revoke_failure" {
				wantErr = callerphase.ErrGatewayLifecycle
			}
			if mode == "cancel_after_issue" {
				wantErr = context.Canceled
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("phase error = %v, want %v", err, wantErr)
			}
			if observed == nil || observed.issues != 1 || observed.revokes != 1 || forwarded != (mode == "consumed" || mode == "terminal_eof") || syscall.Kill(observed.PID(), 0) != syscall.ESRCH {
				t.Fatal("Gateway lifecycle did not issue/revoke once and reap")
			}
			parsed, _ := url.Parse(endpoint)
			if connection, err := net.DialTimeout("tcp", parsed.Host, 200*time.Millisecond); err == nil {
				_ = connection.Close()
				t.Fatal("Gateway listener survived stop")
			}
			stateBytes, err := os.ReadFile(filepath.Join(root, callerstate.StateFileName))
			if err != nil {
				t.Fatal(err)
			}
			if privateToken == "" || strings.Contains(string(stateBytes), privateToken) {
				t.Fatal("grant token absent or persisted")
			}
			counts, failures := provider.Snapshot()
			if len(failures) != 0 || counts.Handoffs != 1 || counts.Sessions != 1 || counts.TerminalConnects != map[bool]int{true: 1, false: 0}[mode == "consumed" || mode == "terminal_eof"] {
				t.Fatal("Provider terminal handoff was not read exactly once")
			}
		})
	}
}

func probeGatewayStatus(t *testing.T, ctx context.Context, endpoint, token string, config *tls.Config, want int) {
	t.Helper()
	parsed, _ := url.Parse(endpoint)
	dialer := tls.Dialer{Config: config, NetDialer: &net.Dialer{Timeout: time.Second}}
	connection, err := dialer.DialContext(ctx, "tcp", parsed.Host)
	if err != nil {
		t.Fatal("Gateway TLS probe failed")
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n\r\n", parsed.EscapedPath(), parsed.Host, token); err != nil {
		t.Fatal("Gateway request failed")
	}
	request, _ := http.NewRequest(http.MethodConnect, endpoint, nil)
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		t.Fatal("Gateway response failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1))
	if err != nil || response.StatusCode != want || len(body) != 0 {
		t.Fatalf("Gateway status = %d, want %d, body must be empty", response.StatusCode, want)
	}
}
