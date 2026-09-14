//go:build darwin || linux

package gatewayapp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewaycontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayservice"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
)

// The backend exists only in this test binary, not the caller-gateway artifact.
// Its extra observation FD counts all resolutions, independently of HTTP replies.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--gateway-service-test-child" {
		observations := os.NewFile(6, "test-backend-observations")
		code := RunWithResolver(nil, os.Stdin, os.Stdout, observedEcho{observations})
		_ = observations.Close()
		os.Exit(code)
	}
	os.Exit(m.Run())
}

type observedEcho struct{ observations *os.File }

func (r observedEcho) Open(ctx context.Context, reference string) (io.ReadWriteCloser, error) {
	if _, err := r.observations.Write([]byte{'O'}); err != nil {
		return nil, gateway.ErrBackendUnavailable
	}
	if reference != "opaque-test-handoff" || ctx.Err() != nil {
		return nil, gateway.ErrBackendUnavailable
	}
	front, back := net.Pipe()
	go func() {
		defer back.Close()
		_, _ = io.Copy(back, back)
	}()
	return front, nil
}

type liveProcess struct {
	command      *exec.Cmd
	control      *os.File
	output       *os.File
	reader       *bufio.Reader
	observations *os.File
	stderr       bytes.Buffer
	waited       bool
	sequence     int
	endpoint     string
	deadline     time.Time
}

func startServiceProcess(t *testing.T, executable string, helper bool, endpoint string, fixture *testcredentials.Fixture, change func(*gatewayservice.Bootstrap)) *liveProcess {
	t.Helper()
	p := &liveProcess{endpoint: endpoint, deadline: time.Now().UTC().Add(20 * time.Second)}
	var extra []*os.File
	var descriptors []protocol.ChannelDescriptor
	var writers []*os.File
	for index, requirement := range credentials.GatewayRequirements() {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		extra = append(extra, reader)
		writers = append(writers, writer)
		descriptors = append(descriptors, protocol.ChannelDescriptor{ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor, MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index})
	}
	control, controlWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p.control = controlWriter
	extra = append(extra, control)
	var eventWriter *os.File
	if helper {
		p.observations, eventWriter, err = os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		extra = append(extra, eventWriter)
		_ = p.observations.SetReadDeadline(time.Now().Add(15 * time.Second))
	}
	base, err := gatewaycontrol.NewRequest("initial", endpoint, descriptors)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := gatewayservice.Bootstrap{ProtocolID: gatewayservice.ProtocolID, Bootstrap: base, ControlDescriptor: 5, Deadline: p.deadline}
	if change != nil {
		change(&bootstrap)
	}
	var input bytes.Buffer
	if err := gatewayservice.EncodeBootstrap(&input, bootstrap); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	p.command = exec.CommandContext(ctx, executable)
	if helper {
		p.command.Args = append(p.command.Args, "--gateway-service-test-child")
	}
	p.command.Env = []string{}
	p.command.Dir = t.TempDir()
	p.command.ExtraFiles = extra
	p.command.Stdin = &input
	p.command.Stderr = &p.stderr
	p.output, eventWriter, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p.command.Stdout = eventWriter
	_ = p.output.SetReadDeadline(time.Now().Add(15 * time.Second))
	p.reader = bufio.NewReader(p.output)
	if err := p.command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = eventWriter.Close()
	for _, file := range extra {
		_ = file.Close()
	}
	t.Cleanup(func() {
		cancel()
		_ = p.control.Close()
		if !p.waited {
			_ = p.command.Wait()
		}
		_ = p.output.Close()
		if p.observations != nil {
			_ = p.observations.Close()
		}
	})
	for index, writer := range writers {
		payload := fixture.Payloads[credentials.GatewayRequirements()[index].ChannelID]
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
	}
	return p
}

func (p *liveProcess) read(t *testing.T, status string) gatewayservice.Reply {
	t.Helper()
	reply, err := gatewayservice.DecodeReply(p.reader)
	if err != nil {
		_ = p.command.Wait()
		p.waited = true
		t.Fatalf("service reply failed: %v; exit=%d; stderr bytes=%d", err, p.command.ProcessState.ExitCode(), p.stderr.Len())
	}
	if reply.Status != status || reply.Sequence != p.sequence || reply.ProcessID != p.command.Process.Pid || reply.Phase != "initial" {
		t.Fatalf("unexpected service reply status/identity: %s", reply.Status)
	}
	return reply
}

func (p *liveProcess) send(t *testing.T, c gatewayservice.Command, status string) gatewayservice.Reply {
	t.Helper()
	p.sequence++
	c.Sequence = p.sequence
	if err := gatewayservice.EncodeCommand(p.control, c); err != nil {
		t.Fatal(err)
	}
	return p.read(t, status)
}

func (p *liveProcess) finish(t *testing.T, code int) {
	t.Helper()
	leftover, err := io.ReadAll(io.LimitReader(p.reader, gatewayservice.MaxReplyBytes+1))
	if err != nil || len(leftover) != 0 {
		t.Fatal("unexpected post-terminal bytes or missing EOF")
	}
	err = p.command.Wait()
	p.waited = true
	if p.command.ProcessState.ExitCode() != code || (code == 0 && err != nil) {
		t.Fatalf("service exit: %d (want %d)", p.command.ProcessState.ExitCode(), code)
	}
	if p.stderr.Len() != 0 {
		t.Fatal("service emitted diagnostics to stderr")
	}
}

func loopbackFixture(t *testing.T) (string, *testcredentials.Fixture) {
	t.Helper()
	// Freeze the exact loopback endpoint before issuing the leaf. No bind retry
	// or endpoint rewrite on collision: a collision is a startup failure.
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://" + reservation.Addr().String() + "/tunnel"
	_ = reservation.Close()
	f := testcredentials.New(t)
	f.ServerTemplate.DNSNames = nil
	f.ServerTemplate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	cert, key := testcredentials.Issue(t, f.ServerCA, f.ServerCAKey, f.ServerTemplate, f.ServerKey)
	var document map[string]any
	if json.Unmarshal(f.Payloads["gateway-server"], &document) != nil {
		t.Fatal("server test fixture")
	}
	document["certificate_chain_pem"], document["private_key_pem"] = cert, key
	f.Payloads["gateway-server"] = testcredentials.JSON(t, document)
	return endpoint, f
}

func testAccess(t *testing.T, endpoint, actor, channel string, f *testcredentials.Fixture) *tls.Config {
	t.Helper()
	access, err := credentials.BuildGatewayAccess(endpoint, actor, f.Payloads[channel], f.Payloads["gateway-trust"])
	if err != nil {
		t.Fatal(err)
	}
	return access.TLSConfig
}

func rawConnectStatus(t *testing.T, endpoint, token, path, method string, config *tls.Config) int {
	t.Helper()
	u, _ := url.Parse(endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return 0
	}
	connection := tls.Client(raw, config)
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if connection.HandshakeContext(ctx) != nil {
		return 0
	}
	request := method + " " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nAuthorization: Bearer " + token + "\r\n\r\n"
	if _, err := io.WriteString(connection, request); err != nil {
		return 0
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: method})
	if err != nil {
		return 0
	}
	_ = response.Body.Close()
	return response.StatusCode
}

func install(t *testing.T, p *liveProcess) {
	t.Helper()
	p.send(t, gatewayservice.Command{Action: "install_policy", TenantA: "tenant-a", TenantB: "tenant-b"}, "policy_installed")
}

func issue(t *testing.T, p *liveProcess) string {
	t.Helper()
	return p.send(t, gatewayservice.Command{Action: "issue_grant", Actor: "controller_a", TenantID: "tenant-a", RuntimeSessionID: "session-a", HandoffReference: "opaque-test-handoff", ExpiresAt: p.deadline.Add(-time.Second)}, "grant_issued").Token
}

func TestRealGatewayCommandReadinessAuthorizationAndUnavailableBackend(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "caller-gateway")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", executable, "./cmd/caller-gateway")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Gateway: %v: %s", err, output)
	}
	t.Run("ready and fail-closed backend", func(t *testing.T) {
		endpoint, f := loopbackFixture(t)
		p := startServiceProcess(t, executable, false, endpoint, f, nil)
		p.read(t, "listening_policy_unset")
		a := testAccess(t, endpoint, "controller_a", "gateway-controller-a", f)
		if status := rawConnectStatus(t, endpoint, strings.Repeat("A", 43), "/tunnel", "CONNECT", a); status != 403 {
			t.Fatalf("policy-unset status = %d", status)
		}
		install(t, p)
		token := issue(t, p)
		if status := rawConnectStatus(t, endpoint, token, "/tunnel", "CONNECT", a); status != 502 {
			t.Fatalf("unavailable backend = %d", status)
		}
		p.send(t, gatewayservice.Command{Action: "stop"}, "stopped")
		p.finish(t, 0)
	})
	for _, name := range []string{"invalid server identity", "occupied endpoint", "expired deadline", "oversized lifetime"} {
		t.Run(name, func(t *testing.T) {
			endpoint, f := loopbackFixture(t)
			var change func(*gatewayservice.Bootstrap)
			code := ExitSoftware
			switch name {
			case "invalid server identity":
				f.Payloads["gateway-server"] = []byte(`{"private_key":"must-not-leak"}`)
				code = ExitData
			case "occupied endpoint":
				u, _ := url.Parse(endpoint)
				listener, err := net.Listen("tcp", u.Host)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			case "expired deadline":
				change = func(b *gatewayservice.Bootstrap) { b.Deadline = time.Now().Add(-time.Second) }
			case "oversized lifetime":
				change = func(b *gatewayservice.Bootstrap) { b.Deadline = time.Now().Add(6 * time.Minute) }
			}
			p := startServiceProcess(t, executable, false, endpoint, f, change)
			p.finish(t, code)
		})
	}
}

func TestServiceChildMTLSAuthorizationBeforeResolutionAndOpaqueBytes(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, f := loopbackFixture(t)
	p := startServiceProcess(t, executable, true, endpoint, f, nil)
	p.read(t, "listening_policy_unset")
	a := testAccess(t, endpoint, "controller_a", "gateway-controller-a", f)
	b := testAccess(t, endpoint, "controller_b", "gateway-controller-b", f)
	if status := rawConnectStatus(t, endpoint, strings.Repeat("A", 43), "/tunnel", "CONNECT", a); status != 403 {
		t.Fatalf("policy-unset rejection = %d", status)
	}
	p.send(t, gatewayservice.Command{Action: "install_policy", TenantA: "same", TenantB: "same"}, "rejected")
	p.send(t, gatewayservice.Command{Action: "issue_grant", Actor: "controller_a", TenantID: "tenant-a", RuntimeSessionID: "session-a", HandoffReference: "opaque-test-handoff", ExpiresAt: p.deadline.Add(-time.Second)}, "rejected")
	install(t, p)
	p.send(t, gatewayservice.Command{Action: "install_policy", TenantA: "different-a", TenantB: "different-b"}, "rejected")
	p.send(t, gatewayservice.Command{Action: "issue_grant", Actor: "controller_a", TenantID: "tenant-b", RuntimeSessionID: "session-a", HandoffReference: "opaque-test-handoff", ExpiresAt: p.deadline.Add(-time.Second)}, "rejected")
	p.send(t, gatewayservice.Command{Action: "issue_grant", Actor: "controller_a", TenantID: "tenant-a", RuntimeSessionID: "session-a", HandoffReference: "opaque-test-handoff", ExpiresAt: p.deadline.Add(time.Second)}, "rejected")
	token := issue(t, p)
	p.send(t, gatewayservice.Command{Action: "revoke", Actor: "controller_b", Token: token}, "rejected")
	missing := a.Clone()
	missing.Certificates = nil
	wrongIssuer := testAccess(t, endpoint, "controller_a", "gateway-controller-a", testcredentials.New(t))
	wrongIssuer.RootCAs = a.RootCAs
	unknown := a.Clone()
	leaf := testcredentials.Template()
	subject, _ := url.Parse("spiffe://gateway/unknown")
	leaf.URIs = []*url.URL{subject}
	cert, key := testcredentials.Issue(t, f.ClientCA, f.ClientCAKey, leaf, testcredentials.Key(t))
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	unknown.Certificates = []tls.Certificate{pair}
	noALPN := a.Clone()
	noALPN.NextProtos = nil
	for name, config := range map[string]*tls.Config{"missing certificate": missing, "untrusted client CA": wrongIssuer} {
		t.Run(name, func(t *testing.T) {
			if status := rawConnectStatus(t, endpoint, token, "/tunnel", "CONNECT", config); status != 0 {
				t.Fatalf("TLS rejection = %d", status)
			}
		})
	}
	for name, check := range map[string]struct {
		config              *tls.Config
		path, method, token string
	}{
		"cross controller":        {b, "/tunnel", "CONNECT", token},
		"unknown same CA subject": {unknown, "/tunnel", "CONNECT", token},
		"unknown grant":           {a, "/tunnel", "CONNECT", strings.Repeat("A", 43)},
		"wrong path":              {a, "/other", "CONNECT", token},
		"query injection":         {a, "/tunnel?session=bad", "CONNECT", token},
		"wrong method":            {a, "/tunnel", "GET", token},
		"no HTTP1 ALPN":           {noALPN, "/tunnel", "CONNECT", token},
	} {
		t.Run(name, func(t *testing.T) {
			if status := rawConnectStatus(t, endpoint, check.token, check.path, check.method, check.config); status != 403 {
				t.Fatalf("authorization rejection = %d", status)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := gateway.DialTunnel(ctx, endpoint, token, a)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte{'b', 'y', 't', 'e', 's', 0, 255, '\r', '\n', 128}
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, received); err != nil || !bytes.Equal(received, payload) {
		t.Fatal("opaque bidirectional bytes differ")
	}
	if status := rawConnectStatus(t, endpoint, token, "/tunnel", "CONNECT", a); status != 403 {
		t.Fatalf("replayed grant = %d", status)
	}
	p.send(t, gatewayservice.Command{Action: "revoke", Actor: "controller_a", Token: token}, "revoked")
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("revocation left tunnel open")
	} else {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			t.Fatal("read timeout is not evidence of revoked tunnel closure")
		}
	}
	p.send(t, gatewayservice.Command{Action: "stop"}, "stopped")
	p.finish(t, 0)
	observed, err := io.ReadAll(p.observations)
	if err != nil || string(observed) != "O" {
		t.Fatalf("backend resolution count = %d, want exactly one", len(observed))
	}
}

func TestServiceChildRejectsMalformedOrReplayedControl(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{`{"sequence":2,"action":"stop"}` + "\n", `{"sequence":1,"action":"stop","private_key":"marker"}` + "\n", strings.Repeat("x", gatewayservice.MaxCommandBytes+1)} {
		endpoint, f := loopbackFixture(t)
		p := startServiceProcess(t, executable, true, endpoint, f, nil)
		p.read(t, "listening_policy_unset")
		_, _ = io.WriteString(p.control, command)
		_ = p.control.Close()
		p.finish(t, ExitSoftware)
	}
}
