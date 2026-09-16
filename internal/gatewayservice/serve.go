package gatewayservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
)

var ErrService = errors.New("Gateway service failed")

// UnavailableResolver remains the fail-closed service-v1 and test boundary.
// Operational service v2 replaces it with the private Caller byte bridge.
type UnavailableResolver struct{}

func (UnavailableResolver) Open(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, gateway.ErrBackendUnavailable
}

// Serve owns the listener and the declared command pipe, but borrows identity.
// It returns only after HTTP/TLS work has stopped; the caller may then Destroy
// the parsed private key. Resolver implementations must honor context/Close.
func Serve(parent context.Context, bootstrap Bootstrap, identity *credentials.GatewayServerIdentity, commands *os.File, output io.Writer, resolver gateway.Resolver) error {
	if parent == nil || identity == nil || identity.TLSConfig == nil || commands == nil || output == nil || resolver == nil {
		return ErrService
	}
	now := time.Now()
	if !bootstrap.Deadline.After(now) || bootstrap.Deadline.Sub(now) > MaxLifetime {
		return ErrService
	}
	deadline := bootstrap.Deadline
	if identity.ExpiresAt.Before(deadline) {
		deadline = identity.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	if closer, ok := resolver.(io.Closer); ok {
		defer closer.Close()
	}
	defer commands.Close()
	stopCommandClose := context.AfterFunc(ctx, func() { _ = commands.Close() })
	defer stopCommandClose()
	// os.Pipe-backed process stdout is deadline-capable; in-memory unit writers
	// are immediate. Process-supervisor hard termination is a separate gate.
	if pipe, ok := output.(*os.File); ok {
		if err := pipe.SetWriteDeadline(deadline); err != nil {
			return ErrService
		}
	}
	parsed, err := url.Parse(bootstrap.Bootstrap.GatewayProbeEndpoint)
	if err != nil || parsed.Scheme != "https" || len(parsed.Path) > 512 {
		return ErrService
	}
	address := parsed.Host
	if parsed.Port() == "" {
		address = net.JoinHostPort(parsed.Hostname(), "443")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return ErrService
	}
	state := &serviceState{path: parsed.Path, host: parsed.Host, subjects: identity.ControllerSubjects, resolver: resolver}
	var httpConnections sync.WaitGroup
	server := &http.Server{
		Handler: state, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnState: func(_ net.Conn, status http.ConnState) {
			switch status {
			case http.StateNew:
				httpConnections.Add(1)
			case http.StateClosed, http.StateHijacked:
				httpConnections.Done()
			}
		},
	}
	ready := make(chan struct{})
	serving := make(chan struct{})
	go func() {
		_ = server.Serve(&readyListener{Listener: tls.NewListener(listener, identity.TLSConfig), ready: ready})
		close(serving)
		cancel()
	}()
	stopServer := context.AfterFunc(ctx, func() { _ = server.Close() })
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			state.mu.Lock()
			state.closing = true
			state.mu.Unlock()
			cancel()
			_ = server.Close()
			<-serving
			httpConnections.Wait()
			state.requests.Wait()
			stopServer()
		})
	}
	defer cleanup()
	select {
	case <-ready:
	case <-ctx.Done():
		return ErrService
	}
	if ctx.Err() != nil {
		return ErrService
	}
	reply := Reply{ProtocolID: ProtocolID, Sequence: 0, Phase: bootstrap.Bootstrap.Phase, ProcessID: os.Getpid(), Status: "listening_policy_unset"}
	if EncodeReply(output, reply) != nil {
		return ErrService
	}
	reader := bufio.NewReaderSize(commands, MaxCommandBytes)
	for sequence := 1; sequence <= MaxCommands; sequence++ {
		command, err := DecodeCommand(reader)
		if err != nil || command.Sequence != sequence || ctx.Err() != nil {
			return ErrControl
		}
		reply.Sequence, reply.Token = sequence, ""
		if command.Action == "stop" {
			cleanup()
			reply.Status = "stopped"
			return EncodeReply(output, reply)
		}
		reply.Status, reply.Token = state.apply(ctx, command, deadline)
		if EncodeReply(output, reply) != nil {
			return ErrService
		}
	}
	return ErrControl
}

type readyListener struct {
	net.Listener
	ready chan struct{}
	once  sync.Once
}

func (l *readyListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.ready) })
	return l.Listener.Accept()
}

type serviceState struct {
	mu         sync.Mutex
	closing    bool
	requests   sync.WaitGroup
	path, host string
	subjects   credentials.GatewayControllerSubjects
	resolver   gateway.Resolver
	gateway    *gateway.Gateway
	handler    *gateway.Handler
}

func (s *serviceState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		deny(w)
		return
	}
	s.requests.Add(1)
	handler := s.handler
	s.mu.Unlock()
	defer s.requests.Done()
	if handler == nil || r.Host != s.host || r.TLS == nil || r.TLS.NegotiatedProtocol != "http/1.1" || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		deny(w)
		return
	}
	// Keep a long-lived tunnel from surviving its authenticated client chain.
	deadline, _ := r.Context().Deadline()
	for _, certificate := range r.TLS.VerifiedChains[0] {
		if deadline.IsZero() || certificate.NotAfter.Before(deadline) {
			deadline = certificate.NotAfter
		}
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	handler.ServeHTTP(w, r.WithContext(ctx))
}

func (s *serviceState) apply(ctx context.Context, c Command, deadline time.Time) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Action == "install_policy" {
		if s.gateway != nil {
			return "rejected", ""
		}
		g, err := gateway.New(map[string]string{s.subjects.ControllerA: c.TenantA, s.subjects.ControllerB: c.TenantB}, s.resolver)
		if err != nil {
			return "rejected", ""
		}
		h, err := gateway.NewHandler(g, s.path)
		if err != nil {
			return "rejected", ""
		}
		s.gateway, s.handler = g, h
		return "policy_installed", ""
	}
	if s.gateway == nil {
		return "rejected", ""
	}
	subject := s.subjects.ControllerA
	if c.Actor == "controller_b" {
		subject = s.subjects.ControllerB
	}
	if c.Action == "issue_grant" {
		if c.ExpiresAt.After(deadline) {
			return "rejected", ""
		}
		token, err := s.gateway.IssueGrant(gateway.GrantRequest{ControllerSubject: subject, TenantID: c.TenantID, RuntimeSessionID: c.RuntimeSessionID, HandoffReference: c.HandoffReference, ExpiresAt: c.ExpiresAt})
		if err != nil {
			return "rejected", ""
		}
		return "grant_issued", token
	}
	if c.Action == "revoke" {
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if s.gateway.Revoke(bounded, c.Token, subject) != nil {
			return "rejected", ""
		}
		return "revoked", ""
	}
	return "rejected", ""
}

func deny(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusForbidden)
}
