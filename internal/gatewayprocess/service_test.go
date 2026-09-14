//go:build darwin || linux

package gatewayprocess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
)

func buildLiveGateway(t *testing.T) string {
	t.Helper()
	return buildExecutable(t, "./internal/gatewayprocess/testdata/livegateway", "caller-gateway")
}

func loopbackServiceFixture(t *testing.T) (string, *testcredentials.Fixture) {
	t.Helper()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://" + reservation.Addr().String() + "/tunnel"
	_ = reservation.Close()
	fixture := testcredentials.New(t)
	fixture.ServerTemplate.DNSNames = nil
	fixture.ServerTemplate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	certificate, key := testcredentials.Issue(t, fixture.ServerCA, fixture.ServerCAKey, fixture.ServerTemplate, fixture.ServerKey)
	var document map[string]any
	if json.Unmarshal(fixture.Payloads["gateway-server"], &document) != nil {
		t.Fatal("server fixture decode failed")
	}
	document["certificate_chain_pem"] = certificate
	document["private_key_pem"] = key
	fixture.Payloads["gateway-server"] = testcredentials.JSON(t, document)
	return endpoint, fixture
}

func serviceClientConfig(t *testing.T, endpoint string, fixture *testcredentials.Fixture) *tls.Config {
	t.Helper()
	access, err := credentials.BuildGatewayAccess(endpoint, "controller_a", fixture.Payloads["gateway-controller-a"], fixture.Payloads["gateway-trust"])
	if err != nil {
		t.Fatal(err)
	}
	return access.TLSConfig
}

func phaseContext(t *testing.T, duration time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), duration)
}

func startAuthorizedService(t *testing.T, runner *ServiceRunner, ctx context.Context, endpoint string, bundle *credentials.Bundle, expiresAt time.Time) (*Service, string) {
	t.Helper()
	service, err := runner.Start(ctx, "initial", endpoint, bundle)
	if err != nil {
		t.Fatal(err)
	}
	operation, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := service.InstallPolicy(operation, "tenant-a", "tenant-b"); err != nil {
		t.Fatal(err)
	}
	token, err := service.IssueGrant(operation, "controller_a", "tenant-a", "session-a", "opaque-test-handoff", expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	return service, token
}

func stopService(t *testing.T, service *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	assertReaped(t, service.PID())
}

func serverCertificateDigest(t *testing.T, endpoint string, config *tls.Config) [sha256.Size]byte {
	t.Helper()
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", parsed.Host, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	state := connection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("Gateway omitted server certificate")
	}
	return sha256.Sum256(state.PeerCertificates[0].Raw)
}

func TestServiceRunnerRestartsOnlyWithExactIdentityAndEndpoint(t *testing.T) {
	executable := buildLiveGateway(t)
	endpoint, fixture := loopbackServiceFixture(t)
	bundle := testBundleWithPayloads(t, fixture.Payloads)
	defer bundle.Destroy()
	runner := NewServiceRunner(executable)
	var pids []int
	runner.observePID = func(pid int) { pids = append(pids, pid) }
	config := serviceClientConfig(t, endpoint, fixture)

	ctx1, cancel1 := phaseContext(t, 10*time.Second)
	service1, err := runner.Start(ctx1, "initial", endpoint, bundle)
	if err != nil {
		t.Fatal(err)
	}
	digest1 := serverCertificateDigest(t, endpoint, config)
	stopService(t, service1)
	cancel1()

	ctx2, cancel2 := phaseContext(t, 10*time.Second)
	defer cancel2()
	service2, err := runner.Start(ctx2, "initial", endpoint, bundle)
	if err != nil {
		t.Fatal(err)
	}
	digest2 := serverCertificateDigest(t, endpoint, config)
	if digest1 != digest2 || service1.PID() == service2.PID() || len(pids) != 2 {
		t.Fatal("restart did not preserve server identity with a fresh process")
	}
	stopService(t, service2)

	ctx3, cancel3 := phaseContext(t, 10*time.Second)
	defer cancel3()
	if service, err := runner.Start(ctx3, "initial", "https://127.0.0.1:1/tunnel", bundle); !errors.Is(err, ErrServiceContinuity) || service != nil {
		t.Fatalf("changed endpoint error = %v", err)
	}
	_, otherFixture := loopbackServiceFixture(t)
	otherBundle := testBundleWithPayloads(t, otherFixture.Payloads)
	defer otherBundle.Destroy()
	if service, err := runner.Start(ctx3, "initial", endpoint, otherBundle); !errors.Is(err, ErrServiceContinuity) || service != nil {
		t.Fatalf("changed identity error = %v", err)
	}
	if len(pids) != 2 {
		t.Fatal("continuity rejection launched a child")
	}
}

func TestFailedStartupDoesNotPinContinuityAndConcurrentStartIsRejected(t *testing.T) {
	executable := buildLiveGateway(t)
	endpoint, fixture := loopbackServiceFixture(t)
	bundle := testBundleWithPayloads(t, fixture.Payloads)
	defer bundle.Destroy()
	parsed, _ := url.Parse(endpoint)
	occupied, err := net.Listen("tcp", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewServiceRunner(executable)
	ctx, cancel := phaseContext(t, 10*time.Second)
	defer cancel()
	if service, err := runner.Start(ctx, "initial", endpoint, bundle); err == nil || service != nil {
		t.Fatal("occupied endpoint reached readiness")
	}
	_ = occupied.Close()
	service, err := runner.Start(ctx, "initial", endpoint, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := runner.Start(ctx, "initial", endpoint, bundle); !errors.Is(err, ErrServiceActive) || duplicate != nil {
		t.Fatalf("concurrent start error = %v", err)
	}
	stopService(t, service)
}

func assertConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	_, err := connection.Read(one[:])
	if err == nil {
		t.Fatal("live tunnel remained open")
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatal("read timeout does not prove tunnel closure")
	}
}

func assertEndpointClosed(t *testing.T, endpoint string) {
	t.Helper()
	parsed, _ := url.Parse(endpoint)
	deadline := time.Now().Add(2 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", parsed.Host, 40*time.Millisecond)
		if err != nil {
			return
		}
		_ = connection.Close()
		if time.Now().After(deadline) {
			t.Fatal("Gateway listener remained reachable")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServiceDeadlineAndGracefulStopCloseLiveTunnelAndReap(t *testing.T) {
	executable := buildLiveGateway(t)
	for _, mode := range []string{"deadline", "stop"} {
		t.Run(mode, func(t *testing.T) {
			endpoint, fixture := loopbackServiceFixture(t)
			bundle := testBundleWithPayloads(t, fixture.Payloads)
			defer bundle.Destroy()
			// The phase deadline covers child startup, policy/grant setup, and
			// tunnel establishment before it tests active-service expiry. Keep
			// that setup inside the production five-second startup bound even
			// when the race detector and the full package graph contend for CPU.
			duration := 10 * time.Second
			ctx, cancel := phaseContext(t, duration)
			defer cancel()
			service, token := startAuthorizedService(t, NewServiceRunner(executable), ctx, endpoint, bundle, time.Now().Add(duration-250*time.Millisecond))
			clientCtx, clientCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer clientCancel()
			connection, err := gateway.DialTunnel(clientCtx, endpoint, token, serviceClientConfig(t, endpoint, fixture))
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("live-before-shutdown")
			if _, err := connection.Write(payload); err != nil {
				t.Fatal(err)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(connection, received); err != nil || !bytes.Equal(received, payload) {
				t.Fatal("pre-shutdown tunnel roundtrip failed")
			}
			if mode == "deadline" {
				<-service.Done()
				if err := service.Wait(); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline result = %v", err)
				}
			} else {
				stopService(t, service)
			}
			assertConnectionClosed(t, connection)
			_ = connection.Close()
			assertEndpointClosed(t, endpoint)
			assertReaped(t, service.PID())
		})
	}
}

func TestStartupTimeoutTerminatesAndReapsService(t *testing.T) {
	executable := buildExecutable(t, "./internal/callerprocess/testdata/hang", "caller-gateway")
	endpoint, fixture := loopbackServiceFixture(t)
	bundle := testBundleWithPayloads(t, fixture.Payloads)
	defer bundle.Destroy()
	runner := NewServiceRunner(executable)
	runner.startupTimeout = 100 * time.Millisecond
	runner.shutdownTimeout = 100 * time.Millisecond
	observed := 0
	runner.observePID = func(pid int) { observed = pid }
	ctx, cancel := phaseContext(t, 5*time.Second)
	defer cancel()
	started := time.Now()
	service, err := runner.Start(ctx, "initial", endpoint, bundle)
	if service != nil || !errors.Is(err, ErrProcessTimeout) || observed == 0 || time.Since(started) > time.Second {
		t.Fatalf("bounded startup result = %v, pid = %d", err, observed)
	}
	assertReaped(t, observed)
}

func TestCanceledControlOperationTerminatesAndReapsService(t *testing.T) {
	executable := buildExecutable(t, "./internal/gatewayprocess/testdata/readyhang", "caller-gateway")
	endpoint, fixture := loopbackServiceFixture(t)
	bundle := testBundleWithPayloads(t, fixture.Payloads)
	defer bundle.Destroy()
	runner := NewServiceRunner(executable)
	runner.shutdownTimeout = 100 * time.Millisecond
	ctx, cancel := phaseContext(t, 5*time.Second)
	defer cancel()
	service, err := runner.Start(ctx, "initial", endpoint, bundle)
	if err != nil {
		t.Fatal(err)
	}
	operation, cancelOperation := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.InstallPolicy(operation, "tenant-a", "tenant-b") }()
	time.Sleep(30 * time.Millisecond)
	cancelOperation()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled operation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled control operation stayed blocked")
	}
	if err := service.Wait(); !errors.Is(err, context.Canceled) {
		t.Fatalf("service cancellation result = %v", err)
	}
	assertReaped(t, service.PID())
}

func TestAbruptCallerDeathClosesGatewayTunnelListenerAndProcess(t *testing.T) {
	directory := t.TempDir()
	gatewayExecutable := filepath.Join(directory, "caller-gateway")
	parentExecutable := filepath.Join(directory, "abrupt-parent")
	for packagePath, output := range map[string]string{
		"./internal/gatewayprocess/testdata/livegateway":  gatewayExecutable,
		"./internal/gatewayprocess/testdata/abruptparent": parentExecutable,
	} {
		command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", output, packagePath)
		command.Dir = filepath.Join("..", "..")
		if buildOutput, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v: %s", packagePath, err, buildOutput)
		}
	}
	endpoint, fixture := loopbackServiceFixture(t)
	deadline := time.Now().UTC().Add(15 * time.Second)
	readers := make([]*os.File, 0, len(credentials.Requirements())+1)
	writers := make([]*os.File, 0, len(credentials.Requirements()))
	for range credentials.Requirements() {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		readers = append(readers, reader)
		writers = append(writers, writer)
	}
	triggerReader, triggerWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readers = append(readers, triggerReader)
	defer triggerWriter.Close()
	input, _ := json.Marshal(map[string]any{"phase": "initial", "endpoint": endpoint, "deadline": deadline})
	command := exec.Command(parentExecutable)
	command.Args = []string{parentExecutable}
	command.Env = []string{}
	command.Dir = t.TempDir()
	command.ExtraFiles = readers
	command.Stdin = bytes.NewReader(input)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	closeFiles(readers)
	for index, writer := range writers {
		payload := fixture.Payloads[credentials.Requirements()[index].ChannelID]
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
	}
	var result struct {
		GatewayPID int    `json:"gateway_pid"`
		Token      string `json:"token"`
	}
	if err := json.NewDecoder(bufio.NewReader(stdout)).Decode(&result); err != nil || result.GatewayPID < 1 || result.Token == "" {
		t.Fatalf("parent result = %#v, %v", result, err)
	}
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer clientCancel()
	connection, err := gateway.DialTunnel(clientCtx, endpoint, result.Token, serviceClientConfig(t, endpoint, fixture))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("before-parent-death")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, received); err != nil || !bytes.Equal(received, payload) {
		t.Fatal("pre-death tunnel roundtrip failed")
	}
	if _, err := triggerWriter.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	_ = triggerWriter.Close()
	if err := command.Wait(); err != nil || command.ProcessState.ExitCode() != 0 || stderr.Len() != 0 {
		t.Fatalf("abrupt parent result: %v, exit=%d, stderr=%d", err, command.ProcessState.ExitCode(), stderr.Len())
	}
	assertConnectionClosed(t, connection)
	_ = connection.Close()
	assertEndpointClosed(t, endpoint)
	deadlineWait := time.Now().Add(3 * time.Second)
	for {
		process, findErr := os.FindProcess(result.GatewayPID)
		if findErr != nil || process.Signal(syscall.Signal(0)) != nil {
			break
		}
		if time.Now().After(deadlineWait) {
			t.Fatalf("orphan Gateway %s survived caller death", strconv.Itoa(result.GatewayPID))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
