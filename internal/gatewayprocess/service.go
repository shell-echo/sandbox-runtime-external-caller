package gatewayprocess

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewaycontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayservice"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const (
	serviceStartupTimeout  = 5 * time.Second
	serviceShutdownTimeout = 2 * time.Second
)

var (
	ErrServiceActive     = errors.New("Gateway service is already active")
	ErrServiceContinuity = errors.New("Gateway service continuity rejected")
	ErrServiceState      = errors.New("Gateway service state is invalid")
)

// ServiceRunner owns one phase-local continuity boundary. After its first
// successful readiness it accepts restarts only with the exact endpoint and
// exact server/trust credential bytes. The digest never leaves this process.
type ServiceRunner struct {
	executable string

	mu              sync.Mutex
	active          bool
	continuitySet   bool
	continuity      [sha256.Size]byte
	observePID      func(int)
	startupTimeout  time.Duration
	shutdownTimeout time.Duration
}

func NewServiceRunner(executable string) *ServiceRunner {
	return &ServiceRunner{
		executable: executable, startupTimeout: serviceStartupTimeout,
		shutdownTimeout: serviceShutdownTimeout,
	}
}

func NewSiblingServiceRunner() *ServiceRunner {
	return NewServiceRunner(NewSiblingRunner().executable)
}

// Start requires one absolute caller phase deadline. Service credentials are
// copied through fresh pipes and remain owned by bundle's caller.
func (runner *ServiceRunner) Start(parent context.Context, phase, endpoint string, bundle *credentials.Bundle) (*Service, error) {
	if !processTransportSupported() {
		return nil, ErrUnsupportedPlatform
	}
	if runner == nil || bundle == nil || validateExecutable(runner.executable) != nil {
		return nil, ErrExecutable
	}
	if parent == nil {
		return nil, ErrServiceState
	}
	deadline, ok := parent.Deadline()
	now := time.Now()
	if !ok || !deadline.After(now) || deadline.Sub(now) > gatewayservice.MaxLifetime {
		return nil, ErrServiceState
	}
	binding, err := serviceContinuity(endpoint, bundle)
	if err != nil {
		return nil, ErrServiceState
	}
	runner.mu.Lock()
	if runner.active {
		runner.mu.Unlock()
		return nil, ErrServiceActive
	}
	if runner.continuitySet && subtle.ConstantTimeCompare(runner.continuity[:], binding[:]) != 1 {
		runner.mu.Unlock()
		return nil, ErrServiceContinuity
	}
	runner.active = true
	runner.mu.Unlock()
	releaseOnError := true
	defer func() {
		if releaseOnError {
			runner.release()
		}
	}()

	requirements := credentials.GatewayRequirements()
	credentialReaders := make([]*os.File, 0, len(requirements))
	credentialWriters := make([]*os.File, 0, len(requirements))
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	for index, requirement := range requirements {
		reader, writer, pipeErr := os.Pipe()
		if pipeErr != nil {
			closeFiles(credentialReaders)
			closeFiles(credentialWriters)
			return nil, ErrProcessIO
		}
		credentialReaders = append(credentialReaders, reader)
		credentialWriters = append(credentialWriters, writer)
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index,
		})
	}
	controlReader, controlWriter, err := os.Pipe()
	if err != nil {
		closeFiles(credentialReaders)
		closeFiles(credentialWriters)
		return nil, ErrProcessIO
	}
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		closeFiles(credentialReaders)
		closeFiles(credentialWriters)
		_ = controlReader.Close()
		_ = controlWriter.Close()
		return nil, ErrProcessIO
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		closeFiles(credentialReaders)
		closeFiles(credentialWriters)
		_ = controlReader.Close()
		_ = controlWriter.Close()
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		return nil, ErrProcessIO
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		closeFiles(credentialReaders)
		closeFiles(credentialWriters)
		_ = controlReader.Close()
		_ = controlWriter.Close()
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		return nil, ErrProcessIO
	}
	cleanupParent := func() {
		closeFiles(credentialWriters)
		_ = controlWriter.Close()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
	}
	cleanupChild := func() {
		closeFiles(credentialReaders)
		_ = controlReader.Close()
		_ = stdinReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
	}

	request, err := gatewaycontrol.NewRequest(phase, endpoint, descriptors)
	if err != nil {
		cleanupParent()
		cleanupChild()
		return nil, ErrProcessResult
	}
	bootstrap := gatewayservice.Bootstrap{
		ProtocolID: gatewayservice.ProtocolID, Bootstrap: request,
		ControlDescriptor: 3 + len(requirements), Deadline: deadline.UTC(),
	}
	command := exec.Command(runner.executable)
	command.Args = []string{runner.executable}
	command.Env = []string{}
	command.ExtraFiles = append(credentialReaders, controlReader)
	command.Stdin = stdinReader
	command.Stdout = stdoutWriter
	command.Stderr = stderrWriter
	configureProcessGroup(command)
	if err := command.Start(); err != nil {
		cleanupParent()
		cleanupChild()
		return nil, ErrProcessStart
	}
	cleanupChild()
	if runner.observePID != nil {
		runner.observePID(command.Process.Pid)
	}

	service := &Service{
		owner: runner, command: command, control: controlWriter, output: stdoutReader,
		reader: bufio.NewReaderSize(stdoutReader, gatewayservice.MaxReplyBytes),
		stderr: stderrReader, phase: phase, deadline: deadline,
		done:            make(chan struct{}),
		terminalDone:    make(chan struct{}),
		shutdownTimeout: runner.boundedShutdownTimeout(),
	}
	go service.waitProcess()
	go service.watchParent(parent)

	startupDeadline := now.Add(runner.boundedStartupTimeout())
	if deadline.Before(startupDeadline) {
		startupDeadline = deadline
	}
	for _, writer := range append([]*os.File{stdinWriter}, credentialWriters...) {
		_ = writer.SetWriteDeadline(startupDeadline)
	}
	stopStartupCancellation := context.AfterFunc(parent, func() {
		_ = stdinWriter.Close()
		closeFiles(credentialWriters)
	})
	defer stopStartupCancellation()
	writeErr := gatewayservice.EncodeBootstrap(stdinWriter, bootstrap)
	if closeErr := stdinWriter.Close(); writeErr == nil && closeErr != nil {
		writeErr = closeErr
	}
	for index, requirement := range requirements {
		if writeErr == nil {
			writeErr = bundle.Use(requirement.ChannelID, func(payload []byte) error {
				return writeAll(credentialWriters[index], payload)
			})
		}
		if closeErr := credentialWriters[index].Close(); writeErr == nil && closeErr != nil {
			writeErr = closeErr
		}
	}
	if writeErr != nil {
		service.abort(ErrProcessIO)
		return nil, service.waitBounded()
	}
	_ = stdoutReader.SetReadDeadline(startupDeadline)
	reply, err := gatewayservice.DecodeReply(service.reader)
	_ = stdoutReader.SetReadDeadline(time.Time{})
	if err != nil || reply.Sequence != 0 || reply.Phase != phase || reply.ProcessID != command.Process.Pid || reply.Status != "listening_policy_unset" {
		if !time.Now().Before(startupDeadline) {
			service.abort(ErrProcessTimeout)
		} else {
			service.abort(ErrProcessResult)
		}
		return nil, service.waitBounded()
	}
	if parent.Err() != nil {
		service.abort(context.Cause(parent))
		return nil, service.waitBounded()
	}
	runner.mu.Lock()
	if !runner.continuitySet {
		runner.continuity = binding
		runner.continuitySet = true
	}
	runner.mu.Unlock()
	releaseOnError = false
	return service, nil
}

type Service struct {
	owner    *ServiceRunner
	command  *exec.Cmd
	control  *os.File
	output   *os.File
	reader   *bufio.Reader
	stderr   *os.File
	phase    string
	deadline time.Time

	commandMu       sync.Mutex
	stateMu         sync.Mutex
	sequence        int
	stopped         bool
	stopRequested   bool
	abortCause      error
	waitErr         error
	stderrResult    drainResult
	done            chan struct{}
	terminalDone    chan struct{}
	shutdownTimeout time.Duration
	abortOnce       sync.Once
	terminalOnce    sync.Once
}

func (service *Service) PID() int {
	if service == nil || service.command == nil || service.command.Process == nil {
		return 0
	}
	return service.command.Process.Pid
}

func (service *Service) Done() <-chan struct{} {
	if service == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return service.done
}

func (service *Service) InstallPolicy(ctx context.Context, tenantA, tenantB string) error {
	reply, err := service.exchange(ctx, gatewayservice.Command{Action: "install_policy", TenantA: tenantA, TenantB: tenantB})
	if err != nil {
		return err
	}
	if reply.Status != "policy_installed" {
		return ErrProcessResult
	}
	return nil
}

func (service *Service) IssueGrant(ctx context.Context, actor, tenant, runtimeSession, handoff string, expiresAt time.Time) (string, error) {
	reply, err := service.exchange(ctx, gatewayservice.Command{
		Action: "issue_grant", Actor: actor, TenantID: tenant,
		RuntimeSessionID: runtimeSession, HandoffReference: handoff, ExpiresAt: expiresAt.UTC(),
	})
	if err != nil {
		return "", err
	}
	if reply.Status != "grant_issued" {
		return "", ErrProcessResult
	}
	return reply.Token, nil
}

func (service *Service) Revoke(ctx context.Context, actor, token string) error {
	reply, err := service.exchange(ctx, gatewayservice.Command{Action: "revoke", Actor: actor, Token: token})
	if err != nil {
		return err
	}
	if reply.Status != "revoked" {
		return ErrProcessResult
	}
	return nil
}

// Stop is graceful only if the child acknowledges terminal stopped, closes
// stdout, exits cleanly, emits no stderr, and is reaped within the caller bound.
func (service *Service) Stop(ctx context.Context) error {
	if service == nil {
		return ErrServiceState
	}
	service.commandMu.Lock()
	defer service.commandMu.Unlock()
	deadline, err := service.operationDeadline(ctx)
	if err != nil {
		return err
	}
	service.stateMu.Lock()
	if service.stopped || service.abortCause != nil {
		service.stateMu.Unlock()
		return ErrServiceState
	}
	select {
	case <-service.done:
		service.stateMu.Unlock()
		return ErrProcessExit
	default:
	}
	service.stopRequested = true
	service.sequence++
	sequence := service.sequence
	service.stateMu.Unlock()
	_ = service.control.SetWriteDeadline(deadline)
	_ = service.output.SetReadDeadline(deadline)
	stopCancellation := service.watchOperationCancellation(ctx)
	defer stopCancellation()
	command := gatewayservice.Command{Sequence: sequence, Action: "stop"}
	if gatewayservice.EncodeCommand(service.control, command) != nil {
		if ctx.Err() != nil {
			service.abort(context.Cause(ctx))
		} else {
			service.abort(ErrProcessIO)
		}
		return service.waitBounded()
	}
	reply, err := gatewayservice.DecodeReply(service.reader)
	if err != nil || reply.Sequence != sequence || reply.Phase != service.phase || reply.ProcessID != service.PID() || reply.Status != "stopped" {
		if ctx.Err() != nil {
			service.abort(context.Cause(ctx))
		} else {
			service.abort(ErrProcessResult)
		}
		return service.waitBounded()
	}
	if _, err := service.reader.ReadByte(); !errors.Is(err, io.EOF) {
		service.abort(ErrProcessResult)
		return service.waitBounded()
	}
	service.stateMu.Lock()
	service.stopped = true
	service.stateMu.Unlock()
	service.closeTerminalDone()
	_ = service.control.Close()
	if err := service.waitBounded(); err != nil {
		return err
	}
	return nil
}

// Wait returns the terminal cause. Parent cancellation/deadline is preserved;
// an unrequested child exit, nonzero exit, stderr, or malformed stream is not.
func (service *Service) Wait() error {
	if service == nil {
		return ErrServiceState
	}
	<-service.done
	_ = service.output.Close()
	service.stateMu.Lock()
	stopRequested := service.stopRequested
	stopped := service.stopped
	abortCause := service.abortCause
	service.stateMu.Unlock()
	if stopRequested && !stopped && abortCause == nil {
		<-service.terminalDone
	}
	service.stateMu.Lock()
	defer service.stateMu.Unlock()
	if service.abortCause != nil {
		return service.abortCause
	}
	if !service.stopped || service.waitErr != nil {
		return ErrProcessExit
	}
	if service.stderrResult.err != nil || len(service.stderrResult.data) != 0 {
		return ErrProcessIO
	}
	return nil
}

func (service *Service) exchange(ctx context.Context, command gatewayservice.Command) (gatewayservice.Reply, error) {
	if service == nil {
		return gatewayservice.Reply{}, ErrServiceState
	}
	service.commandMu.Lock()
	defer service.commandMu.Unlock()
	deadline, err := service.operationDeadline(ctx)
	if err != nil {
		return gatewayservice.Reply{}, err
	}
	service.stateMu.Lock()
	if service.stopped || service.abortCause != nil {
		service.stateMu.Unlock()
		return gatewayservice.Reply{}, ErrServiceState
	}
	select {
	case <-service.done:
		service.stateMu.Unlock()
		return gatewayservice.Reply{}, ErrProcessExit
	default:
	}
	service.sequence++
	command.Sequence = service.sequence
	service.stateMu.Unlock()
	_ = service.control.SetWriteDeadline(deadline)
	_ = service.output.SetReadDeadline(deadline)
	stopCancellation := service.watchOperationCancellation(ctx)
	defer stopCancellation()
	if gatewayservice.EncodeCommand(service.control, command) != nil {
		if ctx.Err() != nil {
			cause := context.Cause(ctx)
			service.abort(cause)
			return gatewayservice.Reply{}, cause
		}
		service.abort(ErrProcessIO)
		return gatewayservice.Reply{}, ErrProcessIO
	}
	reply, err := gatewayservice.DecodeReply(service.reader)
	if err != nil || reply.Sequence != command.Sequence || reply.Phase != service.phase || reply.ProcessID != service.PID() {
		if ctx.Err() != nil {
			cause := context.Cause(ctx)
			service.abort(cause)
			return gatewayservice.Reply{}, cause
		}
		service.abort(ErrProcessResult)
		return gatewayservice.Reply{}, ErrProcessResult
	}
	return reply, nil
}

func (service *Service) operationDeadline(ctx context.Context) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, ErrServiceState
	}
	if ctx.Err() != nil {
		return time.Time{}, context.Cause(ctx)
	}
	deadline := service.deadline
	if operationDeadline, ok := ctx.Deadline(); ok && operationDeadline.Before(deadline) {
		deadline = operationDeadline
	}
	if !deadline.After(time.Now()) {
		return time.Time{}, context.DeadlineExceeded
	}
	return deadline, nil
}

func (service *Service) watchOperationCancellation(ctx context.Context) func() bool {
	var mutex sync.Mutex
	active := true
	stop := context.AfterFunc(ctx, func() {
		mutex.Lock()
		defer mutex.Unlock()
		if !active {
			return
		}
		now := time.Now()
		_ = service.control.SetWriteDeadline(now)
		_ = service.output.SetReadDeadline(now)
	})
	return func() bool {
		mutex.Lock()
		active = false
		mutex.Unlock()
		return stop()
	}
}

func (service *Service) watchParent(parent context.Context) {
	select {
	case <-parent.Done():
		service.abort(context.Cause(parent))
	case <-service.done:
	}
}

func (service *Service) abort(cause error) {
	if cause == nil {
		cause = ErrProcessExit
	}
	service.abortOnce.Do(func() {
		service.stateMu.Lock()
		service.abortCause = cause
		service.stateMu.Unlock()
		service.closeTerminalDone()
		_ = service.control.Close()
		_ = service.output.Close()
		go func() {
			timer := time.NewTimer(service.shutdownTimeout)
			defer timer.Stop()
			select {
			case <-service.done:
			case <-timer.C:
				_ = terminateProcessGroup(service.command.Process)
			}
		}()
	})
}

func (service *Service) closeTerminalDone() {
	service.terminalOnce.Do(func() { close(service.terminalDone) })
}

func (service *Service) waitProcess() {
	stderrResult := make(chan drainResult, 1)
	go func() { stderrResult <- drainBounded(service.stderr, maxStderrBytes) }()
	waitErr := service.command.Wait()
	timer := time.NewTimer(service.shutdownTimeout)
	var result drainResult
	select {
	case result = <-stderrResult:
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
		_ = terminateProcessGroup(service.command.Process)
		_ = service.stderr.Close()
		result = <-stderrResult
	}
	_ = service.control.Close()
	_ = service.stderr.Close()
	service.stateMu.Lock()
	service.waitErr = waitErr
	service.stderrResult = result
	service.stateMu.Unlock()
	service.owner.release()
	close(service.done)
}

func (service *Service) waitBounded() error {
	timer := time.NewTimer(service.shutdownTimeout)
	defer timer.Stop()
	select {
	case <-service.done:
		return service.Wait()
	case <-timer.C:
		service.abort(ErrProcessTimeout)
		_ = terminateProcessGroup(service.command.Process)
		<-service.done
		return service.Wait()
	}
}

func (runner *ServiceRunner) release() {
	runner.mu.Lock()
	runner.active = false
	runner.mu.Unlock()
}

func (runner *ServiceRunner) boundedStartupTimeout() time.Duration {
	if runner.startupTimeout <= 0 || runner.startupTimeout > serviceStartupTimeout {
		return serviceStartupTimeout
	}
	return runner.startupTimeout
}

func (runner *ServiceRunner) boundedShutdownTimeout() time.Duration {
	if runner.shutdownTimeout <= 0 || runner.shutdownTimeout > serviceShutdownTimeout {
		return serviceShutdownTimeout
	}
	return runner.shutdownTimeout
}

func serviceContinuity(endpoint string, bundle *credentials.Bundle) ([sha256.Size]byte, error) {
	hash := sha256.New()
	writeFrame := func(value []byte) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(value)
	}
	writeFrame([]byte("sandbox-gateway-service-continuity-v1"))
	writeFrame([]byte(endpoint))
	err := bundle.UsePair("gateway-server", "gateway-trust", func(server, trust []byte) error {
		writeFrame(server)
		writeFrame(trust)
		return nil
	})
	var result [sha256.Size]byte
	if err != nil {
		return result, err
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}
