// Package callerprocess launches and supervises the candidate-owned external
// caller over a private control channel plus separate credential pipes.
package callerprocess

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

const (
	caseTimeout      = 120 * time.Second
	processTimeout   = 15 * caseTimeout
	processWaitDelay = 2 * time.Second
	gracefulExitWait = 2 * time.Second
	processReapLimit = 5 * time.Second
	maxStderrBytes   = 64 << 10
)

var (
	ErrUnsupportedPlatform = errors.New("external caller process transport is unsupported on this platform")
	ErrExecutable          = errors.New("external caller executable is invalid")
	ErrProcessStart        = errors.New("external caller process did not start")
	ErrProcessIO           = errors.New("external caller process I/O failed")
	ErrProcessExit         = errors.New("external caller process did not exit cleanly")
	ErrProcessTimeout      = errors.New("external caller process exceeded its bounded lifetime")
	ErrProcessResult       = errors.New("external caller process result is invalid")
	ErrProcessState        = errors.New("external caller process state is invalid")
	ErrProcessCleanup      = errors.New("external caller process cleanup could not be confirmed")
)

type Runner struct {
	executable string
	observePID func(int)
	timeout    time.Duration
	session    *Session
}

type Session struct {
	invocation protocol.Invocation
	request    scenariocontrol.Request
	command    *exec.Cmd
	stdin      io.WriteCloser
	stdout     *bufio.Reader
	stderr     <-chan drainResult
	ctx        context.Context
	cancel     context.CancelFunc
	done       bool
	next       int
}

func NewRunner(executable string) *Runner {
	return &Runner{executable: executable, timeout: processTimeout}
}

// FailureCode maps private process failures onto the locked public adapter
// protocol without exposing command, path, PID, stderr, or correlation detail.
func (runner *Runner) FailureCode(err error) string {
	switch {
	case errors.Is(err, ErrUnsupportedPlatform), errors.Is(err, ErrExecutable), errors.Is(err, ErrProcessStart):
		return "caller_start_failed"
	case errors.Is(err, ErrProcessCleanup):
		return "internal_failure"
	default:
		return "scenario_execution_failed"
	}
}

// NewSiblingRunner resolves a fixed sibling artifact name from the adapter's
// own executable location; no argv, environment, or working-directory value
// selects the caller executable.
func NewSiblingRunner() *Runner {
	executable, err := os.Executable()
	if err != nil {
		return NewRunner("")
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return NewRunner("")
	}
	name := "external-caller"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return NewRunner(filepath.Join(filepath.Dir(resolved), name))
}

func (runner *Runner) Start(parent context.Context, invocation protocol.Invocation, caseID string, bundle *credentials.Bundle) (protocol.ScenarioResultData, error) {
	if !processTransportSupported() {
		return protocol.ScenarioResultData{}, ErrUnsupportedPlatform
	}
	if runner == nil || bundle == nil || validateExecutable(runner.executable) != nil {
		return protocol.ScenarioResultData{}, ErrExecutable
	}
	if runner.session != nil {
		return protocol.ScenarioResultData{}, ErrProcessState
	}
	if parent == nil {
		parent = context.Background()
	}

	requirements := credentials.Requirements()
	readers := make([]*os.File, 0, len(requirements))
	writers := make([]*os.File, 0, len(requirements))
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	for index, requirement := range requirements {
		reader, writer, err := os.Pipe()
		if err != nil {
			closeFiles(readers)
			closeFiles(writers)
			return protocol.ScenarioResultData{}, ErrProcessIO
		}
		readers = append(readers, reader)
		writers = append(writers, writer)
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index,
		})
	}
	timeout := runner.timeout
	if timeout <= 0 || timeout > processTimeout {
		timeout = processTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	deadline, ok := boundedCaseDeadline(parent, ctx)
	if !ok {
		cancel()
		closeFiles(readers)
		closeFiles(writers)
		return protocol.ScenarioResultData{}, ErrProcessResult
	}
	request, err := scenariocontrol.NewRequest(invocation, caseID, descriptors, deadline)
	if err != nil {
		cancel()
		closeFiles(readers)
		closeFiles(writers)
		return protocol.ScenarioResultData{}, ErrProcessResult
	}
	command := exec.CommandContext(ctx, runner.executable)
	command.Args = []string{runner.executable}
	command.Env = []string{}
	command.ExtraFiles = readers
	configureProcessGroup(command)
	command.WaitDelay = processWaitDelay
	command.Cancel = func() error { return terminateProcessGroup(command.Process) }
	stdin, err := command.StdinPipe()
	if err != nil {
		cancel()
		closeFiles(readers)
		closeFiles(writers)
		return protocol.ScenarioResultData{}, ErrProcessIO
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		cancel()
		_ = stdin.Close()
		closeFiles(readers)
		closeFiles(writers)
		return protocol.ScenarioResultData{}, ErrProcessIO
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		cancel()
		_ = stdin.Close()
		_ = stdout.Close()
		closeFiles(readers)
		closeFiles(writers)
		return protocol.ScenarioResultData{}, ErrProcessIO
	}
	if err := command.Start(); err != nil {
		cancel()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		closeFiles(readers)
		closeFiles(writers)
		return protocol.ScenarioResultData{}, ErrProcessStart
	}
	closeFiles(readers)
	if runner.observePID != nil {
		runner.observePID(command.Process.Pid)
	}

	stderrResult := make(chan drainResult, 1)
	go func() { stderrResult <- drainBounded(stderr, maxStderrBytes) }()
	session := &Session{
		invocation: invocation, request: request, command: command, stdin: stdin,
		stdout: bufio.NewReader(stdout), stderr: stderrResult, ctx: ctx, cancel: cancel, next: 1,
	}
	stopClose := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stdin.Close()
			closeFiles(writers)
		case <-stopClose:
		}
	}()

	writeErr := scenariocontrol.EncodeRequest(stdin, request)
	for index, requirement := range requirements {
		if writeErr == nil {
			writeErr = bundle.Use(requirement.ChannelID, func(payload []byte) error {
				return writeAll(writers[index], payload)
			})
		}
		if closeErr := writers[index].Close(); writeErr == nil && closeErr != nil {
			writeErr = closeErr
		}
	}
	if writeErr != nil {
		cancel()
	}
	close(stopClose)
	if writeErr != nil {
		return protocol.ScenarioResultData{}, session.abort(ErrProcessIO)
	}
	caseCtx, caseCancel := context.WithDeadline(parent, deadline)
	stopWatch := watchCancellation(caseCtx, session)
	result, err := scenariocontrol.DecodeResultRecord(session.stdout)
	stopWatch()
	caseCancel()
	if err != nil || result.InvocationID != invocation.InvocationID || result.Phase != invocation.Phase || result.CaseID != caseID || result.ProcessID != command.Process.Pid {
		return protocol.ScenarioResultData{}, session.abort(resultError(caseCtx, ctx, ErrProcessResult))
	}
	privateCases := privateCaseIDs(invocation.Phase)
	if len(privateCases) == 0 || privateCases[0] != caseID {
		return protocol.ScenarioResultData{}, session.abort(ErrProcessResult)
	}
	if len(privateCases) == 1 {
		if err := session.finish(); err != nil {
			return protocol.ScenarioResultData{}, err
		}
		return result.Data(), nil
	}
	runner.session = session
	return result.Data(), nil
}

func (runner *Runner) Run(parent context.Context, caseID string) (protocol.ScenarioResultData, error) {
	if runner == nil || runner.session == nil {
		return protocol.ScenarioResultData{}, ErrProcessResult
	}
	result, err := runner.session.Run(parent, caseID)
	if runner.session.done {
		runner.session = nil
	}
	return result, err
}

func (runner *Runner) Close() error {
	if runner == nil || runner.session == nil {
		return nil
	}
	err := runner.session.Close()
	runner.session = nil
	return err
}

func (session *Session) Run(parent context.Context, caseID string) (protocol.ScenarioResultData, error) {
	if session == nil || session.done {
		return protocol.ScenarioResultData{}, ErrProcessResult
	}
	allCases := privateCaseIDs(session.invocation.Phase)
	if len(allCases) < 2 {
		return protocol.ScenarioResultData{}, session.abort(ErrProcessResult)
	}
	expected := allCases[1:]
	if session.next < 1 || session.next > len(expected) || caseID != expected[session.next-1] {
		return protocol.ScenarioResultData{}, session.abort(ErrProcessResult)
	}
	if parent == nil {
		parent = context.Background()
	}
	deadline, ok := boundedCaseDeadline(parent, session.ctx)
	if !ok {
		return protocol.ScenarioResultData{}, session.abort(ErrProcessTimeout)
	}
	command, err := scenariocontrol.NewCommand(session.request, caseID, deadline)
	if err != nil || scenariocontrol.EncodeCommand(session.stdin, command) != nil {
		return protocol.ScenarioResultData{}, session.abort(ErrProcessIO)
	}
	caseCtx, caseCancel := context.WithDeadline(parent, deadline)
	stopWatch := watchCancellation(caseCtx, session)
	result, decodeErr := scenariocontrol.DecodeResultRecord(session.stdout)
	stopWatch()
	caseCancel()
	if decodeErr != nil || result.InvocationID != session.invocation.InvocationID || result.Phase != session.invocation.Phase || result.CaseID != caseID || result.ProcessID != session.command.Process.Pid {
		return protocol.ScenarioResultData{}, session.abort(resultError(caseCtx, session.ctx, ErrProcessResult))
	}
	if session.next == len(expected) {
		if err := session.finish(); err != nil {
			return protocol.ScenarioResultData{}, err
		}
	} else {
		session.next++
	}
	return result.Data(), nil
}

func privateCaseIDs(phase string) []string {
	if phase == "reconstruction" {
		return []string{scenariocontrol.ReconstructionCapabilityCaseID, scenariocontrol.ReconstructionLifecycleCaseID, scenariocontrol.ReconstructionEvidenceCaseID, scenariocontrol.ReconstructionHandoffCaseID, scenariocontrol.ReconstructionReconnectCaseID}
	}
	if phase != "initial" {
		return nil
	}
	return []string{scenariocontrol.CapabilityCaseID, scenariocontrol.LifecycleCaseID, scenariocontrol.ReplayCaseID, scenariocontrol.LifecycleCompletionCaseID, scenariocontrol.ExecResultUsageCaseID, scenariocontrol.StaleFencingCaseID, scenariocontrol.ExecCancellationCaseID, scenariocontrol.TerminalSessionCaseID, scenariocontrol.GatewayRoundTripCaseID, scenariocontrol.GatewayAuthorityRejectionCaseID, scenariocontrol.GatewayGrantExpiryCaseID, scenariocontrol.GatewayRevocationCaseID, scenariocontrol.ArtifactStagingCaseID, scenariocontrol.CrossTenantArtifactCaseID, scenariocontrol.MTLSCallerBindingCaseID}
}

func (session *Session) Close() error {
	if session == nil || session.done {
		return nil
	}
	return session.abort(nil)
}

func (session *Session) finish() error {
	if session.done {
		return nil
	}
	_ = session.stdin.Close()
	waitErr, remainder, stderr, cleanupErr := session.waitAndDrain(true)
	session.done = true
	timedOut := errors.Is(session.ctx.Err(), context.DeadlineExceeded)
	session.cancel()
	if cleanupErr != nil {
		return cleanupErr
	}
	if timedOut {
		return ErrProcessTimeout
	}
	if waitErr != nil {
		return ErrProcessExit
	}
	if remainder.err != nil || len(remainder.data) != 0 || stderr.err != nil || len(stderr.data) != 0 {
		return fmt.Errorf("%w: stdout_remainder_bytes=%d stdout_error=%v stderr_bytes=%d stderr_error=%v", ErrProcessIO, len(remainder.data), remainder.err, len(stderr.data), stderr.err)
	}
	return nil
}

func (session *Session) abort(fallback error) error {
	if session == nil || session.done {
		return fallback
	}
	timedOut := errors.Is(session.ctx.Err(), context.DeadlineExceeded)
	_ = session.stdin.Close()
	_, _, _, cleanupErr := session.waitAndDrain(false)
	session.done = true
	if cleanupErr != nil {
		return cleanupErr
	}
	if timedOut {
		return ErrProcessTimeout
	}
	return fallback
}

func (session *Session) waitAndDrain(graceful bool) (error, drainResult, drainResult, error) {
	stdoutResult := make(chan drainResult, 1)
	waitResult := make(chan error, 1)
	go func() { stdoutResult <- drainBounded(session.stdout, scenariocontrol.MaxResultBytes) }()
	go func() { waitResult <- session.command.Wait() }()

	started := time.Now()
	var waitErr error
	waited := false
	if graceful {
		timer := time.NewTimer(gracefulExitWait)
		select {
		case waitErr = <-waitResult:
			waited = true
			timer.Stop()
		case <-timer.C:
			session.cancel()
		}
	} else {
		session.cancel()
	}
	deadline := started.Add(processReapLimit)
	if !waited {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			_ = terminateProcessGroup(session.command.Process)
			return nil, drainResult{}, drainResult{}, ErrProcessCleanup
		}
		timer := time.NewTimer(remaining)
		select {
		case waitErr = <-waitResult:
			timer.Stop()
		case <-timer.C:
			_ = terminateProcessGroup(session.command.Process)
			return nil, drainResult{}, drainResult{}, ErrProcessCleanup
		}
	}
	// The caller has its own process group. Even after the direct child exits,
	// kill any straggling descendants before accepting EOF and cleanup success.
	if err := terminateProcessGroup(session.command.Process); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return waitErr, drainResult{}, drainResult{}, ErrProcessCleanup
	}
	remainder, ok := receiveDrainBefore(stdoutResult, deadline)
	if !ok {
		return waitErr, drainResult{}, drainResult{}, ErrProcessCleanup
	}
	stderr, ok := receiveDrainBefore(session.stderr, deadline)
	if !ok {
		return waitErr, remainder, drainResult{}, ErrProcessCleanup
	}
	return waitErr, remainder, stderr, nil
}

func receiveDrainBefore(channel <-chan drainResult, deadline time.Time) (drainResult, bool) {
	select {
	case result := <-channel:
		return result, true
	default:
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return drainResult{}, false
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case result := <-channel:
		return result, true
	case <-timer.C:
		return drainResult{}, false
	}
}

func boundedCaseDeadline(parent, process context.Context) (time.Time, bool) {
	deadline := time.Now().Add(caseTimeout)
	if value, ok := parent.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if value, ok := process.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	return deadline.UTC(), deadline.After(time.Now())
}

func watchCancellation(ctx context.Context, session *Session) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			session.cancel()
			_ = session.stdin.Close()
		case <-done:
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

func resultError(caseCtx, processCtx context.Context, fallback error) error {
	if errors.Is(caseCtx.Err(), context.DeadlineExceeded) || errors.Is(processCtx.Err(), context.DeadlineExceeded) {
		return ErrProcessTimeout
	}
	return fallback
}

func validateExecutable(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrExecutable
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return ErrExecutable
	}
	return nil
}

type drainResult struct {
	data []byte
	err  error
}

func drainBounded(reader io.Reader, limit int) drainResult {
	buffer := make([]byte, 4096)
	data := make([]byte, 0, limit)
	overflow := false
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			remaining := limit - len(data)
			if remaining > 0 {
				copyCount := count
				if copyCount > remaining {
					copyCount = remaining
				}
				data = append(data, buffer[:copyCount]...)
			}
			if count > remaining {
				overflow = true
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return drainResult{data: data, err: ErrProcessIO}
			}
			if overflow {
				return drainResult{data: data, err: ErrProcessIO}
			}
			return drainResult{data: data}
		}
		if count == 0 {
			return drainResult{data: data, err: ErrProcessIO}
		}
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil || written <= 0 || written > len(payload) {
			return ErrProcessIO
		}
		payload = payload[written:]
	}
	return nil
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
