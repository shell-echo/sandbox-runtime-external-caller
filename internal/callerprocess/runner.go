// Package callerprocess launches and supervises the candidate-owned external
// caller over a private control channel plus separate credential pipes.
package callerprocess

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callercontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const (
	// The current preparation-only caller has ten seconds for strict state,
	// live Gateway startup, policy installation, clean stop and reap. This same
	// absolute deadline is propagated over private control.
	processTimeout   = 10 * time.Second
	processWaitDelay = 2 * time.Second
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
)

type Runner struct {
	executable string
	observePID func(int)
	timeout    time.Duration
}

func NewRunner(executable string) *Runner {
	return &Runner{executable: executable, timeout: processTimeout}
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

func (runner *Runner) Run(parent context.Context, invocation protocol.Invocation, bundle *credentials.Bundle) error {
	if !processTransportSupported() {
		return ErrUnsupportedPlatform
	}
	if runner == nil || bundle == nil || validateExecutable(runner.executable) != nil {
		return ErrExecutable
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
			return ErrProcessIO
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
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		closeFiles(readers)
		closeFiles(writers)
		return ErrProcessResult
	}
	request, err := callercontrol.NewRequest(invocation, descriptors, deadline)
	if err != nil {
		closeFiles(readers)
		closeFiles(writers)
		return ErrProcessResult
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
		closeFiles(readers)
		closeFiles(writers)
		return ErrProcessIO
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		closeFiles(readers)
		closeFiles(writers)
		return ErrProcessIO
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		closeFiles(readers)
		closeFiles(writers)
		return ErrProcessIO
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		closeFiles(readers)
		closeFiles(writers)
		return ErrProcessStart
	}
	closeFiles(readers)
	if runner.observePID != nil {
		runner.observePID(command.Process.Pid)
	}

	stdoutResult := make(chan drainResult, 1)
	stderrResult := make(chan drainResult, 1)
	go func() { stdoutResult <- drainBounded(stdout, callercontrol.MaxResultBytes) }()
	go func() { stderrResult <- drainBounded(stderr, maxStderrBytes) }()
	stopClose := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stdin.Close()
			closeFiles(writers)
		case <-stopClose:
		}
	}()

	writeErr := callercontrol.EncodeRequest(stdin, request)
	if closeErr := stdin.Close(); writeErr == nil && closeErr != nil {
		writeErr = closeErr
	}
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
	waitErr := command.Wait()
	close(stopClose)
	stdoutBytes := <-stdoutResult
	stderrBytes := <-stderrResult
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrProcessTimeout
	}
	if writeErr != nil || stdoutBytes.err != nil || stderrBytes.err != nil || len(stderrBytes.data) != 0 {
		return ErrProcessIO
	}
	if waitErr != nil {
		return ErrProcessExit
	}
	result, err := callercontrol.DecodeResult(bytesReader(stdoutBytes.data))
	if err != nil || result.Phase != invocation.Phase || result.ProcessID != command.Process.Pid {
		return ErrProcessResult
	}
	return nil
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

type byteReader struct {
	data []byte
}

func bytesReader(data []byte) *byteReader { return &byteReader{data: data} }

func (reader *byteReader) Read(buffer []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	count := copy(buffer, reader.data)
	reader.data = reader.data[count:]
	return count, nil
}
