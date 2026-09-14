//go:build darwin || linux

package gatewayprocess

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
)

func TestRunnerUsesSeparateProcessAndCrossChecksPID(t *testing.T) {
	executable := buildExecutable(t, "./cmd/caller-gateway", "caller-gateway")
	bundle := testBundle(t)
	defer bundle.Destroy()
	runner := NewRunner(executable)
	observed := 0
	runner.observePID = func(pid int) { observed = pid }
	if err := runner.Run(context.Background(), "initial", "https://gateway.example/tunnel", bundle); err != nil {
		t.Fatal(err)
	}
	if observed < 1 || observed == os.Getpid() {
		t.Fatalf("observed Gateway PID = %d, test PID = %d", observed, os.Getpid())
	}
	assertReaped(t, observed)
}

func TestRunnerTimesOutKillsAndReapsProcessGroup(t *testing.T) {
	executable := buildExecutable(t, "./internal/callerprocess/testdata/hang", "hang")
	bundle := testBundle(t)
	defer bundle.Destroy()
	runner := NewRunner(executable)
	runner.timeout = 150 * time.Millisecond
	observed := 0
	runner.observePID = func(pid int) { observed = pid }
	started := time.Now()
	err := runner.Run(context.Background(), "initial", "https://gateway.example/tunnel", bundle)
	if !errors.Is(err, ErrProcessTimeout) {
		t.Fatalf("Runner.Run(hang) error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("bounded termination took %s", elapsed)
	}
	if observed < 1 {
		t.Fatal("hanging Gateway PID was not observed")
	}
	assertReaped(t, observed)
}

func TestRunnerRejectsSymlinkExecutableBeforeProcessStart(t *testing.T) {
	executable := buildExecutable(t, "./cmd/caller-gateway", "caller-gateway")
	linked := filepath.Join(t.TempDir(), "linked-gateway")
	if err := os.Symlink(executable, linked); err != nil {
		t.Fatal(err)
	}
	bundle := testBundle(t)
	defer bundle.Destroy()
	if err := NewRunner(linked).Run(context.Background(), "initial", "https://gateway.example/tunnel", bundle); !errors.Is(err, ErrExecutable) {
		t.Fatalf("Runner.Run(symlink) error = %v", err)
	}
}

func buildExecutable(t *testing.T, packagePath, name string) string {
	t.Helper()
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	output := filepath.Join(t.TempDir(), name)
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", output, packagePath)
	command.Dir = repositoryRoot
	if buildOutput, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v: %s", packagePath, err, buildOutput)
	}
	return output
}

func testBundle(t *testing.T) *credentials.Bundle {
	return testBundleWithPayloads(t, testcredentials.New(t).Payloads)
}

func testBundleWithPayloads(t *testing.T, payloads map[string][]byte) *credentials.Bundle {
	t.Helper()
	requirements := credentials.Requirements()
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	writers := make([]*os.File, 0, len(requirements))
	for _, requirement := range requirements {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		ownedDescriptor, err := syscall.Dup(int(reader.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		writers = append(writers, writer)
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: ownedDescriptor,
		})
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write(payloads[requirements[index].ChannelID])
			_ = writer.Close()
		}(index, writer)
	}
	bundle, err := credentials.NewReader(requirements).Read(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestRunnerForwardsOnlyServerIdentityAndTrust(t *testing.T) {
	executable := buildExecutable(t, "./cmd/caller-gateway", "caller-gateway")
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid server only", false: "invalid server"}[valid], func(t *testing.T) {
			payloads := testcredentials.New(t).Payloads
			for _, id := range []string{"provider-controller-a", "provider-controller-b", "provider-same-ca-unadmitted", "provider-trust", "gateway-controller-a", "gateway-controller-b"} {
				payloads[id] = []byte("forbidden-client-material-marker")
			}
			if !valid {
				payloads["gateway-server"] = []byte("invalid-server-secret-marker")
			}
			bundle := testBundleWithPayloads(t, payloads)
			defer bundle.Destroy()
			err := NewRunner(executable).Run(context.Background(), "initial", "https://gateway.example/tunnel", bundle)
			if valid && err != nil {
				t.Fatal(err)
			}
			if !valid && !errors.Is(err, ErrProcessExit) {
				t.Fatalf("bad server failure = %v", err)
			}
		})
	}
}

func TestRunnerTimeoutUnblocksLargeServerSecretWrite(t *testing.T) {
	executable := buildExecutable(t, "./internal/callerprocess/testdata/hang", "hang")
	payloads := testcredentials.New(t).Payloads
	payloads["gateway-server"] = bytes.Repeat([]byte("x"), credentials.GatewayRequirements()[0].MaxBytes)
	bundle := testBundleWithPayloads(t, payloads)
	defer bundle.Destroy()
	runner := NewRunner(executable)
	runner.timeout = 150 * time.Millisecond
	observed := 0
	runner.observePID = func(pid int) { observed = pid }
	started := time.Now()
	if err := runner.Run(context.Background(), "initial", "https://gateway.example/tunnel", bundle); !errors.Is(err, ErrProcessTimeout) {
		t.Fatalf("blocked secret write error = %v", err)
	}
	if time.Since(started) > 3*time.Second || observed == 0 {
		t.Fatal("blocked secret write exceeded bounded shutdown")
	}
	assertReaped(t, observed)
}

func assertReaped(t *testing.T, pid int) {
	t.Helper()
	process, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	if err := process.Signal(syscall.Signal(0)); err == nil {
		t.Fatalf("process %d is still running", pid)
	}
}
