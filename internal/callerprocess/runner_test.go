//go:build darwin || linux

package callerprocess

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testprovider"
)

func TestRunnerUsesSeparateProcessAndCrossChecksPID(t *testing.T) {
	executable := buildCallerAndGateway(t)
	for _, phase := range []string{"initial", "reconstruction"} {
		t.Run(phase, func(t *testing.T) {
			endpoint := localGatewayEndpoint(t)
			fixture := testcredentials.NewForGatewayHost(t, "127.0.0.1")
			providerServer := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
			bundle := testBundle(t, fixture.Payloads)
			defer bundle.Destroy()
			root := newCallerStateRoot(t)
			var before []byte
			if phase == "reconstruction" {
				state := completeCallerState(t, root)
				providerServer.SeedLifecycle(state)
				var err error
				before, err = os.ReadFile(filepath.Join(root, callerstate.StateFileName))
				if err != nil {
					t.Fatal(err)
				}
			}
			runner := NewRunner(executable)
			observed := 0
			runner.observePID = func(pid int) { observed = pid }
			invocation := testRunnerInvocation(phase, endpoint, root)
			invocation.ProviderOrigin = providerServer.Origin()
			if err := runner.Run(context.Background(), invocation, bundle); err != nil {
				t.Fatal(err)
			}
			if observed < 1 || observed == os.Getpid() {
				t.Fatalf("observed external caller PID = %d, test PID = %d", observed, os.Getpid())
			}
			assertReaped(t, observed)
			after, err := os.ReadFile(filepath.Join(root, callerstate.StateFileName))
			if err != nil {
				t.Fatal(err)
			}
			if phase == "reconstruction" {
				if !bytes.Equal(after, before) {
					t.Fatal("reconstruction changed retained caller state bytes")
				}
			} else if !bytes.Contains(after, []byte(`"stage":"lifecycle_bound"`)) {
				t.Fatalf("initial phase state = %q", after)
			}
			counts, serverErrors := providerServer.Snapshot()
			if len(serverErrors) != 0 || counts.Capabilities != map[bool]int{true: 1, false: 2}[phase == "reconstruction"] || counts.Operations != 1 || counts.Statuses != 1 || counts.Creates != map[bool]int{true: 0, false: 1}[phase == "reconstruction"] {
				t.Fatalf("Provider process composition = %#v / %v", counts, serverErrors)
			}
		})
	}
}

func buildCallerAndGateway(t *testing.T) string {
	t.Helper()
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	directory := t.TempDir()
	caller := filepath.Join(directory, "external-caller")
	for _, artifact := range []struct {
		path string
		name string
	}{
		{path: "./cmd/external-caller", name: "external-caller"},
		{path: "./cmd/caller-gateway", name: "caller-gateway"},
	} {
		command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", filepath.Join(directory, artifact.name), artifact.path)
		command.Dir = repositoryRoot
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v: %s", artifact.path, err, output)
		}
	}
	return caller
}

func TestRunnerTimesOutKillsAndReapsProcessGroup(t *testing.T) {
	executable := buildExecutable(t, "./internal/callerprocess/testdata/hang", "hang")
	bundle := testBundle(t, testcredentials.New(t).Payloads)
	defer bundle.Destroy()
	runner := NewRunner(executable)
	runner.timeout = 150 * time.Millisecond
	observed := 0
	runner.observePID = func(pid int) { observed = pid }
	started := time.Now()
	err := runner.Run(context.Background(), testRunnerInvocation("initial", "https://gateway.example/tunnel", newCallerStateRoot(t)), bundle)
	if !errors.Is(err, ErrProcessTimeout) {
		t.Fatalf("Runner.Run(hang) error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("bounded termination took %s", elapsed)
	}
	if observed < 1 {
		t.Fatal("hanging process PID was not observed")
	}
	assertReaped(t, observed)
}

func TestRunnerRejectsSymlinkExecutableBeforeProcessStart(t *testing.T) {
	executable := buildExecutable(t, "./cmd/external-caller", "external-caller")
	linked := filepath.Join(t.TempDir(), "linked-caller")
	if err := os.Symlink(executable, linked); err != nil {
		t.Fatal(err)
	}
	bundle := testBundle(t, testcredentials.New(t).Payloads)
	defer bundle.Destroy()
	runner := NewRunner(linked)
	if err := runner.Run(context.Background(), testRunnerInvocation("initial", "https://gateway.example/tunnel", newCallerStateRoot(t)), bundle); !errors.Is(err, ErrExecutable) {
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

func testBundle(t *testing.T, payloads map[string][]byte) *credentials.Bundle {
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

func testRunnerInvocation(phase, endpoint, root string) protocol.Invocation {
	return protocol.Invocation{
		FormatVersion: protocol.FormatVersion, ProtocolID: protocol.ProtocolID, ProtocolVersion: protocol.ProtocolVersion,
		MessageType: "invocation", InvocationID: "runner-test", Phase: phase, ProfilePath: "/qualification/profile.json",
		ProviderOrigin: "https://provider.example", GatewayProbeEndpoint: endpoint, CallerStateRoot: root,
	}
}

func localGatewayEndpoint(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return "https://" + address + "/tunnel"
}

func newCallerStateRoot(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "caller-state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func completeCallerState(t *testing.T, root string) callerstate.State {
	t.Helper()
	store, err := callerstate.CreateInitial(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	for _, step := range []func() error{
		func() error {
			return store.BindCapabilities("provider-revision-local-v1", testprovider.CapabilitiesDocument(), digest("f"), "2026-09-12T00:00:00Z")
		},
		func() error { return store.BindLifecycle(1) },
		func() error { return store.BindExec(2, digest("a"), digest("b")) },
		func() error { return store.BindTerminal(3, "runtime-session-1", "opaque:handoff:1") },
		func() error { return store.BindArtifact(4, digest("c")) },
	} {
		if err := step(); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
	}
	state := store.Snapshot()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return state
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
