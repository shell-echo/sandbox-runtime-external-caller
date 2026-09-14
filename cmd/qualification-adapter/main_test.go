package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testprovider"
)

func TestExecutableEmitsStartupBeforeSupervisorInputOrCredentials(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("locked inherited-pipe transport supports Darwin and Linux")
	}
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	artifactDirectory := t.TempDir()
	executable := filepath.Join(artifactDirectory, "qualification-adapter")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", executable, "./cmd/qualification-adapter")
	build.Dir = repositoryRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build qualification adapter: %v: %s", err, output)
	}
	callerExecutable := filepath.Join(artifactDirectory, "external-caller")
	build = exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", callerExecutable, "./cmd/external-caller")
	build.Dir = repositoryRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build external caller: %v: %s", err, output)
	}
	gatewayExecutable := filepath.Join(artifactDirectory, "caller-gateway")
	build = exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", gatewayExecutable, "./cmd/caller-gateway")
	build.Dir = repositoryRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build caller Gateway: %v: %s", err, output)
	}
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid identities", false: "invalid server identity"}[valid], func(t *testing.T) {
			runAdapterIdentityCase(t, executable, valid)
		})
	}
}

func runAdapterIdentityCase(t *testing.T, executable string, valid bool) {
	t.Helper()
	requirements := credentials.Requirements()
	fixture := testcredentials.NewForGatewayHost(t, "127.0.0.1")
	providerServer := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
	payloads := fixture.Payloads
	if !valid {
		payloads["gateway-server"] = []byte(`{"private_key_pem":"synthetic-secret-marker"}`)
	}
	readers := make([]*os.File, 0, len(requirements))
	writers := make([]*os.File, 0, len(requirements))
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	for index, requirement := range requirements {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		readers = append(readers, reader)
		writers = append(writers, writer)
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index,
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable)
	command.Dir = t.TempDir()
	command.Env = []string{}
	command.ExtraFiles = readers
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	for _, reader := range readers {
		_ = reader.Close()
	}

	output := bufio.NewReader(stdout)
	startupLine, err := output.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read startup before input: %v", err)
	}
	var startup protocol.StartupIdentity
	if err := json.Unmarshal(bytes.TrimSuffix(startupLine, []byte{'\n'}), &startup); err != nil || protocol.ValidateStartup(startup) != nil {
		t.Fatalf("startup record is invalid: %v: %q", err, startupLine)
	}
	if startup.CallerReleaseIdentity.Value != "local-development" || startup.AdapterReleaseIdentity.Value != "local-development" {
		t.Fatalf("development release identities = %#v / %#v", startup.CallerReleaseIdentity, startup.AdapterReleaseIdentity)
	}
	if len(startup.CredentialChannelRequirements) != 8 || startup.CredentialChannelRequirements[7].ChannelID != "gateway-server" {
		t.Fatal("server credential was not declared before input")
	}
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gatewayEndpoint := "https://" + reservation.Addr().String() + "/tunnel"
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	stateBase, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(stateBase, "caller-state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	invocation := protocol.Invocation{
		FormatVersion: protocol.FormatVersion, ProtocolID: protocol.ProtocolID, ProtocolVersion: protocol.ProtocolVersion,
		MessageType: "invocation", InvocationID: "process.initial", Phase: "initial", ProfilePath: "/qualification/profile.json",
		ProviderOrigin: providerServer.Origin(), GatewayProbeEndpoint: gatewayEndpoint,
		CredentialChannelDescriptors: descriptors, CallerStateRoot: stateRoot,
	}
	document, err := json.Marshal(invocation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(document); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		if _, err := writer.Write(payloads[requirements[index].ChannelID]); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	remainder, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("qualification adapter exit: %v; stderr=%q", err, stderr.Bytes())
	}
	if ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatalf("process context/stderr = %v / %q", ctx.Err(), stderr.Bytes())
	}
	lines := bytes.Split(bytes.TrimSuffix(remainder, []byte{'\n'}), []byte{'\n'})
	if !valid {
		if len(lines) != 2 || !bytes.Contains(lines[1], []byte(`"error_code":"caller_start_failed"`)) || bytes.Contains(remainder, []byte("synthetic-secret-marker")) {
			t.Fatal("invalid server identity did not produce a sanitized pre-scenario failure")
		}
		if entries, err := os.ReadDir(stateRoot); err != nil || len(entries) != 0 {
			t.Fatalf("credential failure touched state root: %v, %#v", err, entries)
		}
		if counts, serverErrors := providerServer.Snapshot(); len(serverErrors) != 0 || counts != (testprovider.Counts{}) {
			t.Fatalf("credential failure reached Provider: %#v / %v", counts, serverErrors)
		}
		return
	}
	if len(lines) != 17 || !bytes.Contains(lines[0], []byte(`"message_type":"invocation_accepted"`)) || !bytes.Contains(lines[len(lines)-1], []byte(`"completion":"stopped"`)) {
		t.Fatalf("post-startup output has %d records: %q", len(lines), remainder)
	}
	stateDocument, err := os.ReadFile(filepath.Join(stateRoot, callerstate.StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	var state callerstate.State
	if err := json.Unmarshal(stateDocument, &state); err != nil || state.Stage != callerstate.StageLifecycleBound || state.StoreRevision != 3 {
		t.Fatalf("operational initial state = %#v, %v", state, err)
	}
	if entries, err := os.ReadDir(stateRoot); err != nil || len(entries) != 1 || entries[0].Name() != callerstate.StateFileName {
		t.Fatalf("operational initial root = %v, %#v", err, entries)
	}
	if counts, serverErrors := providerServer.Snapshot(); len(serverErrors) != 0 || counts.Capabilities != 2 || counts.Creates != 1 || counts.Operations != 1 || counts.Statuses != 1 {
		t.Fatalf("operational Provider composition = %#v / %v", counts, serverErrors)
	}
}
