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
	providerServer.SetTerminalShell(true)
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
		if len(lines) != 3 || !bytes.Contains(lines[1], []byte(`"message_type":"scenario_started"`)) || !bytes.Contains(lines[2], []byte(`"error_code":"scenario_execution_failed"`)) || bytes.Contains(remainder, []byte("synthetic-secret-marker")) {
			t.Fatal("invalid server identity did not produce a sanitized scenario failure")
		}
		if entries, err := os.ReadDir(stateRoot); err != nil || len(entries) != 0 {
			t.Fatalf("credential failure touched state root: %v, %#v", err, entries)
		}
		if counts, serverErrors := providerServer.Snapshot(); len(serverErrors) != 0 || counts != (testprovider.Counts{}) {
			t.Fatalf("credential failure reached Provider: %#v / %v", counts, serverErrors)
		}
		return
	}
	if len(lines) != 32 || !bytes.Contains(lines[0], []byte(`"message_type":"invocation_accepted"`)) || !bytes.Contains(lines[27], []byte(`"case_id":"initial.provider-cross-tenant-artifact-rejection"`)) || !bytes.Contains(lines[28], []byte(`"error_code":"SANDBOX_NOT_FOUND"`)) || !bytes.Contains(lines[29], []byte(`"case_id":"initial.provider-mtls-caller-binding-rejection"`)) || !bytes.Contains(lines[30], []byte(`"error_code":"SANDBOX_FORBIDDEN"`)) || !bytes.Contains(lines[31], []byte(`"completion":"completed"`)) {
		t.Fatalf("post-startup output has %d records: %q", len(lines), remainder)
	}
	var completed protocol.ScenarioResult
	if err := json.Unmarshal(lines[2], &completed); err != nil || completed.CaseID != "initial.locked-capability-discovery" || completed.Sequence != 3 || len(completed.Interactions) != 3 || len(completed.Assertions) != 3 || len(completed.ObservationIDs) != 9 || completed.ReasonCode != nil {
		t.Fatalf("completed capability result = %#v, %v", completed, err)
	}
	for index, expected := range []struct {
		id, actor, transport string
		status               int
	}{
		{id: "controller-a-capabilities", actor: "controller_a", transport: "http-response", status: 200},
		{id: "controller-b-capabilities", actor: "controller_b", transport: "http-response", status: 200},
		{id: "same-ca-unadmitted-capabilities", actor: "same_ca_unadmitted", transport: "http-response", status: 403},
	} {
		interaction := completed.Interactions[index]
		if interaction.InteractionID != expected.id || interaction.Actor != expected.actor || interaction.FinalOutcome.Transport != expected.transport || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != expected.status || interaction.WireAttempts != 1 || interaction.MutationWriteObserved {
			t.Fatalf("capability interaction %d = %#v", index, interaction)
		}
	}
	for _, assertion := range completed.Assertions {
		if assertion.Result != "asserted" {
			t.Fatalf("capability assertion = %#v", assertion)
		}
	}
	var create protocol.ScenarioResult
	if err := json.Unmarshal(lines[4], &create); err != nil || create.CaseID != "initial.protected-lifecycle-create" || create.Sequence != 5 || len(create.Interactions) != 1 || len(create.Assertions) != 3 || len(create.ObservationIDs) != 5 || create.ReasonCode != nil {
		t.Fatalf("completed create result = %#v, %v", create, err)
	}
	interaction := create.Interactions[0]
	if interaction.InteractionID != "create-sandbox" || interaction.Actor != "controller_a" || interaction.Method != "POST" || interaction.RouteTemplate != "/v1/sandboxes" || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != 202 || interaction.WireAttempts != 1 || !interaction.MutationWriteObserved {
		t.Fatalf("create interaction = %#v", interaction)
	}
	var replay protocol.ScenarioResult
	if err := json.Unmarshal(lines[6], &replay); err != nil || replay.CaseID != "initial.replay-semantics" || replay.Sequence != 7 || len(replay.Interactions) != 2 || len(replay.Assertions) != 2 || len(replay.ObservationIDs) != 6 || replay.ReasonCode != nil {
		t.Fatalf("completed replay result = %#v, %v", replay, err)
	}
	if exact, fresh := replay.Interactions[0], replay.Interactions[1]; exact.InteractionID != "exact-jti-replay" || exact.ReplayOf == nil || *exact.ReplayOf != "create-sandbox" || exact.FinalOutcome.StatusCode == nil || *exact.FinalOutcome.StatusCode != 409 || exact.FinalOutcome.Retryable || !exact.MutationWriteObserved || fresh.InteractionID != "new-jti-idempotency-replay" || fresh.ReplayOf == nil || *fresh.ReplayOf != "create-sandbox" || fresh.FinalOutcome.StatusCode == nil || *fresh.FinalOutcome.StatusCode != 202 || !fresh.MutationWriteObserved {
		t.Fatalf("replay interactions = %#v", replay.Interactions)
	}
	var lifecycle protocol.ScenarioResult
	if err := json.Unmarshal(lines[8], &lifecycle); err != nil || lifecycle.CaseID != "initial.lifecycle-completion-and-status" || lifecycle.Sequence != 9 || len(lifecycle.Interactions) != 2 || len(lifecycle.Assertions) != 1 || len(lifecycle.ObservationIDs) != 4 || lifecycle.ReasonCode != nil {
		t.Fatalf("completed lifecycle result = %#v, %v", lifecycle, err)
	}
	for index, expected := range []struct {
		id, route string
	}{
		{id: "read-create-operation", route: "/v1/operations/{operation_id}"},
		{id: "read-sandbox-status", route: "/v1/sandboxes/{sandbox_id}"},
	} {
		interaction := lifecycle.Interactions[index]
		if interaction.InteractionID != expected.id || interaction.Actor != "controller_a" || interaction.Method != "GET" || interaction.RouteTemplate != expected.route || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != 200 || interaction.WireAttempts != 1 || interaction.MutationWriteObserved {
			t.Fatalf("lifecycle interaction %d = %#v", index, interaction)
		}
	}
	var execEvidence protocol.ScenarioResult
	if err := json.Unmarshal(lines[10], &execEvidence); err != nil || execEvidence.CaseID != "initial.exec-result-and-usage-evidence" || execEvidence.Sequence != 11 || len(execEvidence.Interactions) != 4 || len(execEvidence.Assertions) != 2 || len(execEvidence.ObservationIDs) != 7 || execEvidence.ReasonCode != nil {
		t.Fatalf("completed exec evidence result = %#v, %v", execEvidence, err)
	}
	for index, expected := range []struct {
		id, method, route string
		status            int
		mutation          bool
	}{
		{id: "start-output-exec", method: "POST", route: "/v1/sandboxes/{sandbox_id}/exec", status: 202, mutation: true},
		{id: "read-output-exec-operation", method: "GET", route: "/v1/operations/{operation_id}", status: 200},
		{id: "read-exec-result", method: "GET", route: "/v1/operations/{operation_id}/exec-result", status: 200},
		{id: "read-exec-usage", method: "GET", route: "/v1/operations/{operation_id}/usage-evidence", status: 200},
	} {
		interaction := execEvidence.Interactions[index]
		if interaction.InteractionID != expected.id || interaction.Actor != "controller_a" || interaction.Method != expected.method || interaction.RouteTemplate != expected.route || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != expected.status || interaction.WireAttempts != 1 || interaction.MutationWriteObserved != expected.mutation {
			t.Fatalf("exec evidence interaction %d = %#v", index, interaction)
		}
	}
	var stale protocol.ScenarioResult
	if err := json.Unmarshal(lines[12], &stale); err != nil || stale.CaseID != "initial.stale-fencing-rejection" || stale.Sequence != 13 || len(stale.Interactions) != 1 || len(stale.Assertions) != 1 || len(stale.ObservationIDs) != 3 || stale.ReasonCode != nil {
		t.Fatalf("completed stale-fencing result = %#v, %v", stale, err)
	}
	staleInteraction := stale.Interactions[0]
	if staleInteraction.InteractionID != "start-stale-fence-exec" || staleInteraction.Actor != "controller_a" || staleInteraction.Method != "POST" || staleInteraction.RouteTemplate != "/v1/sandboxes/{sandbox_id}/exec" || staleInteraction.WireAttempts != 1 || staleInteraction.FinalOutcome.StatusCode == nil || *staleInteraction.FinalOutcome.StatusCode != 409 || staleInteraction.FinalOutcome.ErrorCode == nil || *staleInteraction.FinalOutcome.ErrorCode != "SANDBOX_STALE_FENCING_TOKEN" || staleInteraction.FinalOutcome.Retryable || staleInteraction.FinalOutcome.RetryAfterPresent || !staleInteraction.MutationWriteObserved {
		t.Fatalf("stale-fencing interaction = %#v", staleInteraction)
	}
	var cancellation protocol.ScenarioResult
	if err := json.Unmarshal(lines[14], &cancellation); err != nil || cancellation.CaseID != "initial.exec-cancellation" || cancellation.Sequence != 15 || len(cancellation.Interactions) != 5 || len(cancellation.Assertions) != 2 || len(cancellation.ObservationIDs) != 5 || cancellation.ReasonCode != nil {
		t.Fatalf("completed exec cancellation result = %#v, %v", cancellation, err)
	}
	for index, expected := range []struct {
		id, method, route string
		status            int
		mutation          bool
	}{
		{id: "start-cancellable-exec", method: "POST", route: "/v1/sandboxes/{sandbox_id}/exec", status: 202, mutation: true},
		{id: "cancel-exec", method: "POST", route: "/v1/sandboxes/{sandbox_id}/exec:cancel", status: 202, mutation: true},
		{id: "read-cancel-operation", method: "GET", route: "/v1/operations/{operation_id}", status: 200},
		{id: "read-cancelled-operation", method: "GET", route: "/v1/operations/{operation_id}", status: 200},
		{id: "read-cancelled-result", method: "GET", route: "/v1/operations/{operation_id}/exec-result", status: 200},
	} {
		interaction := cancellation.Interactions[index]
		if interaction.InteractionID != expected.id || interaction.Actor != "controller_a" || interaction.Method != expected.method || interaction.RouteTemplate != expected.route || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != expected.status || interaction.WireAttempts != 1 || interaction.MutationWriteObserved != expected.mutation {
			t.Fatalf("exec cancellation interaction %d = %#v", index, interaction)
		}
	}
	var terminal protocol.ScenarioResult
	if err := json.Unmarshal(lines[16], &terminal); err != nil || terminal.CaseID != "initial.terminal-session-and-opaque-handoff" || terminal.Sequence != 17 || len(terminal.Interactions) != 3 || len(terminal.Assertions) != 1 || len(terminal.ObservationIDs) != 5 || terminal.ReasonCode != nil {
		t.Fatalf("completed terminal handoff result = %#v, %v", terminal, err)
	}
	for index, expected := range []struct {
		id, method, route string
		status            int
		mutation          bool
	}{
		{id: "open-terminal-session", method: "POST", route: "/v1/sandboxes/{sandbox_id}/runtime-sessions", status: 202, mutation: true},
		{id: "read-terminal-operation", method: "GET", route: "/v1/operations/{operation_id}", status: 200},
		{id: "read-terminal-handoff", method: "GET", route: "/v1/operations/{operation_id}/runtime-session", status: 200},
	} {
		interaction := terminal.Interactions[index]
		if interaction.InteractionID != expected.id || interaction.Actor != "controller_a" || interaction.Method != expected.method || interaction.RouteTemplate != expected.route || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != expected.status || interaction.WireAttempts != 1 || interaction.MutationWriteObserved != expected.mutation {
			t.Fatalf("terminal handoff interaction %d = %#v", index, interaction)
		}
	}
	var gatewayRoundTrip protocol.ScenarioResult
	if err := json.Unmarshal(lines[18], &gatewayRoundTrip); err != nil || gatewayRoundTrip.CaseID != "initial.gateway-terminal-byte-round-trip" || gatewayRoundTrip.Sequence != 19 || len(gatewayRoundTrip.Interactions) != 1 || len(gatewayRoundTrip.Assertions) != 1 || len(gatewayRoundTrip.ObservationIDs) != 5 || gatewayRoundTrip.ReasonCode != nil {
		t.Fatalf("completed Gateway round-trip result = %#v, %v", gatewayRoundTrip, err)
	}
	gatewayInteraction := gatewayRoundTrip.Interactions[0]
	if gatewayInteraction.InteractionID != "gateway-terminal-round-trip" || gatewayInteraction.Surface != "caller_gateway" || gatewayInteraction.Actor != "controller_a" || gatewayInteraction.Method != "CONNECT" || gatewayInteraction.RouteTemplate != "consumer-defined:terminal-connect" || gatewayInteraction.FinalOutcome.Transport != "authorized-byte-round-trip" || gatewayInteraction.FinalOutcome.StatusCode != nil || gatewayInteraction.FinalOutcome.ErrorCode != nil || gatewayInteraction.WireAttempts != 1 || gatewayInteraction.MutationWriteObserved {
		t.Fatalf("Gateway round-trip interaction = %#v", gatewayInteraction)
	}
	var gatewayRejection protocol.ScenarioResult
	if err := json.Unmarshal(lines[20], &gatewayRejection); err != nil || gatewayRejection.CaseID != "initial.gateway-wrong-caller-and-cross-tenant-rejection" || gatewayRejection.Sequence != 21 || len(gatewayRejection.Interactions) != 2 || len(gatewayRejection.Assertions) != 1 || len(gatewayRejection.ObservationIDs) != 3 || gatewayRejection.ReasonCode != nil {
		t.Fatalf("completed Gateway rejection result = %#v, %v", gatewayRejection, err)
	}
	for index, interaction := range gatewayRejection.Interactions {
		if interaction.Surface != "caller_gateway" || interaction.Method != "CONNECT" || interaction.RouteTemplate != "consumer-defined:terminal-connect" || interaction.FinalOutcome.Transport != "gateway-upgrade-rejected" || interaction.FinalOutcome.StatusCode != nil || interaction.FinalOutcome.ErrorCode != nil || interaction.WireAttempts != 1 || interaction.MutationWriteObserved || len(interaction.TransientOutcomes) != 0 {
			t.Fatalf("Gateway rejection interaction %d = %#v", index, interaction)
		}
	}
	var gatewayExpiry protocol.ScenarioResult
	if err := json.Unmarshal(lines[22], &gatewayExpiry); err != nil || gatewayExpiry.CaseID != "initial.gateway-grant-expiry" || gatewayExpiry.Sequence != 23 || len(gatewayExpiry.Interactions) != 1 || len(gatewayExpiry.Assertions) != 1 || len(gatewayExpiry.ObservationIDs) != 3 || gatewayExpiry.ReasonCode != nil {
		t.Fatalf("completed Gateway expiry result = %#v, %v", gatewayExpiry, err)
	}
	expiryInteraction := gatewayExpiry.Interactions[0]
	if expiryInteraction.InteractionID != "gateway-expiring-grant" || expiryInteraction.Surface != "caller_gateway" || expiryInteraction.Actor != "controller_a" || expiryInteraction.Method != "CONNECT" || expiryInteraction.RouteTemplate != "consumer-defined:terminal-connect" || expiryInteraction.FinalOutcome.Transport != "gateway-closed-at-grant-expiry" || expiryInteraction.FinalOutcome.StatusCode != nil || expiryInteraction.FinalOutcome.ErrorCode != nil || expiryInteraction.WireAttempts != 1 || expiryInteraction.MutationWriteObserved || len(expiryInteraction.TransientOutcomes) != 0 {
		t.Fatalf("Gateway expiry interaction = %#v", expiryInteraction)
	}
	var gatewayRevocation protocol.ScenarioResult
	if err := json.Unmarshal(lines[24], &gatewayRevocation); err != nil || gatewayRevocation.CaseID != "initial.gateway-revocation" || gatewayRevocation.Sequence != 25 || len(gatewayRevocation.Interactions) != 2 || len(gatewayRevocation.Assertions) != 1 || len(gatewayRevocation.ObservationIDs) != 3 || gatewayRevocation.ReasonCode != nil {
		t.Fatalf("completed Gateway revocation result = %#v, %v", gatewayRevocation, err)
	}
	if connect, revoke := gatewayRevocation.Interactions[0], gatewayRevocation.Interactions[1]; connect.InteractionID != "gateway-revocable-grant" || connect.FinalOutcome.Transport != "authorized-byte-round-trip" || connect.WireAttempts != 1 || connect.MutationWriteObserved || revoke.InteractionID != "gateway-revoke-grant" || revoke.Method != "CONTROL" || revoke.RouteTemplate != "consumer-defined:revoke-grant" || revoke.FinalOutcome.Transport != "revocation-acknowledged" || revoke.WireAttempts != 1 || !revoke.MutationWriteObserved {
		t.Fatalf("Gateway revocation interactions = %#v", gatewayRevocation.Interactions)
	}
	var artifact protocol.ScenarioResult
	if err := json.Unmarshal(lines[26], &artifact); err != nil || artifact.CaseID != "initial.artifact-staging-and-evidence" || artifact.Sequence != 27 || len(artifact.Interactions) != 3 || len(artifact.Assertions) != 1 || len(artifact.ObservationIDs) != 5 || artifact.ReasonCode != nil {
		t.Fatalf("completed artifact result = %#v, %v", artifact, err)
	}
	var crossTenant protocol.ScenarioResult
	if err := json.Unmarshal(lines[28], &crossTenant); err != nil || crossTenant.CaseID != "initial.provider-cross-tenant-artifact-rejection" || crossTenant.Sequence != 29 || len(crossTenant.Interactions) != 2 || len(crossTenant.Assertions) != 1 || len(crossTenant.ObservationIDs) != 4 || crossTenant.ReasonCode != nil {
		t.Fatalf("completed cross-tenant artifact result = %#v, %v", crossTenant, err)
	}
	if stage, read := crossTenant.Interactions[0], crossTenant.Interactions[1]; stage.FinalOutcome.StatusCode == nil || *stage.FinalOutcome.StatusCode != 403 || stage.FinalOutcome.ErrorCode == nil || *stage.FinalOutcome.ErrorCode != "SANDBOX_FORBIDDEN" || !stage.MutationWriteObserved || read.FinalOutcome.StatusCode == nil || *read.FinalOutcome.StatusCode != 404 || read.FinalOutcome.ErrorCode == nil || *read.FinalOutcome.ErrorCode != "SANDBOX_NOT_FOUND" || read.MutationWriteObserved {
		t.Fatalf("cross-tenant artifact interactions = %#v", crossTenant.Interactions)
	}
	var mtlsBinding protocol.ScenarioResult
	if err := json.Unmarshal(lines[30], &mtlsBinding); err != nil || mtlsBinding.CaseID != "initial.provider-mtls-caller-binding-rejection" || mtlsBinding.Sequence != 31 || len(mtlsBinding.Interactions) != 1 || len(mtlsBinding.Assertions) != 1 || len(mtlsBinding.ObservationIDs) != 3 || mtlsBinding.ReasonCode != nil {
		t.Fatalf("completed mTLS caller-binding result = %#v, %v", mtlsBinding, err)
	}
	if interaction := mtlsBinding.Interactions[0]; interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != 403 || interaction.FinalOutcome.ErrorCode == nil || *interaction.FinalOutcome.ErrorCode != "SANDBOX_FORBIDDEN" || interaction.MutationWriteObserved {
		t.Fatalf("mTLS caller-binding interaction = %#v", interaction)
	}
	stateDocument, err := os.ReadFile(filepath.Join(stateRoot, callerstate.StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	var state callerstate.State
	if err := json.Unmarshal(stateDocument, &state); err != nil || state.Stage != callerstate.StageInitialComplete || state.StoreRevision != 6 || state.Lifecycle == nil || state.Exec == nil || state.Terminal == nil || state.Artifact == nil {
		t.Fatalf("operational initial state = %#v, %v", state, err)
	}
	assertForbiddenCorrelationsAbsent(t, remainder, state)
	if entries, err := os.ReadDir(stateRoot); err != nil || len(entries) != 1 || entries[0].Name() != callerstate.StateFileName {
		t.Fatalf("operational initial root = %v, %#v", err, entries)
	}
	if counts, serverErrors := providerServer.Snapshot(); len(serverErrors) != 0 || counts != (testprovider.Counts{Capabilities: 2, UnadmittedCapabilityGets: 1, Creates: 1, ExactJTIReplays: 1, IdempotencyReplays: 1, Operations: 6, Statuses: 1, Execs: 2, StaleExecRejections: 1, CancelExecs: 1, ExecResults: 2, UsageReads: 1, Sessions: 1, Handoffs: 1, TerminalConnects: 3, ArtifactStages: 1, ArtifactEvidenceReads: 1, CrossTenantArtifactRejections: 1, CrossTenantOperationReadRejections: 1, WrongMTLSCallerRejections: 1}) {
		t.Fatalf("operational Provider composition = %#v / %v", counts, serverErrors)
	}
	retainedEvidence, ok := providerServer.SnapshotRetainedEvidence(state)
	if !ok {
		t.Fatal("initial synthetic Provider did not retain evidence")
	}
	runReconstructionAdapterProcess(t, executable, gatewayEndpoint, stateRoot, stateDocument, retainedEvidence)
}

func runReconstructionAdapterProcess(t *testing.T, executable, gatewayEndpoint, stateRoot string, stateBefore []byte, retainedEvidence testprovider.RetainedEvidence) {
	t.Helper()
	fixture := testcredentials.NewForGatewayHost(t, "127.0.0.1")
	providerServer := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
	providerServer.SetTerminalShell(true)
	var retainedState callerstate.State
	if err := json.Unmarshal(stateBefore, &retainedState); err != nil {
		t.Fatal(err)
	}
	if !providerServer.SeedRetainedEvidence(retainedState, retainedEvidence) {
		t.Fatal("failed to seed reconstructed synthetic Provider evidence")
	}
	requirements := credentials.Requirements()
	readers := make([]*os.File, 0, len(requirements))
	writers := make([]*os.File, 0, len(requirements))
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	for index, requirement := range requirements {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		readers, writers = append(readers, reader), append(writers, writer)
		descriptors = append(descriptors, protocol.ChannelDescriptor{ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor, MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable)
	command.Dir, command.Env, command.ExtraFiles = t.TempDir(), []string{}, readers
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
	startup, err := output.ReadBytes('\n')
	if err != nil || !bytes.Contains(startup, []byte(`"message_type":"startup_identity"`)) {
		t.Fatalf("reconstruction startup = %v / %q", err, startup)
	}
	invocation := protocol.Invocation{FormatVersion: protocol.FormatVersion, ProtocolID: protocol.ProtocolID, ProtocolVersion: protocol.ProtocolVersion, MessageType: "invocation", InvocationID: "process.reconstruction", Phase: "reconstruction", ProfilePath: "/qualification/profile.json", ProviderOrigin: providerServer.Origin(), GatewayProbeEndpoint: gatewayEndpoint, CredentialChannelDescriptors: descriptors, CallerStateRoot: stateRoot}
	document, err := json.Marshal(invocation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(document); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	for index, writer := range writers {
		if _, err := writer.Write(fixture.Payloads[requirements[index].ChannelID]); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
	}
	remainder, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil || ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatalf("reconstruction adapter exit = %v context=%v stderr=%q", err, ctx.Err(), stderr.Bytes())
	}
	assertForbiddenCorrelationsAbsent(t, remainder, retainedState)
	lines := bytes.Split(bytes.TrimSuffix(remainder, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 12 || !bytes.Contains(lines[0], []byte(`"message_type":"invocation_accepted"`)) || !bytes.Contains(lines[1], []byte(`"case_id":"reconstruction.locked-capability-discovery"`)) || !bytes.Contains(lines[2], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[3], []byte(`"case_id":"reconstruction.durable-lifecycle"`)) || !bytes.Contains(lines[4], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[5], []byte(`"case_id":"reconstruction.retained-exec-usage-and-artifact-evidence"`)) || !bytes.Contains(lines[6], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[7], []byte(`"case_id":"reconstruction.durable-opaque-handoff"`)) || !bytes.Contains(lines[8], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[9], []byte(`"case_id":"reconstruction.same-shell-reconnect"`)) || !bytes.Contains(lines[10], []byte(`"disposition":"completed"`)) || !bytes.Contains(lines[11], []byte(`"completion":"completed"`)) {
		t.Fatalf("reconstruction adapter output = %q", remainder)
	}
	var result protocol.ScenarioResult
	if err := json.Unmarshal(lines[2], &result); err != nil || result.CaseID != "reconstruction.locked-capability-discovery" || len(result.Interactions) != 1 || len(result.Assertions) != 2 || len(result.ObservationIDs) != 5 || result.ReasonCode != nil {
		t.Fatalf("reconstruction result = %#v / %v", result, err)
	}
	var lifecycle protocol.ScenarioResult
	if err := json.Unmarshal(lines[4], &lifecycle); err != nil || lifecycle.CaseID != "reconstruction.durable-lifecycle" || len(lifecycle.Interactions) != 2 || len(lifecycle.Assertions) != 1 || len(lifecycle.ObservationIDs) != 6 || lifecycle.ReasonCode != nil {
		t.Fatalf("reconstruction lifecycle result = %#v / %v", lifecycle, err)
	}
	for index, interactionID := range []string{"read-reconstructed-create-operation", "read-reconstructed-sandbox"} {
		interaction := lifecycle.Interactions[index]
		if interaction.InteractionID != interactionID || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != 200 || interaction.WireAttempts != 1 || interaction.MutationWriteObserved {
			t.Fatalf("reconstruction lifecycle interaction %d = %#v", index, interaction)
		}
	}
	var evidence protocol.ScenarioResult
	if err := json.Unmarshal(lines[6], &evidence); err != nil || evidence.CaseID != "reconstruction.retained-exec-usage-and-artifact-evidence" || len(evidence.Interactions) != 3 || len(evidence.Assertions) != 1 || len(evidence.ObservationIDs) != 3 || evidence.ReasonCode != nil {
		t.Fatalf("reconstruction evidence result = %#v / %v", evidence, err)
	}
	for index, interactionID := range []string{"read-retained-exec-result", "read-retained-usage", "read-retained-artifact-evidence"} {
		interaction := evidence.Interactions[index]
		if interaction.InteractionID != interactionID || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != 200 || interaction.WireAttempts != 1 || interaction.MutationWriteObserved {
			t.Fatalf("reconstruction evidence interaction %d = %#v", index, interaction)
		}
	}
	var handoff protocol.ScenarioResult
	if err := json.Unmarshal(lines[8], &handoff); err != nil || handoff.CaseID != "reconstruction.durable-opaque-handoff" || len(handoff.Interactions) != 1 || len(handoff.Assertions) != 1 || len(handoff.ObservationIDs) != 3 || handoff.ReasonCode != nil {
		t.Fatalf("reconstruction handoff result = %#v / %v", handoff, err)
	}
	if interaction := handoff.Interactions[0]; interaction.InteractionID != "read-retained-terminal-handoff" || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != 200 || interaction.WireAttempts != 1 || interaction.MutationWriteObserved {
		t.Fatalf("reconstruction handoff interaction = %#v", interaction)
	}
	var reconnect protocol.ScenarioResult
	if err := json.Unmarshal(lines[10], &reconnect); err != nil || reconnect.CaseID != "reconstruction.same-shell-reconnect" || len(reconnect.Interactions) != 1 || len(reconnect.Assertions) != 2 || len(reconnect.ObservationIDs) != 4 || reconnect.ReasonCode != nil {
		t.Fatalf("reconstruction reconnect result = %#v / %v", reconnect, err)
	}
	if interaction := reconnect.Interactions[0]; interaction.InteractionID != "gateway-same-shell-reconnect" || interaction.FinalOutcome.Transport != "authorized-byte-round-trip" || interaction.WireAttempts != 1 || interaction.MutationWriteObserved {
		t.Fatalf("reconstruction reconnect interaction = %#v", interaction)
	}
	stateAfter, err := os.ReadFile(filepath.Join(stateRoot, callerstate.StateFileName))
	if err != nil || !bytes.Equal(stateAfter, stateBefore) {
		t.Fatalf("reconstruction state changed = %v / %q", err, stateAfter)
	}
	if counts, serverErrors := providerServer.Snapshot(); len(serverErrors) != 0 || counts != (testprovider.Counts{Capabilities: 1, Operations: 1, Statuses: 1, ExecResults: 1, UsageReads: 1, Handoffs: 1, TerminalConnects: 1, ArtifactEvidenceReads: 1}) {
		t.Fatalf("reconstruction Provider composition = %#v / %v", counts, serverErrors)
	}
}

func assertForbiddenCorrelationsAbsent(t *testing.T, transcript []byte, state callerstate.State) {
	t.Helper()
	values := []string{
		state.Plan.RunID, state.Plan.TenantAID, state.Plan.TenantBID, state.Plan.WorkOrderAID, state.Plan.WorkOrderBID,
		state.Plan.WorkspaceID, state.Plan.BranchID, state.Plan.ProviderResolutionID, state.Plan.SandboxID,
		state.Plan.Create.OperationID, state.Plan.Create.AttemptID, state.Plan.Create.IdempotencyKey,
		state.Plan.Exec.OperationID, state.Plan.Exec.AttemptID, state.Plan.Exec.IdempotencyKey,
		state.Plan.Terminal.OperationID, state.Plan.Terminal.AttemptID, state.Plan.Terminal.IdempotencyKey,
		state.Plan.Artifact.OperationID, state.Plan.Artifact.AttemptID, state.Plan.Artifact.IdempotencyKey,
	}
	if state.Terminal != nil {
		values = append(values, state.Terminal.RuntimeSessionID, state.Terminal.HandoffReference)
	}
	for _, value := range values {
		if value != "" && bytes.Contains(transcript, []byte(value)) {
			t.Fatalf("adapter transcript contains forbidden caller correlation %q", value)
		}
	}
}
