//go:build darwin || linux

package callerprovider_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerprovider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testprovider"
)

func TestLiveMTLSInitialThroughExecUsageAndTerminalHandoff(t *testing.T) {
	fixture := testcredentials.NewForGatewayHost(t, "127.0.0.1")
	server := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
	bundle := readBundle(t, fixture.Payloads)
	defer bundle.Destroy()
	store, err := callerstate.CreateInitial(privateRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	terminal, err := callerprovider.Run(ctx, "initial", server.Origin(), bundle, store)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	deadline, _ := ctx.Deadline()
	if terminal == nil || !terminal.ExpiresAt.Equal(deadline) {
		t.Fatal("fresh authority did not preserve the actual handoff expiry")
	}
	state := store.Snapshot()
	if state.Stage != callerstate.StageTerminalBound || state.StoreRevision != 5 || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.Terminal == nil {
		t.Fatalf("live Provider state = %#v", state)
	}
	counts, serverErrors := server.Snapshot()
	if len(serverErrors) != 0 || counts != (testprovider.Counts{Capabilities: 2, Creates: 1, Operations: 3, Statuses: 1, Execs: 1, ExecResults: 1, UsageReads: 1, Sessions: 1, Handoffs: 1}) {
		t.Fatalf("live Provider counts/errors = %#v / %v", counts, serverErrors)
	}
}

func TestLiveMTLSLockedCapabilityScenarioOnly(t *testing.T) {
	fixture := testcredentials.NewForGatewayHost(t, "127.0.0.1")
	server := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
	server.SetCapabilityTransients("controller_a", 1)
	bundle := readBundle(t, fixture.Payloads)
	defer bundle.Destroy()
	store, err := callerstate.CreateInitial(privateRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := callerprovider.RunCapabilityDiscoveryScenario(ctx, server.Origin(), bundle, store)
	if err != nil {
		counts, serverErrors := server.Snapshot()
		t.Fatalf("%v; state=%#v counts=%#v server=%v", err, store.Snapshot(), counts, serverErrors)
	}
	if result.CaseID != "initial.locked-capability-discovery" || result.Disposition != "completed" || len(result.Interactions) != 3 || len(result.Assertions) != 3 || len(result.ObservationIDs) != 9 {
		t.Fatalf("capability scenario result = %#v", result)
	}
	if got, want := []string{result.Interactions[0].InteractionID, result.Interactions[1].InteractionID, result.Interactions[2].InteractionID}, []string{"controller-a-capabilities", "controller-b-capabilities", "same-ca-unadmitted-capabilities"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capability interaction order = %v, want %v", got, want)
	}
	if got, want := result.Assertions, []protocol.AssertionResult{
		{AssertionID: "caller-consumed-embedded-contract-identity", Result: "asserted"},
		{AssertionID: "caller-consumed-embedded-profile-identity", Result: "asserted"},
		{AssertionID: "harness-expectations-not-used-as-caller-attestation", Result: "asserted"},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capability assertions = %#v, want %#v", got, want)
	}
	if got, want := result.ObservationIDs, []string{
		"schema-valid-capability-document", "exact-provider-revision", "exact-atomic-coding-shell-profile", "caller-and-adapter-startup-identities-observed",
		"distinct-controller-identity", "distinct-tenant-binding", "byte-identical-capability-snapshot",
		"same-ca-distinct-uri-san", "no-capability-document-returned",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capability observations = %v, want %v", got, want)
	}
	if result.Interactions[0].WireAttempts != 2 || len(result.Interactions[0].TransientOutcomes) != 1 || result.Interactions[0].TransientOutcomes[0].Transport != "http-response" || result.Interactions[0].TransientOutcomes[0].StatusCode == nil || *result.Interactions[0].TransientOutcomes[0].StatusCode != 503 || !result.Interactions[0].TransientOutcomes[0].Retryable {
		t.Fatalf("capability retry evidence = %#v", result.Interactions[0])
	}
	state := store.Snapshot()
	if state.Stage != callerstate.StageCapabilitiesBound || state.StoreRevision != 2 || state.Provider == nil || state.Lifecycle != nil || state.Exec != nil || state.Terminal != nil {
		t.Fatalf("capability-only state = %#v", state)
	}
	counts, serverErrors := server.Snapshot()
	if len(serverErrors) != 0 || counts != (testprovider.Counts{Capabilities: 2, UnadmittedCapabilityGets: 1, CapabilityTransients: 1}) {
		t.Fatalf("capability-only Provider calls = %#v / %v", counts, serverErrors)
	}
}

func TestLiveMTLSLockedCapabilityScenarioCancellationPreservesPlannedState(t *testing.T) {
	fixture := testcredentials.NewForGatewayHost(t, "127.0.0.1")
	server := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
	server.SetCapabilityTransients("controller_a", 64)
	bundle := readBundle(t, fixture.Payloads)
	defer bundle.Destroy()
	store, err := callerstate.CreateInitial(privateRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := callerprovider.RunCapabilityDiscoveryScenario(ctx, server.Origin(), bundle, store); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled capability scenario error = %v", err)
	}
	state := store.Snapshot()
	if state.Stage != callerstate.StagePlanned || state.StoreRevision != 1 || state.Provider != nil {
		t.Fatalf("cancelled capability state = %#v", state)
	}
	counts, serverErrors := server.Snapshot()
	if len(serverErrors) != 0 || counts.CapabilityTransients < 1 || counts.Capabilities != 0 || counts.UnadmittedCapabilityGets != 0 || counts.Creates != 0 {
		t.Fatalf("cancelled capability calls = %#v / %v", counts, serverErrors)
	}
}

func TestLiveMTLSLockedCapabilityThroughTerminalHandoff(t *testing.T) {
	fixture := testcredentials.NewForGatewayHost(t, "127.0.0.1")
	server := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
	server.SetCreateTransients(1)
	bundle := readBundle(t, fixture.Payloads)
	defer bundle.Destroy()
	store, err := callerstate.CreateInitial(privateRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	executor, err := callerprovider.NewInitialScenarioExecutor(server.Origin(), bundle, store)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close()
	firstCtx, firstCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer firstCancel()
	if _, err := executor.Execute(firstCtx, "initial.locked-capability-discovery"); err != nil {
		t.Fatal(err)
	}
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer secondCancel()
	result, err := executor.Execute(secondCtx, "initial.protected-lifecycle-create")
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != "initial.protected-lifecycle-create" || result.Disposition != "completed" || len(result.Interactions) != 1 || len(result.Assertions) != 3 || len(result.ObservationIDs) != 5 {
		t.Fatalf("protected create result = %#v", result)
	}
	interaction := result.Interactions[0]
	if interaction.WireAttempts != 2 || len(interaction.TransientOutcomes) != 1 || interaction.TransientOutcomes[0].StatusCode == nil || *interaction.TransientOutcomes[0].StatusCode != 503 || !interaction.TransientOutcomes[0].Retryable || !interaction.TransientOutcomes[0].RetryAfterPresent || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != 202 || !interaction.MutationWriteObserved {
		t.Fatalf("protected create interaction = %#v", interaction)
	}
	thirdCtx, thirdCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer thirdCancel()
	replay, err := executor.Execute(thirdCtx, "initial.replay-semantics")
	if err != nil {
		t.Fatal(err)
	}
	if replay.CaseID != "initial.replay-semantics" || replay.Disposition != "completed" || len(replay.Interactions) != 2 || len(replay.Assertions) != 2 || len(replay.ObservationIDs) != 6 || replay.Interactions[0].FinalOutcome.StatusCode == nil || *replay.Interactions[0].FinalOutcome.StatusCode != 409 || replay.Interactions[1].FinalOutcome.StatusCode == nil || *replay.Interactions[1].FinalOutcome.StatusCode != 202 {
		t.Fatalf("replay semantics result = %#v", replay)
	}
	fourthCtx, fourthCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fourthCancel()
	lifecycle, err := executor.Execute(fourthCtx, "initial.lifecycle-completion-and-status")
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle.CaseID != "initial.lifecycle-completion-and-status" || lifecycle.Disposition != "completed" || len(lifecycle.Interactions) != 2 || len(lifecycle.Assertions) != 1 || len(lifecycle.ObservationIDs) != 4 || lifecycle.Interactions[0].FinalOutcome.StatusCode == nil || *lifecycle.Interactions[0].FinalOutcome.StatusCode != 200 || lifecycle.Interactions[1].FinalOutcome.StatusCode == nil || *lifecycle.Interactions[1].FinalOutcome.StatusCode != 200 {
		t.Fatalf("lifecycle completion result = %#v", lifecycle)
	}
	fifthCtx, fifthCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fifthCancel()
	execEvidence, err := executor.Execute(fifthCtx, "initial.exec-result-and-usage-evidence")
	if err != nil {
		t.Fatal(err)
	}
	if execEvidence.CaseID != "initial.exec-result-and-usage-evidence" || execEvidence.Disposition != "completed" || len(execEvidence.Interactions) != 4 || len(execEvidence.Assertions) != 2 || len(execEvidence.ObservationIDs) != 7 || execEvidence.Interactions[0].FinalOutcome.StatusCode == nil || *execEvidence.Interactions[0].FinalOutcome.StatusCode != 202 {
		t.Fatalf("exec result/usage evidence = %#v", execEvidence)
	}
	state := store.Snapshot()
	if state.Stage != callerstate.StageExecBound || state.StoreRevision != 4 || state.Provider == nil || state.Lifecycle == nil || state.Exec == nil || state.Lifecycle.OperationID != state.Plan.Create.OperationID || state.Exec.Operation.OperationID != state.Plan.Exec.OperationID {
		t.Fatalf("exec evidence state = %#v", state)
	}
	sixthCtx, sixthCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sixthCancel()
	stale, err := executor.Execute(sixthCtx, "initial.stale-fencing-rejection")
	if err != nil {
		t.Fatal(err)
	}
	if stale.CaseID != "initial.stale-fencing-rejection" || stale.Disposition != "completed" || len(stale.Interactions) != 1 || len(stale.Assertions) != 1 || len(stale.ObservationIDs) != 3 || stale.Interactions[0].WireAttempts != 1 || stale.Interactions[0].FinalOutcome.StatusCode == nil || *stale.Interactions[0].FinalOutcome.StatusCode != 409 || stale.Interactions[0].FinalOutcome.ErrorCode == nil || *stale.Interactions[0].FinalOutcome.ErrorCode != "SANDBOX_STALE_FENCING_TOKEN" || stale.Interactions[0].FinalOutcome.Retryable || stale.Interactions[0].FinalOutcome.RetryAfterPresent {
		t.Fatalf("stale fencing result = %#v", stale)
	}
	if after := store.Snapshot(); !reflect.DeepEqual(after, state) {
		t.Fatalf("stale fencing changed exec-bound state = before %#v / after %#v", state, after)
	}
	seventhCtx, seventhCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer seventhCancel()
	cancellation, err := executor.Execute(seventhCtx, "initial.exec-cancellation")
	if err != nil {
		t.Fatal(err)
	}
	if cancellation.CaseID != "initial.exec-cancellation" || cancellation.Disposition != "completed" || len(cancellation.Interactions) != 5 || len(cancellation.Assertions) != 2 || len(cancellation.ObservationIDs) != 5 {
		t.Fatalf("exec cancellation result = %#v", cancellation)
	}
	for index, status := range []int{202, 202, 200, 200, 200} {
		interaction := cancellation.Interactions[index]
		if interaction.WireAttempts != 1 || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != status || interaction.MutationWriteObserved != (index < 2) {
			t.Fatalf("exec cancellation interaction %d = %#v", index, interaction)
		}
	}
	if after := store.Snapshot(); !reflect.DeepEqual(after, state) {
		t.Fatalf("exec cancellation changed exec-bound state = before %#v / after %#v", state, after)
	}
	eighthCtx, eighthCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer eighthCancel()
	terminal, err := executor.Execute(eighthCtx, "initial.terminal-session-and-opaque-handoff")
	if err != nil {
		t.Fatal(err)
	}
	if terminal.CaseID != "initial.terminal-session-and-opaque-handoff" || terminal.Disposition != "completed" || len(terminal.Interactions) != 3 || len(terminal.Assertions) != 1 || len(terminal.ObservationIDs) != 5 {
		t.Fatalf("terminal handoff result = %#v", terminal)
	}
	for index, status := range []int{202, 200, 200} {
		interaction := terminal.Interactions[index]
		if interaction.WireAttempts != 1 || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != status || interaction.MutationWriteObserved != (index == 0) {
			t.Fatalf("terminal handoff interaction %d = %#v", index, interaction)
		}
	}
	afterTerminal := store.Snapshot()
	if afterTerminal.Stage != callerstate.StageTerminalBound || afterTerminal.StoreRevision != 5 || afterTerminal.Terminal == nil || afterTerminal.Terminal.Operation.FencingToken != 5 || afterTerminal.Terminal.RuntimeSessionID == "" || afterTerminal.Terminal.HandoffReference == "" {
		t.Fatalf("terminal-bound state = %#v", afterTerminal)
	}
	counts, serverErrors := server.Snapshot()
	if len(serverErrors) != 0 || counts != (testprovider.Counts{Capabilities: 2, UnadmittedCapabilityGets: 1, Creates: 1, CreateTransients: 1, ExactJTIReplays: 1, IdempotencyReplays: 1, Operations: 5, Statuses: 1, Execs: 2, StaleExecRejections: 1, CancelExecs: 1, ExecResults: 2, UsageReads: 1, Sessions: 1, Handoffs: 1}) {
		t.Fatalf("protected create Provider calls = %#v / %v", counts, serverErrors)
	}
}

func readBundle(t *testing.T, payloads map[string][]byte) *credentials.Bundle {
	t.Helper()
	requirements := credentials.Requirements()
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	writers := make([]*os.File, 0, len(requirements))
	for _, requirement := range requirements {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		fd, err := syscall.Dup(int(reader.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		writers = append(writers, writer)
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: fd,
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

func privateRoot(t *testing.T) string {
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
