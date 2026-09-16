//go:build darwin || linux

package callerprocess

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	executable := buildCallerExecutable(t)
	endpoint := localGatewayEndpoint(t)
	fixture := testcredentials.NewForGatewayHost(t, "127.0.0.1")
	providerServer := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
	bundle := testBundle(t, fixture.Payloads)
	defer bundle.Destroy()
	root := newCallerStateRoot(t)
	runner := NewRunner(executable)
	observed := 0
	runner.observePID = func(pid int) { observed = pid }
	invocation := testRunnerInvocation("initial", endpoint, root)
	invocation.ProviderOrigin = providerServer.Origin()
	result, err := runner.Start(context.Background(), invocation, "initial.locked-capability-discovery", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if result.CaseID != "initial.locked-capability-discovery" || result.Disposition != "completed" || len(result.Interactions) != 3 {
		t.Fatalf("scenario result = %#v", result)
	}
	if observed < 1 || observed == os.Getpid() {
		t.Fatalf("observed external caller PID = %d, test PID = %d", observed, os.Getpid())
	}
	process, _ := os.FindProcess(observed)
	if process == nil || process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive between scenarios")
	}
	if _, err := runner.Start(context.Background(), invocation, "initial.locked-capability-discovery", bundle); !errors.Is(err, ErrProcessState) {
		t.Fatalf("second start while Caller is active = %v", err)
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("rejected second start terminated the active Caller")
	}
	second, err := runner.Run(context.Background(), "initial.protected-lifecycle-create")
	if err != nil {
		t.Fatal(err)
	}
	if second.CaseID != "initial.protected-lifecycle-create" || second.Disposition != "completed" || len(second.Interactions) != 1 || !second.Interactions[0].MutationWriteObserved {
		t.Fatalf("create scenario result = %#v", second)
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for replay semantics")
	}
	third, err := runner.Run(context.Background(), "initial.replay-semantics")
	if err != nil {
		t.Fatal(err)
	}
	if third.CaseID != "initial.replay-semantics" || third.Disposition != "completed" || len(third.Interactions) != 2 || third.Interactions[0].FinalOutcome.StatusCode == nil || *third.Interactions[0].FinalOutcome.StatusCode != 409 || third.Interactions[1].FinalOutcome.StatusCode == nil || *third.Interactions[1].FinalOutcome.StatusCode != 202 {
		t.Fatalf("replay scenario result = %#v", third)
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for lifecycle completion")
	}
	fourth, err := runner.Run(context.Background(), "initial.lifecycle-completion-and-status")
	if err != nil {
		t.Fatal(err)
	}
	if fourth.CaseID != "initial.lifecycle-completion-and-status" || fourth.Disposition != "completed" || len(fourth.Interactions) != 2 || fourth.Interactions[0].FinalOutcome.StatusCode == nil || *fourth.Interactions[0].FinalOutcome.StatusCode != 200 || fourth.Interactions[1].FinalOutcome.StatusCode == nil || *fourth.Interactions[1].FinalOutcome.StatusCode != 200 {
		t.Fatalf("lifecycle completion result = %#v", fourth)
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for exec result/usage evidence")
	}
	fifth, err := runner.Run(context.Background(), "initial.exec-result-and-usage-evidence")
	if err != nil {
		t.Fatal(err)
	}
	if fifth.CaseID != "initial.exec-result-and-usage-evidence" || fifth.Disposition != "completed" || len(fifth.Interactions) != 4 || fifth.Interactions[0].FinalOutcome.StatusCode == nil || *fifth.Interactions[0].FinalOutcome.StatusCode != 202 || fifth.Interactions[1].FinalOutcome.StatusCode == nil || *fifth.Interactions[1].FinalOutcome.StatusCode != 200 || fifth.Interactions[2].FinalOutcome.StatusCode == nil || *fifth.Interactions[2].FinalOutcome.StatusCode != 200 || fifth.Interactions[3].FinalOutcome.StatusCode == nil || *fifth.Interactions[3].FinalOutcome.StatusCode != 200 {
		t.Fatalf("exec result/usage result = %#v", fifth)
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for stale-fencing rejection")
	}
	sixth, err := runner.Run(context.Background(), "initial.stale-fencing-rejection")
	if err != nil {
		t.Fatal(err)
	}
	if sixth.CaseID != "initial.stale-fencing-rejection" || sixth.Disposition != "completed" || len(sixth.Interactions) != 1 || sixth.Interactions[0].FinalOutcome.StatusCode == nil || *sixth.Interactions[0].FinalOutcome.StatusCode != 409 || sixth.Interactions[0].FinalOutcome.ErrorCode == nil || *sixth.Interactions[0].FinalOutcome.ErrorCode != "SANDBOX_STALE_FENCING_TOKEN" {
		t.Fatalf("stale-fencing result = %#v", sixth)
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for exec cancellation")
	}
	seventh, err := runner.Run(context.Background(), "initial.exec-cancellation")
	if err != nil {
		t.Fatal(err)
	}
	if seventh.CaseID != "initial.exec-cancellation" || seventh.Disposition != "completed" || len(seventh.Interactions) != 5 {
		t.Fatalf("exec cancellation result = %#v", seventh)
	}
	for index, status := range []int{202, 202, 200, 200, 200} {
		if seventh.Interactions[index].FinalOutcome.StatusCode == nil || *seventh.Interactions[index].FinalOutcome.StatusCode != status {
			t.Fatalf("exec cancellation interaction %d = %#v", index, seventh.Interactions[index])
		}
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for terminal handoff")
	}
	eighth, err := runner.Run(context.Background(), "initial.terminal-session-and-opaque-handoff")
	if err != nil {
		t.Fatal(err)
	}
	if eighth.CaseID != "initial.terminal-session-and-opaque-handoff" || eighth.Disposition != "completed" || len(eighth.Interactions) != 3 {
		t.Fatalf("terminal handoff result = %#v", eighth)
	}
	for index, status := range []int{202, 200, 200} {
		if eighth.Interactions[index].FinalOutcome.StatusCode == nil || *eighth.Interactions[index].FinalOutcome.StatusCode != status {
			t.Fatalf("terminal handoff interaction %d = %#v", index, eighth.Interactions[index])
		}
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for Gateway terminal round-trip")
	}
	ninth, err := runner.Run(context.Background(), "initial.gateway-terminal-byte-round-trip")
	if err != nil {
		t.Fatal(err)
	}
	if ninth.CaseID != "initial.gateway-terminal-byte-round-trip" || ninth.Disposition != "completed" || len(ninth.Interactions) != 1 || ninth.Interactions[0].FinalOutcome.Transport != "authorized-byte-round-trip" || ninth.Interactions[0].WireAttempts != 1 {
		t.Fatalf("Gateway terminal round-trip result = %#v", ninth)
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for Gateway authority rejection")
	}
	tenth, err := runner.Run(context.Background(), "initial.gateway-wrong-caller-and-cross-tenant-rejection")
	if err != nil {
		t.Fatal(err)
	}
	if tenth.CaseID != "initial.gateway-wrong-caller-and-cross-tenant-rejection" || tenth.Disposition != "completed" || len(tenth.Interactions) != 2 {
		t.Fatalf("Gateway authority rejection result = %#v", tenth)
	}
	for index, interaction := range tenth.Interactions {
		if interaction.FinalOutcome.Transport != "gateway-upgrade-rejected" || interaction.WireAttempts != 1 {
			t.Fatalf("Gateway authority rejection interaction %d = %#v", index, interaction)
		}
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for Gateway grant expiry")
	}
	eleventh, err := runner.Run(context.Background(), "initial.gateway-grant-expiry")
	if err != nil {
		t.Fatal(err)
	}
	if eleventh.CaseID != "initial.gateway-grant-expiry" || eleventh.Disposition != "completed" || len(eleventh.Interactions) != 1 || eleventh.Interactions[0].FinalOutcome.Transport != "gateway-closed-at-grant-expiry" || eleventh.Interactions[0].WireAttempts != 1 {
		t.Fatalf("Gateway grant-expiry result = %#v", eleventh)
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for Gateway revocation")
	}
	twelfth, err := runner.Run(context.Background(), "initial.gateway-revocation")
	if err != nil {
		t.Fatal(err)
	}
	if twelfth.CaseID != "initial.gateway-revocation" || twelfth.Disposition != "completed" || len(twelfth.Interactions) != 2 || twelfth.Interactions[0].FinalOutcome.Transport != "authorized-byte-round-trip" || twelfth.Interactions[1].FinalOutcome.Transport != "revocation-acknowledged" || !twelfth.Interactions[1].MutationWriteObserved {
		t.Fatalf("Gateway revocation result = %#v", twelfth)
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for artifact staging")
	}
	thirteenth, err := runner.Run(context.Background(), "initial.artifact-staging-and-evidence")
	if err != nil {
		t.Fatal(err)
	}
	if thirteenth.CaseID != "initial.artifact-staging-and-evidence" || thirteenth.Disposition != "completed" || len(thirteenth.Interactions) != 3 {
		t.Fatalf("artifact staging result = %#v", thirteenth)
	}
	for index, status := range []int{202, 200, 200} {
		if thirteenth.Interactions[index].FinalOutcome.StatusCode == nil || *thirteenth.Interactions[index].FinalOutcome.StatusCode != status {
			t.Fatalf("artifact interaction %d = %#v", index, thirteenth.Interactions[index])
		}
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for cross-tenant artifact rejection")
	}
	fourteenth, err := runner.Run(context.Background(), "initial.provider-cross-tenant-artifact-rejection")
	if err != nil {
		t.Fatal(err)
	}
	if fourteenth.CaseID != "initial.provider-cross-tenant-artifact-rejection" || fourteenth.Disposition != "completed" || len(fourteenth.Interactions) != 2 {
		t.Fatalf("cross-tenant artifact result = %#v", fourteenth)
	}
	for index, status := range []int{403, 404} {
		if fourteenth.Interactions[index].FinalOutcome.StatusCode == nil || *fourteenth.Interactions[index].FinalOutcome.StatusCode != status {
			t.Fatalf("cross-tenant interaction %d = %#v", index, fourteenth.Interactions[index])
		}
	}
	if process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("external caller did not remain alive for mTLS caller-binding rejection")
	}
	fifteenth, err := runner.Run(context.Background(), "initial.provider-mtls-caller-binding-rejection")
	if err != nil {
		t.Fatal(err)
	}
	if fifteenth.CaseID != "initial.provider-mtls-caller-binding-rejection" || fifteenth.Disposition != "completed" || len(fifteenth.Interactions) != 1 || fifteenth.Interactions[0].FinalOutcome.StatusCode == nil || *fifteenth.Interactions[0].FinalOutcome.StatusCode != 403 || fifteenth.Interactions[0].FinalOutcome.ErrorCode == nil || *fifteenth.Interactions[0].FinalOutcome.ErrorCode != "SANDBOX_FORBIDDEN" {
		t.Fatalf("mTLS caller-binding result = %#v", fifteenth)
	}
	assertReaped(t, observed)
	after, err := os.ReadFile(filepath.Join(root, callerstate.StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(after, []byte(`"stage":"initial_complete"`)) {
		t.Fatalf("initial phase state = %q", after)
	}
	counts, serverErrors := providerServer.Snapshot()
	wantCounts := testprovider.Counts{Capabilities: 2, UnadmittedCapabilityGets: 1, Creates: 1, ExactJTIReplays: 1, IdempotencyReplays: 1, Operations: 6, Statuses: 1, Execs: 2, StaleExecRejections: 1, CancelExecs: 1, ExecResults: 2, UsageReads: 1, Sessions: 1, Handoffs: 1, TerminalConnects: 3, ArtifactStages: 1, ArtifactEvidenceReads: 1, CrossTenantArtifactRejections: 1, CrossTenantOperationReadRejections: 1, WrongMTLSCallerRejections: 1}
	if len(serverErrors) != 0 || counts != wantCounts {
		t.Fatalf("Provider scenario composition = %#v / %v", counts, serverErrors)
	}
	reconstructedProvider := testprovider.New(t, fixture.ProviderCA, fixture.ProviderServerCertificate(t, "127.0.0.1"), fixture.ProviderAdmissionPublicKeys)
	var retainedState callerstate.State
	if err := json.Unmarshal(after, &retainedState); err != nil {
		t.Fatal(err)
	}
	retainedEvidence, ok := providerServer.SnapshotRetainedEvidence(retainedState)
	if !ok || !reconstructedProvider.SeedRetainedEvidence(retainedState, retainedEvidence) {
		t.Fatal("failed to transfer synthetic Provider retained evidence")
	}
	reconstructionRunner := NewRunner(executable)
	reconstructedPID := 0
	reconstructionRunner.observePID = func(pid int) { reconstructedPID = pid }
	reconstructionInvocation := testRunnerInvocation("reconstruction", endpoint, root)
	reconstructionInvocation.ProviderOrigin = reconstructedProvider.Origin()
	reconstructed, err := reconstructionRunner.Start(context.Background(), reconstructionInvocation, "reconstruction.locked-capability-discovery", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if reconstructedPID < 1 || reconstructedPID == observed || reconstructed.CaseID != "reconstruction.locked-capability-discovery" || reconstructed.Disposition != "completed" || len(reconstructed.Interactions) != 1 || reconstructed.Interactions[0].FinalOutcome.StatusCode == nil || *reconstructed.Interactions[0].FinalOutcome.StatusCode != 200 {
		t.Fatalf("reconstruction capability/PID = %#v / %d", reconstructed, reconstructedPID)
	}
	reconstructedProcess, _ := os.FindProcess(reconstructedPID)
	if reconstructedProcess == nil || reconstructedProcess.Signal(syscall.Signal(0)) != nil {
		t.Fatal("reconstruction Caller did not remain alive for durable lifecycle")
	}
	reconstructedLifecycle, err := reconstructionRunner.Run(context.Background(), "reconstruction.durable-lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	if reconstructedLifecycle.CaseID != "reconstruction.durable-lifecycle" || reconstructedLifecycle.Disposition != "completed" || len(reconstructedLifecycle.Interactions) != 2 {
		t.Fatalf("reconstruction lifecycle result = %#v", reconstructedLifecycle)
	}
	for index, interactionID := range []string{"read-reconstructed-create-operation", "read-reconstructed-sandbox"} {
		interaction := reconstructedLifecycle.Interactions[index]
		if interaction.InteractionID != interactionID || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != 200 || interaction.WireAttempts != 1 || interaction.MutationWriteObserved {
			t.Fatalf("reconstruction lifecycle interaction %d = %#v", index, interaction)
		}
	}
	if reconstructedProcess.Signal(syscall.Signal(0)) != nil {
		t.Fatal("reconstruction Caller did not remain alive for retained evidence")
	}
	reconstructedEvidence, err := reconstructionRunner.Run(context.Background(), "reconstruction.retained-exec-usage-and-artifact-evidence")
	if err != nil {
		t.Fatal(err)
	}
	if reconstructedEvidence.CaseID != "reconstruction.retained-exec-usage-and-artifact-evidence" || reconstructedEvidence.Disposition != "completed" || len(reconstructedEvidence.Interactions) != 3 {
		t.Fatalf("reconstruction evidence result = %#v", reconstructedEvidence)
	}
	for index, interactionID := range []string{"read-retained-exec-result", "read-retained-usage", "read-retained-artifact-evidence"} {
		interaction := reconstructedEvidence.Interactions[index]
		if interaction.InteractionID != interactionID || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != 200 || interaction.WireAttempts != 1 || interaction.MutationWriteObserved {
			t.Fatalf("reconstruction evidence interaction %d = %#v", index, interaction)
		}
	}
	if reconstructedProcess.Signal(syscall.Signal(0)) != nil {
		t.Fatal("reconstruction Caller did not remain alive for retained handoff")
	}
	reconstructedHandoff, err := reconstructionRunner.Run(context.Background(), "reconstruction.durable-opaque-handoff")
	if err != nil {
		t.Fatal(err)
	}
	if reconstructedHandoff.CaseID != "reconstruction.durable-opaque-handoff" || reconstructedHandoff.Disposition != "completed" || len(reconstructedHandoff.Interactions) != 1 || reconstructedHandoff.Interactions[0].FinalOutcome.StatusCode == nil || *reconstructedHandoff.Interactions[0].FinalOutcome.StatusCode != 200 {
		t.Fatalf("reconstruction handoff result = %#v", reconstructedHandoff)
	}
	if reconstructedProcess.Signal(syscall.Signal(0)) != nil {
		t.Fatal("reconstruction Caller did not remain alive for same-shell reconnect")
	}
	reconstructedReconnect, err := reconstructionRunner.Run(context.Background(), "reconstruction.same-shell-reconnect")
	if err != nil {
		t.Fatal(err)
	}
	if reconstructedReconnect.CaseID != "reconstruction.same-shell-reconnect" || reconstructedReconnect.Disposition != "completed" || len(reconstructedReconnect.Interactions) != 1 || reconstructedReconnect.Interactions[0].FinalOutcome.Transport != "authorized-byte-round-trip" {
		t.Fatalf("reconstruction reconnect result = %#v", reconstructedReconnect)
	}
	assertReaped(t, reconstructedPID)
	reconstructedState, err := os.ReadFile(filepath.Join(root, callerstate.StateFileName))
	if err != nil || !bytes.Equal(reconstructedState, after) {
		t.Fatalf("reconstruction changed caller state = %v / %q", err, reconstructedState)
	}
	if reconstructedCounts, reconstructedErrors := reconstructedProvider.Snapshot(); len(reconstructedErrors) != 0 || reconstructedCounts != (testprovider.Counts{Capabilities: 1, Operations: 1, Statuses: 1, ExecResults: 1, UsageReads: 1, Handoffs: 1, TerminalConnects: 1, ArtifactEvidenceReads: 1}) {
		t.Fatalf("reconstructed Provider composition = %#v / %v", reconstructedCounts, reconstructedErrors)
	}
}

func buildCallerExecutable(t *testing.T) string {
	t.Helper()
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	directory := t.TempDir()
	caller := filepath.Join(directory, "external-caller")
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", caller, "./cmd/external-caller")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build external caller: %v: %s", err, output)
	}
	gateway := filepath.Join(directory, "caller-gateway")
	command = exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", gateway, "./cmd/caller-gateway")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build caller Gateway: %v: %s", err, output)
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
	_, err := runner.Start(context.Background(), testRunnerInvocation("initial", "https://gateway.example/tunnel", newCallerStateRoot(t)), "initial.locked-capability-discovery", bundle)
	if !errors.Is(err, ErrProcessTimeout) {
		t.Fatalf("Runner.Start(hang) error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("bounded termination took %s", elapsed)
	}
	if observed < 1 {
		t.Fatal("hanging process PID was not observed")
	}
	assertReaped(t, observed)
}

func TestSessionFinishIsBoundedAndKillsStragglingProcessGroup(t *testing.T) {
	executable := buildExecutable(t, "./internal/callerprocess/testdata/straggler", "straggler")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable)
	command.Args = []string{executable}
	command.Env = []string{}
	configureProcessGroup(command)
	command.WaitDelay = processWaitDelay
	command.Cancel = func() error { return terminateProcessGroup(command.Process) }
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	pid := command.Process.Pid
	stderrResult := make(chan drainResult, 1)
	go func() { stderrResult <- drainBounded(stderr, maxStderrBytes) }()
	session := &Session{command: command, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: stderrResult, ctx: ctx, cancel: cancel}
	started := time.Now()
	err = session.finish()
	if time.Since(started) > processReapLimit+time.Second {
		t.Fatalf("straggler cleanup exceeded bound: %s", time.Since(started))
	}
	if err != nil && !errors.Is(err, ErrProcessIO) && !errors.Is(err, ErrProcessExit) {
		t.Fatalf("straggler cleanup error = %v", err)
	}
	assertProcessGroupGone(t, pid)
}

func TestSessionCloseReapsStragglingProcessGroup(t *testing.T) {
	executable := buildExecutable(t, "./internal/callerprocess/testdata/straggler", "straggler")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable)
	command.Args = []string{executable}
	command.Env = []string{}
	configureProcessGroup(command)
	command.WaitDelay = processWaitDelay
	command.Cancel = func() error { return terminateProcessGroup(command.Process) }
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	stderrResult := make(chan drainResult, 1)
	go func() { stderrResult <- drainBounded(stderr, maxStderrBytes) }()
	session := &Session{command: command, stdin: stdin, stdout: reader, stderr: stderrResult, ctx: ctx, cancel: cancel}
	pid := command.Process.Pid
	started := time.Now()
	if err := session.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if elapsed := time.Since(started); elapsed > processReapLimit+time.Second {
		t.Fatalf("Close took %v", elapsed)
	}
	assertProcessGroupGone(t, pid)
}

func TestRunnerFailureCodeIsClosedAndSanitized(t *testing.T) {
	runner := NewRunner("/not/used")
	for _, test := range []struct {
		err  error
		want string
	}{
		{err: ErrExecutable, want: "caller_start_failed"},
		{err: ErrProcessStart, want: "caller_start_failed"},
		{err: ErrProcessCleanup, want: "internal_failure"},
		{err: ErrProcessTimeout, want: "scenario_execution_failed"},
		{err: errors.New("private detail"), want: "scenario_execution_failed"},
	} {
		if got := runner.FailureCode(test.err); got != test.want {
			t.Fatalf("FailureCode(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}

func assertProcessGroupGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		err := syscall.Kill(-pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process group %d remains: %v", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
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
	if _, err := runner.Start(context.Background(), testRunnerInvocation("initial", "https://gateway.example/tunnel", newCallerStateRoot(t)), "initial.locked-capability-discovery", bundle); !errors.Is(err, ErrExecutable) {
		t.Fatalf("Runner.Start(symlink) error = %v", err)
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
