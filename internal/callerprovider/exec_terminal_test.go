//go:build darwin || linux

package callerprovider

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

func (client *fakeClient) recordStep(step string, admission provider.Admission) error {
	client.admissions = append(client.admissions, admission)
	if client.hook != nil {
		return client.hook(step)
	}
	return nil
}

func (client *fakeClient) CreateExec(_ context.Context, sandbox string, request provider.ExecRequest, admission provider.Admission) (provider.ProviderOperation, error) {
	client.execs = append(client.execs, request)
	if err := client.recordStep("exec", admission); err != nil {
		return provider.ProviderOperation{}, err
	}
	if client.execHook != nil {
		if err := client.execHook(len(client.execs), request, admission); err != nil {
			return provider.ProviderOperation{}, err
		}
	}
	return provider.ProviderOperation{OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken, SandboxID: sandbox, Type: "exec", Status: "accepted"}, nil
}

func (client *fakeClient) CancelExec(_ context.Context, sandbox string, request provider.CancelExecRequest, admission provider.Admission) (provider.ProviderOperation, error) {
	client.cancels = append(client.cancels, request)
	if err := client.recordStep("cancel", admission); err != nil {
		return provider.ProviderOperation{}, err
	}
	if client.cancelHook != nil {
		if err := client.cancelHook(len(client.cancels), request, admission); err != nil {
			return provider.ProviderOperation{}, err
		}
	}
	return provider.ProviderOperation{OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken, SandboxID: sandbox, Type: "cancel_exec", Status: "accepted"}, nil
}

func (client *fakeClient) GetExecResult(_ context.Context, descriptor provider.ReadDescriptor, admission provider.Admission) (provider.ExecResult, error) {
	if err := client.recordStep("result", admission); err != nil {
		return provider.ExecResult{}, err
	}
	result := client.result
	if result.OperationID != descriptor.OperationID {
		stamp := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
		zero := 0
		result = provider.ExecResult{OperationID: descriptor.OperationID, AttemptID: descriptor.AttemptID, FencingToken: descriptor.FencingToken, SandboxID: descriptor.SandboxID, Status: "completed", ExitCode: &zero, StdoutReference: "ref:stdout:synthetic", StartedAt: stamp, CompletedAt: stamp, RetainedUntil: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	}
	if client.resultHook != nil {
		client.resultHook(&result)
	}
	client.result = result
	return result, nil
}

func (client *fakeClient) GetUsageEvidence(_ context.Context, descriptor provider.ReadDescriptor, admission provider.Admission) (provider.UsageEvidence, error) {
	if err := client.recordStep("usage", admission); err != nil {
		return provider.UsageEvidence{}, err
	}
	usage := client.usage
	if usage.OperationID != descriptor.OperationID {
		stamp := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
		usage = provider.UsageEvidence{
			EvidenceID: "usage-1", SandboxID: descriptor.SandboxID, OperationID: descriptor.OperationID, AttemptID: descriptor.AttemptID, FencingToken: descriptor.FencingToken,
			Entries:    []provider.UsageEntry{{EntryID: "count-1", SandboxID: descriptor.SandboxID, OperationID: descriptor.OperationID, Meter: "sandbox.exec_count", Quantity: 1, Unit: "count", MeterSource: "reconciled", EvidenceReference: "ref:usage:1", OccurredAt: stamp}},
			ObservedAt: stamp, RetainedUntil: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), ReconciliationStatus: "partial", EvidenceDigest: jcs.DigestBytes([]byte("provider-local-evidence")),
		}
	}
	if client.usageHook != nil {
		client.usageHook(&usage)
	}
	client.usage = usage
	return usage, nil
}

func (client *fakeClient) OpenRuntimeSession(_ context.Context, sandbox string, request provider.RuntimeSessionOpenRequest, admission provider.Admission) (provider.ProviderOperation, error) {
	client.sessions = append(client.sessions, request)
	if err := client.recordStep("session", admission); err != nil {
		return provider.ProviderOperation{}, err
	}
	if client.sessionHook != nil {
		if err := client.sessionHook(len(client.sessions), request, admission); err != nil {
			return provider.ProviderOperation{}, err
		}
	}
	return provider.ProviderOperation{OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken, SandboxID: sandbox, Type: "open_runtime_session", Status: "accepted"}, nil
}

func (client *fakeClient) GetRuntimeSessionHandoff(_ context.Context, descriptor provider.ReadDescriptor, admission provider.Admission) (provider.RuntimeSessionHandoff, error) {
	if err := client.recordStep("handoff", admission); err != nil {
		return provider.RuntimeSessionHandoff{}, err
	}
	handoff := client.handoff
	if handoff.OperationID != descriptor.OperationID && len(client.sessions) > 0 {
		session := client.sessions[0]
		handoff = provider.RuntimeSessionHandoff{OperationID: descriptor.OperationID, AttemptID: descriptor.AttemptID, FencingToken: descriptor.FencingToken, SandboxID: descriptor.SandboxID, RuntimeSessionID: session.RuntimeSessionID, RuntimeType: "terminal", CapabilityProfileID: TerminalProfileID, Protocol: "websocket", InternalEndpointReference: "ref:session:synthetic-1", ConnectionGeneration: 1, ExpiresAt: session.ExpiresAt}
	}
	if client.handoffHook != nil {
		client.handoffHook(&handoff)
	}
	client.handoff = handoff
	return handoff, nil
}

func (client *fakeClient) ConnectRuntimeSession(_ context.Context, handoff provider.RuntimeSessionHandoff, admission provider.Admission) (io.ReadWriteCloser, error) {
	client.connects = append(client.connects, handoff)
	if err := client.recordStep("connect", admission); err != nil {
		return nil, err
	}
	if client.connectHook != nil {
		return client.connectHook(handoff, admission)
	}
	caller, backend := net.Pipe()
	go serveFakeShell(backend, false)
	return caller, nil
}

func serveFakeShell(backend io.ReadWriteCloser, appendUnexpected bool) {
	defer backend.Close()
	reader := bufio.NewReader(backend)
	for {
		line, err := reader.ReadString('\n')
		if markerStart := strings.Index(line, "SRC-ROUNDTRIP-"); markerStart >= 0 {
			const markerLength = len("SRC-ROUNDTRIP-") + 32
			if len(line) >= markerStart+markerLength {
				_, _ = io.WriteString(backend, "\r\n"+line[markerStart:markerStart+markerLength]+"\r\n")
				if appendUnexpected {
					_, _ = io.WriteString(backend, "unexpected-pre-expiry-byte")
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func TestExecTerminalBindsObservedDocumentsAndOrderedAdmissions(t *testing.T) {
	store, client, run := initialFixture(t)
	if err := run(); err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	resultDigest, _ := jcs.Digest(client.result)
	usageDigest, _ := jcs.Digest(client.usage)
	if state.Stage != callerstate.StageTerminalBound || state.StoreRevision != 5 || state.Exec.ResultDigest != resultDigest || state.Exec.UsageEvidenceDigest != usageDigest || usageDigest == client.usage.EvidenceDigest || state.Terminal.RuntimeSessionID != client.sessions[0].RuntimeSessionID {
		t.Fatal("state is not bound to the actual documents")
	}
	var operations []string
	for _, admission := range client.admissions {
		operations = append(operations, admission.Context.Operation)
	}
	want := []string{"create", "read_operation", "read_sandbox", "exec", "read_operation", "read_result", "read_usage_evidence", "open_runtime_session", "read_operation", "read_runtime_session"}
	if !reflect.DeepEqual(operations, want) {
		t.Fatalf("calls = %v", operations)
	}
	if len(client.execs) != 1 || len(client.sessions) != 1 || client.execs[0].OperationID != state.Plan.Exec.OperationID || client.execs[0].IdempotencyKey != state.Plan.Exec.IdempotencyKey || client.sessions[0].IdempotencyKey != state.Plan.Terminal.IdempotencyKey {
		t.Fatal("mutation plan changed")
	}
	if err := store.ValidateUnchanged(); err != nil {
		t.Fatal(err)
	}
}

func TestExecTerminalFailureRetainsLastDurableStage(t *testing.T) {
	for _, step := range []string{"exec", "result", "usage", "session", "handoff", "poll_exec", "poll_session"} {
		t.Run(step, func(t *testing.T) {
			store, client, run := initialFixture(t)
			wanted := step
			if step == "poll_exec" {
				wanted = "poll:" + store.Snapshot().Plan.Exec.OperationID
			}
			if step == "poll_session" {
				wanted = "poll:" + store.Snapshot().Plan.Terminal.OperationID
			}
			client.hook = func(at string) error {
				if at == wanted {
					return errors.New("private backend diagnostic")
				}
				return nil
			}
			if err := run(); err != ErrLifecycle {
				t.Fatalf("failure = %v", err)
			}
			wantStage := callerstate.StageLifecycleBound
			if step == "session" || step == "handoff" || step == "poll_session" {
				wantStage = callerstate.StageExecBound
			}
			if store.Snapshot().Stage != wantStage || len(client.execs) != 1 || len(client.sessions) > 1 {
				t.Fatalf("failure stage = %s", store.Snapshot().Stage)
			}
			if err := store.ValidateUnchanged(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExecTerminalRejectsInconsistentEvidence(t *testing.T) {
	for _, name := range []string{"failed result", "missing exit", "wrong result attempt", "expired result", "reversed times", "unknown usage", "wrong usage operation", "cross sandbox entry", "wrong count", "no count", "expired usage", "wrong session", "wrong profile", "expired handoff", "extended handoff", "wrong operation type", "unknown operation"} {
		t.Run(name, func(t *testing.T) {
			store, client, run := initialFixture(t)
			client.resultHook = func(r *provider.ExecResult) {
				switch name {
				case "failed result":
					r.Status = "failed"
				case "missing exit":
					r.ExitCode = nil
				case "wrong result attempt":
					r.AttemptID = "other"
				case "expired result":
					r.RetainedUntil = r.CompletedAt
				case "reversed times":
					r.StartedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
				}
			}
			client.usageHook = func(u *provider.UsageEvidence) {
				switch name {
				case "unknown usage":
					u.ReconciliationStatus = "unknown"
				case "wrong usage operation":
					u.OperationID = "other"
				case "cross sandbox entry":
					u.Entries[0].SandboxID = "other"
				case "wrong count":
					u.Entries[0].Quantity = 2
				case "no count":
					u.Entries = nil
				case "expired usage":
					u.RetainedUntil = u.ObservedAt
				}
			}
			client.handoffHook = func(h *provider.RuntimeSessionHandoff) {
				switch name {
				case "wrong session":
					h.RuntimeSessionID = "other"
				case "wrong profile":
					h.CapabilityProfileID = "other"
				case "expired handoff":
					h.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
				case "extended handoff":
					h.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
				}
			}
			client.operationHook = func(op *provider.ProviderOperation) {
				if op.Type == "exec" {
					if name == "wrong operation type" {
						op.Type = "create"
					}
					if name == "unknown operation" {
						op.Status = "outcome_unknown"
					}
				}
			}
			if err := run(); err != ErrLifecycle {
				t.Fatalf("failure = %v", err)
			}
			want := callerstate.StageLifecycleBound
			if name == "wrong session" || name == "wrong profile" || name == "expired handoff" || name == "extended handoff" {
				want = callerstate.StageExecBound
			}
			if store.Snapshot().Stage != want {
				t.Fatalf("stage = %s, want %s", store.Snapshot().Stage, want)
			}
		})
	}
}

func initialFixture(t *testing.T) (*callerstate.Store, *fakeClient, func() error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return initialFixtureContext(t, ctx)
}

func initialFixtureContext(t *testing.T, ctx context.Context) (*callerstate.Store, *fakeClient, func() error) {
	t.Helper()
	store := initialStore(t)
	t.Cleanup(func() { _ = store.Close() })
	capabilities, raw := selectedCapabilities(t)
	client := &fakeClient{capabilities: capabilities, raw: raw, store: store}
	other := &fakeClient{capabilities: capabilities, raw: raw, store: store}
	closed := 0
	factory := fakeFactory(t, map[string]*fakeClient{"controller_a": client, "controller_b": other}, &closed)
	return store, client, func() error {
		authority, err := run(ctx, "initial", "https://provider.example", &credentials.Bundle{}, store, factory, time.Now)
		if authority != nil {
			authority.Close()
		}
		if err != nil && authority != nil {
			t.Fatal("failed Provider work exposed terminal authority")
		}
		return err
	}
}

func TestPendingEvidenceRetriesFreshAdmissionsWithoutRepeatingMutations(t *testing.T) {
	store, client, run := initialFixture(t)
	reads := 0
	delay := 1
	client.hook = func(step string) error {
		if step == "usage" {
			reads++
			if reads == 1 {
				return &provider.HTTPError{StatusCode: 503, Document: provider.StandardError{Retryable: true}, RetryAfterSeconds: &delay}
			}
		}
		return nil
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if reads != 2 || len(client.execs) != 1 || len(client.sessions) != 1 || store.Snapshot().Stage != callerstate.StageTerminalBound {
		t.Fatal("pending read repeated mutation or skipped binding")
	}
	seen := map[string]bool{}
	for _, admission := range client.admissions {
		if seen[admission.Claims.JTI] {
			t.Fatal("retry reused an admission token")
		}
		seen[admission.Claims.JTI] = true
	}
}

func TestResultExpiryWhileWaitingForUsageDoesNotBindExec(t *testing.T) {
	store, client, run := initialFixture(t)
	client.resultHook = func(result *provider.ExecResult) {
		result.RetainedUntil = time.Now().Add(500 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	}
	reads, delay := 0, 1
	client.hook = func(step string) error {
		if step == "usage" {
			reads++
			if reads == 1 {
				return &provider.HTTPError{StatusCode: 503, Document: provider.StandardError{Retryable: true}, RetryAfterSeconds: &delay}
			}
		}
		return nil
	}
	if err := run(); err != ErrLifecycle {
		t.Fatalf("expired result = %v", err)
	}
	if store.Snapshot().Stage != callerstate.StageLifecycleBound || len(client.sessions) != 0 {
		t.Fatal("expired evidence advanced state")
	}
}

func TestEvidenceReadCancellationAndUnretryableFailureDoNotAdvance(t *testing.T) {
	for _, scenario := range []string{"cancel after result", "cancel pending read", "expired", "missing retry after", "delay exceeds budget"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			store, client, run := initialFixtureContext(t, ctx)
			readCalls := 0
			delay := 1
			client.resultHook = func(*provider.ExecResult) {
				if scenario == "cancel after result" {
					cancel()
				}
			}
			client.hook = func(step string) error {
				if step != "usage" {
					return nil
				}
				readCalls++
				switch scenario {
				case "expired":
					return &provider.HTTPError{StatusCode: 410}
				case "missing retry after":
					return &provider.HTTPError{StatusCode: 503, Document: provider.StandardError{Retryable: true}}
				case "delay exceeds budget":
					delay = int(^uint(0) >> 1)
				case "cancel pending read":
					time.AfterFunc(10*time.Millisecond, cancel)
				}
				return &provider.HTTPError{StatusCode: 503, Document: provider.StandardError{Retryable: true}, RetryAfterSeconds: &delay}
			}
			err := run()
			if scenario == "cancel after result" || scenario == "cancel pending read" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation = %v", err)
				}
			} else if err != ErrLifecycle {
				t.Fatalf("failure = %v", err)
			}
			if store.Snapshot().Stage != callerstate.StageLifecycleBound || len(client.execs) != 1 || len(client.sessions) != 0 || readCalls > 1 {
				t.Fatal("failed read changed state or repeated mutation")
			}
		})
	}
}

func TestRequestsClipDeadlineToPhaseLeaseAndExecLimit(t *testing.T) {
	store := initialStore(t)
	defer store.Close()
	now := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(30*time.Second))
	defer cancel()
	for _, test := range []struct {
		limit int64
		lease time.Duration
		want  time.Duration
	}{{2, 20 * time.Second, 2 * time.Second}, {100, 4 * time.Second, 4 * time.Second}, {100, 100 * time.Second, 30 * time.Second}, {1 << 62, 100 * time.Second, 30 * time.Second}} {
		request, err := execRequest(ctx, store.Snapshot(), test.limit, now.Add(test.lease).Format(time.RFC3339Nano), now)
		if err != nil {
			t.Fatal(err)
		}
		deadline, _ := time.Parse(time.RFC3339Nano, request.DeadlineAt)
		if !deadline.Equal(now.Add(test.want)) {
			t.Fatalf("exec deadline = %v", deadline)
		}
	}
	request, err := runtimeSessionRequest(ctx, store.Snapshot(), now.Add(3*time.Second).Format(time.RFC3339Nano), now)
	if err != nil || request.ExpiresAt != now.Add(3*time.Second).Format(time.RFC3339Nano) || request.ExpiresAt != request.DeadlineAt {
		t.Fatal("session exceeded lease/deadline")
	}
}
