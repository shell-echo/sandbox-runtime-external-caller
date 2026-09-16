//go:build darwin || linux

package callerphase

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callercontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerterminal"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
)

type recordingService struct {
	tenantA, tenantB string
	installed        bool
	stopped          bool
	waited           bool
	installErr       error
	stopHook         func()
	grantHook        func(context.Context, string, string, string, string, time.Time) (string, error)
	revokeHook       func(context.Context, string, string) error
	granted          bool
	revoked          bool
	backendSet       bool
}

func (service *recordingService) SetBackend(callerterminal.BackendOpener) error {
	service.backendSet = true
	return nil
}

func (service *recordingService) IssueGrant(ctx context.Context, actor, tenant, session, handoff string, expiry time.Time) (string, error) {
	service.granted = true
	if service.grantHook != nil {
		return service.grantHook(ctx, actor, tenant, session, handoff, expiry)
	}
	return strings.Repeat("A", 43), nil
}

func (service *recordingService) Revoke(ctx context.Context, actor, token string) error {
	service.revoked = true
	if service.revokeHook != nil {
		return service.revokeHook(ctx, actor, token)
	}
	return nil
}

func (service *recordingService) InstallPolicy(_ context.Context, tenantA, tenantB string) error {
	service.tenantA, service.tenantB = tenantA, tenantB
	service.installed = true
	return service.installErr
}

func (service *recordingService) Stop(context.Context) error {
	if service.stopHook != nil {
		service.stopHook()
	}
	service.stopped = true
	return nil
}

func (service *recordingService) Wait() error {
	service.waited = true
	return nil
}

func TestCoordinateInitialCreatesOnlyPlanAndCompletesGatewayLifecycle(t *testing.T) {
	root := newPrivateRoot(t)
	bundle := testBundle(t)
	defer bundle.Destroy()
	service := &recordingService{}
	started := 0
	request := testRequest("initial", root)
	err := Coordinate(context.Background(), request, bundle, func(ctx context.Context, phase, endpoint string, got *credentials.Bundle) (GatewayService, error) {
		started++
		if _, ok := ctx.Deadline(); !ok || phase != "initial" || endpoint != request.GatewayProbeEndpoint || got != bundle {
			t.Fatal("Gateway start did not preserve phase inputs and deadline")
		}
		return service, nil
	}, fakeProvider)
	if err != nil {
		t.Fatal(err)
	}
	if started != 1 || !service.installed || !service.backendSet || !service.granted || !service.revoked || !service.stopped || service.waited || service.tenantA == "" || service.tenantB == "" || service.tenantA == service.tenantB {
		t.Fatalf("Gateway lifecycle = start %d, service %#v", started, service)
	}
	state := readState(t, root)
	if state.Stage != callerstate.StageTerminalBound || state.StoreRevision != 5 || state.Plan.TenantAID != service.tenantA || state.Plan.TenantBID != service.tenantB {
		t.Fatalf("initial lifecycle state = %#v", state)
	}
	if _, err := callerstate.OpenReconstruction(root); !errors.Is(err, callerstate.ErrInvalidState) {
		t.Fatalf("planned state accepted for reconstruction: %v", err)
	}
}

func TestCoordinateReconstructionRequiresCompleteStateAndDoesNotMutateIt(t *testing.T) {
	root := completeRoot(t)
	want := readState(t, root)
	bundle := testBundle(t)
	defer bundle.Destroy()
	service := &recordingService{}
	if err := Coordinate(context.Background(), testRequest("reconstruction", root), bundle, func(context.Context, string, string, *credentials.Bundle) (GatewayService, error) {
		return service, nil
	}, fakeProvider); err != nil {
		t.Fatal(err)
	}
	got := readState(t, root)
	if !reflect.DeepEqual(got, want) || service.tenantA != want.Plan.TenantAID || service.tenantB != want.Plan.TenantBID || !service.stopped || service.granted || service.revoked {
		t.Fatalf("reconstruction changed state or policy: got %#v service %#v", got, service)
	}

	partial := newPrivateRoot(t)
	store, err := callerstate.CreateInitial(partial)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	started := false
	if err := Coordinate(context.Background(), testRequest("reconstruction", partial), bundle, func(context.Context, string, string, *credentials.Bundle) (GatewayService, error) {
		started = true
		return &recordingService{}, nil
	}, fakeProvider); !errors.Is(err, ErrPhaseState) || started {
		t.Fatalf("partial reconstruction = %v, started %t", err, started)
	}
}

func TestCoordinateRejectsDeadlineBeforeStateAndCleansUpFailedService(t *testing.T) {
	bundle := testBundle(t)
	defer bundle.Destroy()
	expiredRoot := newPrivateRoot(t)
	expired := testRequest("initial", expiredRoot)
	expired.Deadline = time.Now().Add(-time.Second).UTC()
	if err := Coordinate(context.Background(), expired, bundle, func(context.Context, string, string, *credentials.Bundle) (GatewayService, error) {
		t.Fatal("expired phase started Gateway")
		return nil, nil
	}, fakeProvider); !errors.Is(err, ErrPhaseDeadline) {
		t.Fatalf("expired deadline error = %v", err)
	}
	if entries, err := os.ReadDir(expiredRoot); err != nil || len(entries) != 0 {
		t.Fatalf("expired phase touched state root: %v, %#v", err, entries)
	}
	canceledRoot := newPrivateRoot(t)
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Coordinate(parent, testRequest("initial", canceledRoot), bundle, func(context.Context, string, string, *credentials.Bundle) (GatewayService, error) {
		t.Fatal("canceled phase started Gateway")
		return nil, nil
	}, fakeProvider); !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation error = %v", err)
	}
	if entries, err := os.ReadDir(canceledRoot); err != nil || len(entries) != 0 {
		t.Fatalf("canceled phase touched state root: %v, %#v", err, entries)
	}

	failureRoot := newPrivateRoot(t)
	service := &recordingService{installErr: errors.New("synthetic failure")}
	if err := Coordinate(context.Background(), testRequest("initial", failureRoot), bundle, func(context.Context, string, string, *credentials.Bundle) (GatewayService, error) {
		return service, nil
	}, fakeProvider); !errors.Is(err, ErrGatewayLifecycle) {
		t.Fatalf("failed policy error = %v", err)
	}
	if !service.waited || service.stopped {
		t.Fatalf("failed service cleanup = %#v", service)
	}
	if readState(t, failureRoot).Stage != callerstate.StagePlanned {
		t.Fatal("failed phase did not retain fail-closed partial state")
	}
}

func TestCoordinateRejectsStateChangedDuringGatewayLifecycle(t *testing.T) {
	root := newPrivateRoot(t)
	bundle := testBundle(t)
	defer bundle.Destroy()
	service := &recordingService{stopHook: func() {
		path := filepath.Join(root, callerstate.StateFileName)
		document, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(document, ' '), 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	if err := Coordinate(context.Background(), testRequest("initial", root), bundle, func(context.Context, string, string, *credentials.Bundle) (GatewayService, error) {
		return service, nil
	}, fakeProvider); !errors.Is(err, ErrPhaseState) {
		t.Fatalf("out-of-band state change error = %v", err)
	}
	if !service.stopped {
		t.Fatal("state check ran before clean Gateway stop")
	}
}

func fakeProvider(_ context.Context, phase, _ string, _ *credentials.Bundle, store *callerstate.Store) (*callerterminal.Authority, error) {
	if phase == "reconstruction" {
		return nil, nil
	}
	if err := store.BindCapabilities("provider-revision-1", []byte(`{"capabilities":[]}`), testDigest('f'), "2026-09-12T00:00:00Z"); err != nil {
		return nil, err
	}
	if err := store.BindLifecycle(1); err != nil {
		return nil, err
	}
	if err := store.BindExec(2, testDigest('a'), testDigest('b')); err != nil {
		return nil, err
	}
	if err := store.BindTerminal(3, "runtime-session-1", "ref:session:synthetic"); err != nil {
		return nil, err
	}
	state := store.Snapshot()
	return &callerterminal.Authority{
		ProviderRevisionID: state.Provider.ProviderRevisionID, SandboxID: state.Plan.SandboxID,
		OperationID: state.Terminal.Operation.OperationID, AttemptID: state.Terminal.Operation.AttemptID, FencingToken: 3,
		RuntimeSessionID: state.Terminal.RuntimeSessionID, HandoffReference: state.Terminal.HandoffReference,
		ExpiresAt: time.Now().Add(time.Minute),
	}, nil
}

func TestCoordinateRejectsLifecycleOnlySuccess(t *testing.T) {
	root := newPrivateRoot(t)
	bundle := testBundle(t)
	defer bundle.Destroy()
	service := &recordingService{}
	err := Coordinate(context.Background(), testRequest("initial", root), bundle, func(context.Context, string, string, *credentials.Bundle) (GatewayService, error) {
		return service, nil
	}, func(_ context.Context, _, _ string, _ *credentials.Bundle, store *callerstate.Store) (*callerterminal.Authority, error) {
		if err := store.BindCapabilities("provider-revision-1", []byte(`{"capabilities":[]}`), testDigest('f'), "2026-09-12T00:00:00Z"); err != nil {
			return nil, err
		}
		return nil, store.BindLifecycle(1)
	})
	if err != ErrPhaseState || service.stopped || !service.waited || service.granted || readState(t, root).Stage != callerstate.StageLifecycleBound {
		t.Fatalf("incomplete success = %v", err)
	}
}

func testRequest(phase, root string) callercontrol.Request {
	return callercontrol.Request{
		FormatVersion: callercontrol.FormatVersion, ProtocolID: callercontrol.ProtocolID, ProtocolVersion: callercontrol.ProtocolVersion,
		MessageType: "run_phase", Phase: phase, ProviderOrigin: "https://provider.example",
		GatewayProbeEndpoint: "https://gateway.example/tunnel", CallerStateRoot: root,
		Deadline: time.Now().Add(30 * time.Second).UTC(), CredentialChannelDescriptors: fixedDescriptors(),
	}
}

func newPrivateRoot(t *testing.T) string {
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

func completeRoot(t *testing.T) string {
	t.Helper()
	root := newPrivateRoot(t)
	store, err := callerstate.CreateInitial(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindCapabilities("provider-revision-1", []byte(`{"capabilities":[]}`), testDigest('f'), "2026-09-12T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := store.BindLifecycle(1); err != nil {
		t.Fatal(err)
	}
	if err := store.BindExec(2, testDigest('a'), testDigest('b')); err != nil {
		t.Fatal(err)
	}
	if err := store.BindTerminal(3, "runtime-session-1", "opaque:handoff:1"); err != nil {
		t.Fatal(err)
	}
	if err := store.BindArtifact(4, testDigest('c')); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return root
}

func readState(t *testing.T, root string) callerstate.State {
	t.Helper()
	document, err := os.ReadFile(filepath.Join(root, callerstate.StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	var state callerstate.State
	if err := json.Unmarshal(document, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func testDigest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func testBundle(t *testing.T) *credentials.Bundle {
	t.Helper()
	requirements := credentials.Requirements()
	payloads := testcredentials.New(t).Payloads
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

func fixedDescriptors() []protocol.ChannelDescriptor {
	requirements := credentials.Requirements()
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	for index, requirement := range requirements {
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index,
		})
	}
	return descriptors
}
