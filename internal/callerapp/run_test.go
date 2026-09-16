//go:build darwin || linux

package callerapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callercontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerphase"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerterminal"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
)

type recordingGateway struct {
	phase      string
	endpoint   string
	totalBytes int
	err        error
	bundle     *credentials.Bundle
	service    *recordingService
}

type recordingService struct {
	tenantA, tenantB string
	stopped          bool
}

func (gateway *recordingGateway) Start(_ context.Context, phase, endpoint string, bundle *credentials.Bundle) (callerphase.GatewayService, error) {
	gateway.phase = phase
	gateway.endpoint = endpoint
	gateway.totalBytes = bundle.TotalBytes()
	gateway.bundle = bundle
	if gateway.err != nil {
		return nil, gateway.err
	}
	gateway.service = &recordingService{}
	return gateway.service, nil
}

func (service *recordingService) InstallPolicy(_ context.Context, tenantA, tenantB string) error {
	service.tenantA, service.tenantB = tenantA, tenantB
	return nil
}

func (service *recordingService) Stop(context.Context) error {
	service.stopped = true
	return nil
}

func (service *recordingService) Wait() error { return nil }

func (service *recordingService) SetBackend(callerterminal.BackendOpener) error { return nil }

func (service *recordingService) IssueGrant(context.Context, string, string, string, string, time.Time) (string, error) {
	return strings.Repeat("A", 43), nil
}

func (service *recordingService) Revoke(context.Context, string, string) error { return nil }

func TestRunConsumesControlAndCredentialPipes(t *testing.T) {
	descriptors, writers := callerCredentialPipes(t)
	payloads := testcredentials.New(t).Payloads
	request := callerRequest(t, descriptors)
	var input bytes.Buffer
	if err := callercontrol.EncodeRequest(&input, request); err != nil {
		t.Fatal(err)
	}
	var writersDone sync.WaitGroup
	for index, writer := range writers {
		writersDone.Add(1)
		go func(index int, writer *os.File) {
			defer writersDone.Done()
			_, _ = writer.Write(payloads[credentials.Requirements()[index].ChannelID])
			_ = writer.Close()
		}(index, writer)
	}
	var output bytes.Buffer
	gateway := &recordingGateway{}
	if code := RunWithCoordinator(context.Background(), nil, &input, &output, gateway.Start, fakeProviderPhase); code != ExitSuccess {
		t.Fatalf("Run() exit code = %d", code)
	}
	writersDone.Wait()
	result, err := callercontrol.DecodeResult(bytes.NewReader(output.Bytes()))
	if err != nil || result.Phase != "initial" || result.ProcessID != os.Getpid() {
		t.Fatalf("caller result = %#v, %v", result, err)
	}
}

func TestRunRejectsArgumentsAndMalformedControlWithoutOutput(t *testing.T) {
	for _, test := range []struct {
		name  string
		args  []string
		input []byte
		want  int
	}{
		{name: "argument", args: []string{"forbidden"}, want: ExitUsage},
		{name: "malformed", input: []byte(`{"unknown":true}`), want: ExitData},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if code := Run(test.args, bytes.NewReader(test.input), &output); code != test.want {
				t.Fatalf("Run() exit code = %d, want %d", code, test.want)
			}
			if output.Len() != 0 {
				t.Fatalf("rejected caller output = %q", output.Bytes())
			}
		})
	}
}

func TestRunWithScenariosRejectsNilParentBeforeInput(t *testing.T) {
	var output bytes.Buffer
	if code := RunWithScenarios(nil, nil, bytes.NewReader(nil), &output, nil); code != ExitSoftware || output.Len() != 0 {
		t.Fatalf("RunWithScenarios(nil parent) = %d, %q", code, output.Bytes())
	}
}

func TestRunWithCoordinatorForwardsPhaseEndpointAndLiveBundle(t *testing.T) {
	descriptors, writers := callerCredentialPipes(t)
	payloads := testcredentials.New(t).Payloads
	request := callerRequest(t, descriptors)
	var input bytes.Buffer
	if err := callercontrol.EncodeRequest(&input, request); err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write(payloads[credentials.Requirements()[index].ChannelID])
			_ = writer.Close()
		}(index, writer)
	}
	gateway := &recordingGateway{}
	var output bytes.Buffer
	if code := RunWithCoordinator(context.Background(), nil, &input, &output, gateway.Start, fakeProviderPhase); code != ExitSuccess {
		t.Fatalf("RunWithCoordinator() exit code = %d", code)
	}
	expectedBytes := 0
	for _, payload := range payloads {
		expectedBytes += len(payload)
	}
	if gateway.phase != "initial" || gateway.endpoint != "https://gateway.example/tunnel" || gateway.totalBytes != expectedBytes || gateway.service == nil || !gateway.service.stopped || gateway.service.tenantA == "" || gateway.service.tenantB == "" {
		t.Fatalf("Gateway input = phase %q, endpoint %q, bytes %d", gateway.phase, gateway.endpoint, gateway.totalBytes)
	}
}

func TestRunWithCoordinatorFailsClosedWithoutReadiness(t *testing.T) {
	descriptors, writers := callerCredentialPipes(t)
	payloads := testcredentials.New(t).Payloads
	request := callerRequest(t, descriptors)
	var input bytes.Buffer
	if err := callercontrol.EncodeRequest(&input, request); err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write(payloads[credentials.Requirements()[index].ChannelID])
			_ = writer.Close()
		}(index, writer)
	}
	var output bytes.Buffer
	gateway := &recordingGateway{err: errors.New("failed")}
	if code := RunWithCoordinator(context.Background(), nil, &input, &output, gateway.Start, fakeProviderPhase); code != ExitSoftware {
		t.Fatalf("RunWithCoordinator(failure) exit code = %d", code)
	}
	if output.Len() != 0 {
		t.Fatalf("failed Gateway emitted caller readiness: %q", output.Bytes())
	}
	if gateway.bundle == nil || gateway.bundle.TotalBytes() != 0 {
		t.Fatal("failed Gateway retained caller credential bytes")
	}
}

func TestRunRejectsRegularCredentialDescriptors(t *testing.T) {
	requirements := credentials.Requirements()
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	descriptorFDs := make([]int, 0, len(requirements))
	for _, requirement := range requirements {
		file, err := os.CreateTemp(t.TempDir(), "not-a-pipe")
		if err != nil {
			t.Fatal(err)
		}
		ownedDescriptor, err := syscall.Dup(int(file.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		descriptorFDs = append(descriptorFDs, ownedDescriptor)
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: ownedDescriptor,
		})
	}
	defer func() {
		for _, descriptor := range descriptorFDs[1:] {
			_ = syscall.Close(descriptor)
		}
	}()
	var input bytes.Buffer
	if err := callercontrol.EncodeRequest(&input, callerRequest(t, descriptors)); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if code := Run(nil, &input, &output); code != ExitData || output.Len() != 0 {
		t.Fatalf("Run(regular descriptors) = %d, %q", code, output.Bytes())
	}
}

func callerRequest(t *testing.T, descriptors []protocol.ChannelDescriptor) callercontrol.Request {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "caller-state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	request, err := callercontrol.NewRequest(protocol.Invocation{
		FormatVersion: protocol.FormatVersion, ProtocolID: protocol.ProtocolID, ProtocolVersion: protocol.ProtocolVersion,
		MessageType: "invocation", InvocationID: "caller-app-test", Phase: "initial", ProfilePath: "/qualification/profile.json",
		ProviderOrigin: "https://provider.example", GatewayProbeEndpoint: "https://gateway.example/tunnel", CallerStateRoot: root,
	}, descriptors, time.Now().Add(30*time.Second).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func callerCredentialPipes(t *testing.T) ([]protocol.ChannelDescriptor, []*os.File) {
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
	return descriptors, writers
}

func TestRequestWireContainsNoCredentialBytes(t *testing.T) {
	request := callerRequest(t, fixedCallerDescriptors())
	document, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(document, []byte("PRIVATE KEY")) || bytes.Contains(document, []byte("CERTIFICATE")) {
		t.Fatalf("control request contains credential material: %q", document)
	}
}

func fixedCallerDescriptors() []protocol.ChannelDescriptor {
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

func fakeProviderPhase(_ context.Context, phase, _ string, _ *credentials.Bundle, store *callerstate.Store) (*callerterminal.Authority, error) {
	if phase == "reconstruction" {
		return nil, nil
	}
	if err := store.BindCapabilities("provider-revision-1", []byte(`{"capabilities":[]}`), "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "2026-09-12T00:00:00Z"); err != nil {
		return nil, err
	}
	if err := store.BindLifecycle(1); err != nil {
		return nil, err
	}
	if err := store.BindExec(2, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
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
