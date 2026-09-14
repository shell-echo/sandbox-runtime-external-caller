//go:build darwin || linux

package callerprovider_test

import (
	"context"
	"os"
	"path/filepath"
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

func TestLiveMTLSInitialCapabilityCreateAndReconciliation(t *testing.T) {
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
	if err := callerprovider.Run(ctx, "initial", server.Origin(), bundle, store); err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	if state.Stage != callerstate.StageLifecycleBound || state.Provider == nil || state.Lifecycle == nil {
		t.Fatalf("live Provider state = %#v", state)
	}
	counts, serverErrors := server.Snapshot()
	if len(serverErrors) != 0 || counts.Capabilities != 2 || counts.Creates != 1 || counts.Operations != 1 || counts.Statuses != 1 {
		t.Fatalf("live Provider counts/errors = %#v / %v", counts, serverErrors)
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
