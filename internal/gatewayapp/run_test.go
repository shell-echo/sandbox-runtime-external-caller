//go:build darwin || linux

package gatewayapp

import (
	"bytes"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewaycontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
)

func TestRunConsumesControlAndGatewayCredentialPipes(t *testing.T) {
	descriptors, writers := gatewayCredentialPipes(t)
	payloads := testcredentials.New(t).Payloads
	request, err := gatewaycontrol.NewRequest("initial", "https://gateway.example/tunnel", descriptors)
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	if err := gatewaycontrol.EncodeRequest(&input, request); err != nil {
		t.Fatal(err)
	}
	var writersDone sync.WaitGroup
	for index, writer := range writers {
		writersDone.Add(1)
		go func(index int, writer *os.File) {
			defer writersDone.Done()
			_, _ = writer.Write(payloads[credentials.GatewayRequirements()[index].ChannelID])
			_ = writer.Close()
		}(index, writer)
	}
	var output bytes.Buffer
	if code := Run(nil, &input, &output); code != ExitSuccess {
		t.Fatalf("Run() exit code = %d", code)
	}
	writersDone.Wait()
	result, err := gatewaycontrol.DecodeResult(bytes.NewReader(output.Bytes()))
	if err != nil || result.Phase != "initial" || result.ProcessID != os.Getpid() || result.Status != "server_identity_validated_no_listener" {
		t.Fatalf("Gateway result = %#v, %v", result, err)
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
				t.Fatalf("rejected Gateway output = %q", output.Bytes())
			}
		})
	}
}

func gatewayCredentialPipes(t *testing.T) ([]protocol.ChannelDescriptor, []*os.File) {
	t.Helper()
	requirements := credentials.GatewayRequirements()
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
