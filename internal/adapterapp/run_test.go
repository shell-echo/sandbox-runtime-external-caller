//go:build darwin || linux

package adapterapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func TestRunEmitsStartupBeforeInputAndStopsWithoutScenarioClaims(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	invocation := testInvocation(descriptors)
	document, err := json.Marshal(invocation)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var writersDone sync.WaitGroup
	input := &startupOrderingReader{
		document: bytes.NewReader(document), output: &output,
		onFirstRead: func() {
			for index, writer := range writers {
				writersDone.Add(1)
				go func(index int, writer *os.File) {
					defer writersDone.Done()
					_, _ = writer.Write([]byte{byte(index + 1)})
					_ = writer.Close()
				}(index, writer)
			}
		},
	}

	if code := Run(nil, input, &output); code != ExitSuccess {
		t.Fatalf("Run() exit code = %d", code)
	}
	writersDone.Wait()

	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 18 {
		t.Fatalf("adapter record count = %d", len(lines))
	}
	for index, line := range lines {
		var envelope struct {
			MessageType string  `json:"message_type"`
			Sequence    int     `json:"sequence"`
			Disposition string  `json:"disposition"`
			ReasonCode  *string `json:"reason_code"`
			Completion  string  `json:"completion"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
		if envelope.Sequence != index {
			t.Fatalf("record %d sequence = %d", index, envelope.Sequence)
		}
		switch {
		case index == 0 && envelope.MessageType != "startup_identity":
			t.Fatalf("first record type = %q", envelope.MessageType)
		case index == 1 && envelope.MessageType != "invocation_accepted":
			t.Fatalf("second record type = %q", envelope.MessageType)
		case index >= 2 && index < len(lines)-1:
			if envelope.MessageType != "scenario_result" || envelope.Disposition != "not_executed" || envelope.ReasonCode == nil || *envelope.ReasonCode != "prerequisite_not_satisfied" {
				t.Fatalf("scenario record %d = %#v", index, envelope)
			}
		case index == len(lines)-1 && (envelope.MessageType != "invocation_finished" || envelope.Completion != "stopped"):
			t.Fatalf("terminal record = %#v", envelope)
		}
	}
}

func TestRunRejectsArgumentsBeforeAnyOutput(t *testing.T) {
	var output bytes.Buffer
	if code := Run([]string{"forbidden"}, bytes.NewReader(nil), &output); code != ExitUsage {
		t.Fatalf("Run(arguments) exit code = %d", code)
	}
	if output.Len() != 0 {
		t.Fatalf("argument rejection output = %q", output.Bytes())
	}
}

func TestRunReportsInvalidInvocationAsTerminalProtocolRecord(t *testing.T) {
	var output bytes.Buffer
	if code := Run(nil, bytes.NewReader([]byte(`{"unknown":true}`)), &output); code != ExitSuccess {
		t.Fatalf("Run(invalid invocation) exit code = %d", code)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 2 || !bytes.Contains(lines[0], []byte(`"message_type":"startup_identity"`)) || !bytes.Contains(lines[1], []byte(`"error_code":"invalid_invocation"`)) {
		t.Fatalf("invalid invocation output = %q", output.Bytes())
	}
}

func TestRunWithCallerReportsStartFailureAndDestroysForwardedSecrets(t *testing.T) {
	descriptors, writers := testCredentialPipes(t)
	document, err := json.Marshal(testInvocation(descriptors))
	if err != nil {
		t.Fatal(err)
	}
	for index, writer := range writers {
		go func(index int, writer *os.File) {
			_, _ = writer.Write([]byte{byte(index + 1)})
			_ = writer.Close()
		}(index, writer)
	}
	runner := &failingCallerRunner{}
	var output bytes.Buffer
	if code := RunWithCaller(context.Background(), nil, bytes.NewReader(document), &output, runner); code != ExitSuccess {
		t.Fatalf("RunWithCaller() exit code = %d", code)
	}
	if runner.phase != "initial" || len(runner.retainedSecret) != 1 || runner.retainedSecret[0] != 0 {
		t.Fatalf("caller invocation/secret after failure = %q / %v", runner.phase, runner.retainedSecret)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 3 || !bytes.Contains(lines[2], []byte(`"error_code":"caller_start_failed"`)) || bytes.Contains(output.Bytes(), []byte(`"scenario_result"`)) {
		t.Fatalf("caller failure output = %q", output.Bytes())
	}
}

type failingCallerRunner struct {
	phase          string
	retainedSecret []byte
}

func (runner *failingCallerRunner) Run(_ context.Context, invocation protocol.Invocation, bundle *credentials.Bundle) error {
	runner.phase = invocation.Phase
	_ = bundle.Use("provider-controller-a", func(payload []byte) error {
		runner.retainedSecret = payload
		return nil
	})
	return errors.New("synthetic caller start failure")
}

type startupOrderingReader struct {
	document    *bytes.Reader
	output      *bytes.Buffer
	onFirstRead func()
	checked     bool
}

func (reader *startupOrderingReader) Read(buffer []byte) (int, error) {
	if !reader.checked {
		reader.checked = true
		if !bytes.Contains(reader.output.Bytes(), []byte(`"message_type":"startup_identity"`)) {
			return 0, io.ErrUnexpectedEOF
		}
		if reader.onFirstRead != nil {
			reader.onFirstRead()
		}
	}
	return reader.document.Read(buffer)
}

func testCredentialPipes(t *testing.T) ([]protocol.ChannelDescriptor, []*os.File) {
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

func testInvocation(descriptors []protocol.ChannelDescriptor) protocol.Invocation {
	return protocol.Invocation{
		FormatVersion: protocol.FormatVersion, ProtocolID: protocol.ProtocolID, ProtocolVersion: protocol.ProtocolVersion,
		MessageType: "invocation", InvocationID: "run.initial", Phase: "initial", ProfilePath: "/qualification/profile.json",
		ProviderOrigin: "https://provider.example", GatewayProbeEndpoint: "https://gateway.example/tunnel",
		CredentialChannelDescriptors: descriptors, CallerStateRoot: "/caller/state",
	}
}
