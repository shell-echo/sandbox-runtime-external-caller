package callercontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func TestRequestRoundTripIsClosedBoundedAndCredentialFree(t *testing.T) {
	descriptors := fixedDescriptors()
	deadline := time.Now().Add(30 * time.Second).UTC()
	request, err := NewRequest(testInvocation(), descriptors, deadline)
	if err != nil {
		t.Fatal(err)
	}
	descriptors[0].ChannelID = "mutated"
	if request.CredentialChannelDescriptors[0].ChannelID == "mutated" {
		t.Fatal("NewRequest retained caller-owned descriptor storage")
	}
	var wire bytes.Buffer
	if err := EncodeRequest(&wire, request); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		`"invocation_id"`, `"profile_path"`, `"sandbox_id"`, `"operation_id"`, `"attempt_id"`,
		`"idempotency_key"`, `"fencing_token"`, `"runtime_session_id"`, `"handoff_reference"`,
		`"certificate_chain_pem"`, `"private_key_pem"`,
	} {
		if bytes.Contains(wire.Bytes(), []byte(forbidden)) {
			t.Fatalf("control request contains forbidden member %s", forbidden)
		}
	}
	decoded, err := DecodeRequest(bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Phase != "initial" || decoded.ProviderOrigin != "https://provider.example" || !decoded.Deadline.Equal(deadline) || len(decoded.CredentialChannelDescriptors) != 8 {
		t.Fatalf("decoded request = %#v", decoded)
	}
}

func TestRequestRejectsUnknownDuplicateOversizedAndBindingChanges(t *testing.T) {
	request, err := NewRequest(testInvocation(), fixedDescriptors(), time.Now().Add(30*time.Second).UTC())
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		wire []byte
	}{
		{name: "unknown", wire: insertMember(document, `"sandbox_id":"forbidden"`)},
		{name: "duplicate", wire: insertMember(document, `"phase":"initial"`)},
		{name: "multiple", wire: append(append([]byte(nil), document...), document...)},
		{name: "oversized", wire: bytes.Repeat([]byte{' '}, MaxRequestBytes+1)},
		{name: "old v3 identity", wire: bytes.Replace(document, []byte(ProtocolID), []byte("sandbox-runtime-external-caller-private-control-v3"), 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeRequest(bytes.NewReader(test.wire)); !errors.Is(err, ErrControlRequest) {
				t.Fatalf("DecodeRequest() error = %v", err)
			}
		})
	}

	request.ProviderOrigin = "https://provider.example/path"
	if err := EncodeRequest(&bytes.Buffer{}, request); !errors.Is(err, ErrControlRequest) {
		t.Fatalf("path-bearing Provider origin error = %v", err)
	}
	request, _ = NewRequest(testInvocation(), fixedDescriptors(), time.Now().Add(30*time.Second).UTC())
	request.CredentialChannelDescriptors[0].FileDescriptor = request.CredentialChannelDescriptors[1].FileDescriptor
	if err := EncodeRequest(&bytes.Buffer{}, request); !errors.Is(err, ErrControlRequest) {
		t.Fatalf("duplicate credential descriptor error = %v", err)
	}
	request, _ = NewRequest(testInvocation(), fixedDescriptors(), time.Now().Add(30*time.Second).UTC())
	request.Deadline = time.Time{}
	if err := EncodeRequest(&bytes.Buffer{}, request); !errors.Is(err, ErrControlRequest) {
		t.Fatalf("zero deadline error = %v", err)
	}
}

func TestResultRequiresSingleLFAndExactProcessBinding(t *testing.T) {
	result, err := NewResult("reconstruction", 1234)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := EncodeResult(&wire, result); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResult(bytes.NewReader(wire.Bytes()))
	if err != nil || decoded.Phase != "reconstruction" || decoded.ProcessID != 1234 || decoded.MessageType != "phase_lifecycle_complete" || decoded.Status != "provider_lifecycle_and_gateway_coordination_complete_no_scenario_results" {
		t.Fatalf("DecodeResult() = %#v, %v", decoded, err)
	}
	oldV3 := bytes.Replace(wire.Bytes(), []byte(ProtocolID), []byte("sandbox-runtime-external-caller-private-control-v3"), 1)
	if _, err := DecodeResult(bytes.NewReader(oldV3)); !errors.Is(err, ErrControlResult) {
		t.Fatalf("old v3 result identity error = %v", err)
	}
	if _, err := DecodeResult(strings.NewReader(wire.String() + "\n")); !errors.Is(err, ErrControlResult) {
		t.Fatalf("extra LF result error = %v", err)
	}
	unknown := insertMember(bytes.TrimSuffix(wire.Bytes(), []byte{'\n'}), `"runtime_session_id":"forbidden"`)
	unknown = append(unknown, '\n')
	if _, err := DecodeResult(bytes.NewReader(unknown)); !errors.Is(err, ErrControlResult) {
		t.Fatalf("unknown result member error = %v", err)
	}
}

func testInvocation() protocol.Invocation {
	return protocol.Invocation{
		FormatVersion: protocol.FormatVersion, ProtocolID: protocol.ProtocolID, ProtocolVersion: protocol.ProtocolVersion,
		MessageType: "invocation", InvocationID: "private-control-test", Phase: "initial", ProfilePath: "/qualification/profile.json",
		ProviderOrigin: "https://provider.example", GatewayProbeEndpoint: "https://gateway.example/tunnel", CallerStateRoot: "/caller/state",
	}
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

func insertMember(document []byte, member string) []byte {
	return []byte("{" + member + "," + strings.TrimPrefix(string(document), "{"))
}
