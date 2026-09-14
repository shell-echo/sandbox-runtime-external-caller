package gatewaycontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func TestRequestRoundTripIsClosedBoundedAndCredentialFree(t *testing.T) {
	descriptors := fixedDescriptors()
	request, err := NewRequest("initial", "https://gateway.example/tunnel", descriptors)
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
		`"invocation_id"`, `"profile_path"`, `"provider_origin"`, `"caller_state_root"`,
		`"sandbox_id"`, `"operation_id"`, `"attempt_id"`, `"idempotency_key"`,
		`"fencing_token"`, `"runtime_session_id"`, `"handoff_reference"`,
		`"certificate_chain_pem"`, `"private_key_pem"`,
	} {
		if bytes.Contains(wire.Bytes(), []byte(forbidden)) {
			t.Fatalf("Gateway control request contains forbidden member %s", forbidden)
		}
	}
	decoded, err := DecodeRequest(bytes.NewReader(wire.Bytes()))
	if err != nil || decoded.Phase != "initial" || len(decoded.CredentialChannelDescriptors) != 2 {
		t.Fatalf("DecodeRequest() = %#v, %v", decoded, err)
	}
}

func TestRequestRejectsUnknownDuplicateOversizedAndBindingChanges(t *testing.T) {
	request, err := NewRequest("initial", "https://gateway.example/tunnel", fixedDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "unknown", wire: insertMember(document, `"sandbox_id":"forbidden"`)},
		{name: "duplicate", wire: insertMember(document, `"phase":"initial"`)},
		{name: "multiple", wire: append(append([]byte(nil), document...), document...)},
		{name: "oversized", wire: bytes.Repeat([]byte{' '}, MaxRequestBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeRequest(bytes.NewReader(test.wire)); !errors.Is(err, ErrControlRequest) {
				t.Fatalf("DecodeRequest() error = %v", err)
			}
		})
	}

	request.GatewayProbeEndpoint = "https://gateway.example/tunnel?correlation=forbidden"
	if err := EncodeRequest(&bytes.Buffer{}, request); !errors.Is(err, ErrControlRequest) {
		t.Fatalf("query-bearing Gateway endpoint error = %v", err)
	}
	request, _ = NewRequest("initial", "https://gateway.example/tunnel", fixedDescriptors())
	request.CredentialChannelDescriptors[0].FileDescriptor = request.CredentialChannelDescriptors[1].FileDescriptor
	if err := EncodeRequest(&bytes.Buffer{}, request); !errors.Is(err, ErrControlRequest) {
		t.Fatalf("duplicate credential descriptor error = %v", err)
	}
}

func TestResultRequiresSingleLFAndExplicitNoListenerStatus(t *testing.T) {
	result, err := NewResult("reconstruction", 1234)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := EncodeResult(&wire, result); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResult(bytes.NewReader(wire.Bytes()))
	if err != nil || decoded.Phase != "reconstruction" || decoded.ProcessID != 1234 || decoded.Status != "server_identity_validated_no_listener" {
		t.Fatalf("DecodeResult() = %#v, %v", decoded, err)
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

func fixedDescriptors() []protocol.ChannelDescriptor {
	requirements := credentials.GatewayRequirements()
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	for index, requirement := range requirements {
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index,
		})
	}
	return descriptors
}

func TestGatewayControlRejectsLegacyIdentityAndFalseReadiness(t *testing.T) {
	request, err := NewRequest("initial", "https://gateway.example/tunnel", fixedDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	request.ProtocolID = "sandbox-runtime-external-caller-private-gateway-control-v1"
	request.ProtocolVersion = "1.0.0"
	wire, _ := json.Marshal(request)
	if _, err := DecodeRequest(bytes.NewReader(wire)); !errors.Is(err, ErrControlRequest) {
		t.Fatal("legacy control accepted")
	}
	result, _ := NewResult("initial", 123)
	for _, status := range []string{"control_and_credentials_consumed_no_listener", "listening", "passed"} {
		result.Status = status
		if err := EncodeResult(&bytes.Buffer{}, result); !errors.Is(err, ErrControlResult) {
			t.Fatal("false readiness accepted")
		}
	}
}

func insertMember(document []byte, member string) []byte {
	return []byte("{" + member + "," + strings.TrimPrefix(string(document), "{"))
}
