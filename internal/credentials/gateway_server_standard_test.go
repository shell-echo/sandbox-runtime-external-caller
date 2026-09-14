package credentials_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callercontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewaycontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

// The e1.5e.1 declaration is now active. These tests bind it to the unchanged
// public codec and reject legacy or ambiguous delivery before opening any FD.
func TestGatewayServerStandardFitsExistingPublicProtocol(t *testing.T) {
	requirements := servingRequirements(t)
	startup, err := protocol.NewStartupIdentity(
		protocol.SourceIdentity{Kind: "release-id", Value: "serving-proposal", Immutable: true},
		protocol.SourceIdentity{Kind: "release-id", Value: "serving-proposal", Immutable: true},
		requirements,
	)
	if err != nil {
		t.Fatalf("declared server identity must fit the locked public codec: %v", err)
	}
	var output bytes.Buffer
	if err := protocol.EncodeStartup(&output, startup); err != nil {
		t.Fatal(err)
	}
	var projected protocol.StartupIdentity
	if err := json.Unmarshal(output.Bytes(), &projected); err != nil || protocol.ValidateStartup(projected) != nil {
		t.Fatal("proposed declaration failed startup encoding/validation")
	}
	total := 0
	for _, requirement := range requirements {
		total += requirement.MaxBytes
	}
	if len(requirements) != 8 || total != 2097152 || total > protocol.MaxCredentialTotalBytes {
		t.Fatalf("serving declaration count/bytes = %d/%d", len(requirements), total)
	}
	for _, phase := range []string{"initial", "reconstruction"} {
		invocation := declarationInvocation(channelDescriptors(requirements))
		invocation.Phase = phase
		invocation.InvocationID = "declaration." + phase
		decoded, err := (&protocol.InvocationDecoder{}).Decode(bytes.NewReader(marshalDocument(t, invocation)))
		if err != nil {
			t.Fatalf("%s invocation: %v", phase, err)
		}
		if err := protocol.MatchCredentialRequirements(projected.CredentialChannelRequirements, decoded.CredentialChannelDescriptors); err != nil {
			t.Fatalf("%s declaration binding: %v", phase, err)
		}
	}
}

func TestGatewayServerStandardRejectsAmbiguousDeclarations(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]protocol.ChannelRequirement) []protocol.ChannelRequirement
	}{
		{"ninth channel", func(requirements []protocol.ChannelRequirement) []protocol.ChannelRequirement {
			extra := requirements[7]
			extra.ChannelID = "extra-server"
			return append(requirements, extra)
		}},
		{"duplicate channel", func(requirements []protocol.ChannelRequirement) []protocol.ChannelRequirement {
			requirements[7].ChannelID = requirements[4].ChannelID
			return requirements
		}},
		{"invented role", func(requirements []protocol.ChannelRequirement) []protocol.ChannelRequirement {
			requirements[7].Role = "gateway_server_credentials"
			return requirements
		}},
		{"invented actor", func(requirements []protocol.ChannelRequirement) []protocol.ChannelRequirement {
			requirements[7].Actor = protocol.NamedActor("gateway_server")
			return requirements
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := protocol.NewStartupIdentity(
				protocol.SourceIdentity{Kind: "release-id", Value: "proposal", Immutable: true},
				protocol.SourceIdentity{Kind: "release-id", Value: "proposal", Immutable: true},
				test.mutate(servingRequirements(t)),
			)
			if !errors.Is(err, protocol.ErrSchema) {
				t.Fatalf("invalid declaration error = %v", err)
			}
		})
	}
}

func TestGatewayServerStandardRequiresExactDescriptorBinding(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]protocol.ChannelDescriptor) []protocol.ChannelDescriptor
	}{
		{"missing server", func(d []protocol.ChannelDescriptor) []protocol.ChannelDescriptor { return d[:7] }},
		{"controller actor substitution", func(d []protocol.ChannelDescriptor) []protocol.ChannelDescriptor {
			d[7].Actor = protocol.NamedActor("controller_a")
			return d
		}},
		{"trust role substitution", func(d []protocol.ChannelDescriptor) []protocol.ChannelDescriptor {
			d[7].Role = "gateway_trust"
			return d
		}},
		{"client payload type substitution", func(d []protocol.ChannelDescriptor) []protocol.ChannelDescriptor {
			d[7].MediaType = credentials.GatewayCredentialMediaType
			return d
		}},
		{"limit change", func(d []protocol.ChannelDescriptor) []protocol.ChannelDescriptor {
			d[7].MaxBytes++
			return d
		}},
		{"descriptor alias", func(d []protocol.ChannelDescriptor) []protocol.ChannelDescriptor {
			d[7].FileDescriptor = d[0].FileDescriptor
			return d
		}},
		{"order change", func(d []protocol.ChannelDescriptor) []protocol.ChannelDescriptor {
			d[7], d[6] = d[6], d[7]
			return d
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			requirements := servingRequirements(t)
			if err := protocol.MatchCredentialRequirements(requirements, test.mutate(channelDescriptors(requirements))); !errors.Is(err, protocol.ErrSchema) {
				t.Fatalf("ambiguous delivery error = %v", err)
			}
		})
	}
}

func TestCurrentBootstrapRejectsLegacyChannelSets(t *testing.T) {
	current := credentials.Requirements()
	if len(current) != 8 {
		t.Fatal("e1.5e.2 must activate the serving declaration")
	}
	descriptors := channelDescriptors(servingRequirements(t))
	if err := protocol.MatchCredentialRequirements(current[:7], descriptors); !errors.Is(err, protocol.ErrSchema) {
		t.Fatalf("undeclared eighth channel on legacy public declaration error = %v", err)
	}
	if _, err := callercontrol.NewRequest(declarationInvocation(descriptors[:7]), descriptors[:7], time.Now().Add(time.Minute).UTC()); !errors.Is(err, callercontrol.ErrControlRequest) {
		t.Fatalf("missing server on active caller control error = %v", err)
	}
	if _, err := gatewaycontrol.NewRequest("initial", "https://gateway.example/tunnel", descriptors[4:7]); !errors.Is(err, gatewaycontrol.ErrControlRequest) {
		t.Fatalf("legacy client channel set on server Gateway control error = %v", err)
	}
}

func TestGatewayServerStandardKeepsSecretsAndCorrelationOutOfControl(t *testing.T) {
	descriptors := channelDescriptors(credentials.Requirements())
	invocation := declarationInvocation(descriptors)
	callerRequest, err := callercontrol.NewRequest(invocation, descriptors, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatal(err)
	}
	gatewayRequest, err := gatewaycontrol.NewRequest("initial", invocation.GatewayProbeEndpoint, channelDescriptors(credentials.GatewayRequirements()))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"private_key_pem", "certificate_chain_pem", "client_ca_certificates_pem", "server_credentials",
		"sandbox_id", "operation_id", "attempt_id", "idempotency_key", "fencing_token", "runtime_session_id", "handoff_reference",
	} {
		t.Run(field, func(t *testing.T) {
			// Marker bytes are not a real credential. No FD is opened by any decoder.
			if _, err := (&protocol.InvocationDecoder{}).Decode(bytes.NewReader(withUnknownMember(t, invocation, field))); !errors.Is(err, protocol.ErrSchema) {
				t.Fatalf("public control accepted %s: %v", field, err)
			}
			if _, err := callercontrol.DecodeRequest(bytes.NewReader(withUnknownMember(t, callerRequest, field))); !errors.Is(err, callercontrol.ErrControlRequest) {
				t.Fatalf("caller control accepted %s: %v", field, err)
			}
			if _, err := gatewaycontrol.DecodeRequest(bytes.NewReader(withUnknownMember(t, gatewayRequest, field))); !errors.Is(err, gatewaycontrol.ErrControlRequest) {
				t.Fatalf("Gateway control accepted %s: %v", field, err)
			}
		})
	}
}

func servingRequirements(t *testing.T) []protocol.ChannelRequirement {
	t.Helper()
	document, err := os.ReadFile(filepath.Join("..", "..", "docs", "protocol", "gateway-server-channel-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var server protocol.ChannelRequirement
	if err := decoder.Decode(&server); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatal("declaration fixture contains trailing data")
	}
	if server.ChannelID != "gateway-server" || server.Role != "gateway_credentials" || !server.Actor.IsNull() ||
		server.MediaType != "application/vnd.shell-echo.sandbox-gateway-server-credentials-v1+json" || server.MaxBytes != 262144 {
		t.Fatal("server declaration does not match the e1.5e.1 decision")
	}
	requirements := credentials.Requirements()
	if !bytes.Equal(marshalDocument(t, requirements[7]), marshalDocument(t, server)) {
		t.Fatal("active declaration differs from the reviewed standard")
	}
	return requirements
}

func channelDescriptors(requirements []protocol.ChannelRequirement) []protocol.ChannelDescriptor {
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	for index, requirement := range requirements {
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index,
		})
	}
	return descriptors
}

func declarationInvocation(descriptors []protocol.ChannelDescriptor) protocol.Invocation {
	return protocol.Invocation{
		FormatVersion: protocol.FormatVersion, ProtocolID: protocol.ProtocolID, ProtocolVersion: protocol.ProtocolVersion,
		MessageType: "invocation", InvocationID: "declaration.initial", Phase: "initial", ProfilePath: "/qualification/profile.json",
		ProviderOrigin: "https://provider.example", GatewayProbeEndpoint: "https://gateway.example/tunnel",
		CallerStateRoot: "/caller/state", CredentialChannelDescriptors: descriptors,
	}
}

func marshalDocument(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func withUnknownMember(t *testing.T, value any, field string) []byte {
	t.Helper()
	var document map[string]json.RawMessage
	if err := json.Unmarshal(marshalDocument(t, value), &document); err != nil {
		t.Fatal(err)
	}
	document[field] = json.RawMessage(`"synthetic-forbidden-value"`)
	return marshalDocument(t, document)
}
