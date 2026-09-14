package credentials

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func TestRequirementsAreAValidFixedStartupDeclaration(t *testing.T) {
	requirements := Requirements()
	startup, err := protocol.NewStartupIdentity(
		protocol.SourceIdentity{Kind: "release-id", Value: "caller-v1", Immutable: true},
		protocol.SourceIdentity{Kind: "release-id", Value: "adapter-v1", Immutable: true},
		requirements,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(startup.CredentialChannelRequirements) != 8 {
		t.Fatalf("credential requirement count = %d", len(startup.CredentialChannelRequirements))
	}
	if startup.CredentialChannelRequirements[0].Role != "provider_credentials" || startup.CredentialChannelRequirements[3].Role != "provider_trust" || startup.CredentialChannelRequirements[6].Role != "gateway_trust" {
		t.Fatalf("unexpected fixed credential order: %#v", startup.CredentialChannelRequirements)
	}
	startup.CredentialChannelRequirements[0].ChannelID = "mutated"
	if Requirements()[0].ChannelID != "provider-controller-a" {
		t.Fatal("Requirements returned shared mutable state")
	}
}

func TestGatewayRequirementsAreAnIndependentExactSubset(t *testing.T) {
	requirements := GatewayRequirements()
	if len(requirements) != 2 || requirements[0].ChannelID != "gateway-server" || requirements[1].ChannelID != "gateway-trust" {
		t.Fatalf("Gateway requirements = %#v", requirements)
	}
	requirements[0].ChannelID = "mutated"
	if GatewayRequirements()[0].ChannelID != "gateway-server" || Requirements()[7].ChannelID != "gateway-server" {
		t.Fatal("GatewayRequirements returned shared mutable state")
	}
}

func TestReaderConsumesExactAnonymousPipesThroughEOFAndDestroysBytes(t *testing.T) {
	requirements := Requirements()
	payloads := make(map[string][]byte, len(requirements))
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	readers := make([]*os.File, 0, len(requirements))
	writers := make([]*os.File, 0, len(requirements))
	for index, requirement := range requirements {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		readers = append(readers, reader)
		writers = append(writers, writer)
		payload := []byte{byte(index + 1), 0, '\n', byte(0xff - index)}
		payloads[requirement.ChannelID] = payload
		descriptors = append(descriptors, descriptorFor(requirement, int(reader.Fd())))
	}
	for index, writer := range writers {
		payload := payloads[requirements[index].ChannelID]
		go func() {
			_, _ = writer.Write(payload)
			_ = writer.Close()
		}()
	}

	reader := NewReader(requirements)
	bundle, err := reader.Read(descriptors)
	for _, pipeReader := range readers {
		_ = pipeReader.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()
	if bundle.TotalBytes() != len(requirements)*4 {
		t.Fatalf("credential total = %d", bundle.TotalBytes())
	}
	var retained []byte
	if err := bundle.Use("provider-controller-a", func(payload []byte) error {
		if !bytes.Equal(payload, payloads["provider-controller-a"]) {
			t.Fatalf("provider payload = %v", payload)
		}
		retained = payload
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bundle.Destroy()
	if !bytes.Equal(retained, make([]byte, len(retained))) || bundle.TotalBytes() != 0 {
		t.Fatal("Destroy did not clear bundle-owned credential bytes")
	}
	if err := bundle.Use("provider-controller-a", func([]byte) error { return nil }); !errors.Is(err, ErrUnknownChannel) {
		t.Fatalf("Use after Destroy error = %v", err)
	}
	if _, err := reader.Read(descriptors); !errors.Is(err, ErrReaderConsumed) {
		t.Fatalf("second Read error = %v", err)
	}
}

func TestReaderRejectsMismatchBeforeOpeningDescriptors(t *testing.T) {
	requirement := Requirements()[0]
	descriptor := descriptorFor(requirement, 3)
	descriptor.ChannelID = "unexpected-channel"
	if _, err := NewReader([]protocol.ChannelRequirement{requirement}).Read([]protocol.ChannelDescriptor{descriptor}); !errors.Is(err, ErrDescriptorMismatch) {
		t.Fatalf("Read mismatch error = %v", err)
	}
}

func TestReaderRejectsRegularFileAndOversizedPipe(t *testing.T) {
	requirement := Requirements()[7] // The active server-secret channel.

	regular, err := os.CreateTemp(t.TempDir(), "credential")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReader([]protocol.ChannelRequirement{requirement}).Read([]protocol.ChannelDescriptor{descriptorFor(requirement, int(regular.Fd()))}); !errors.Is(err, ErrNotPipe) {
		t.Fatalf("regular-file Read error = %v", err)
	}
	_ = regular.Close()

	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = pipeWriter.Write(bytes.Repeat([]byte{'x'}, requirement.MaxBytes+1))
		_ = pipeWriter.Close()
	}()
	_, err = NewReader([]protocol.ChannelRequirement{requirement}).Read([]protocol.ChannelDescriptor{descriptorFor(requirement, int(pipeReader.Fd()))})
	_ = pipeReader.Close()
	if !errors.Is(err, ErrChannelLimit) {
		t.Fatalf("oversized Read error = %v", err)
	}
}

func descriptorFor(requirement protocol.ChannelRequirement, fileDescriptor int) protocol.ChannelDescriptor {
	return protocol.ChannelDescriptor{
		ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
		MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: fileDescriptor,
	}
}
