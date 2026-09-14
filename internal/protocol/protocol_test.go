package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/authority"
)

func TestProtocolConstantsMatchAuthorityLock(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", authority.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	var lock authority.Lock
	if err := json.Unmarshal(document, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Source.Revision != ContractRevision || lock.Source.ContractTree != ContractTree ||
		lock.Contract.Namespace != "urn:shell-echo:sandbox-runtime:provider-v1" || lock.Contract.Version != "1.0.0" ||
		lock.QualificationProfile.ProfileID != ProfileID || lock.QualificationProfile.ProfileVersion != ProfileVersion || lock.QualificationProfile.ProfileDigest != ProfileDigest ||
		lock.AdapterProtocol.ProtocolID != ProtocolID || lock.AdapterProtocol.ProtocolVersion != ProtocolVersion || lock.AdapterProtocol.SchemaDigest != ProtocolSchemaDigest || lock.AdapterProtocol.SemanticsDigest != ProtocolSemanticsDigest {
		t.Fatal("compiled protocol constants do not match authority.lock.json")
	}
	wantPhases := []authority.PhaseIdentity{
		{PhaseID: "initial", CaseIDs: initialCaseIDs},
		{PhaseID: "reconstruction", CaseIDs: reconstructionCaseIDs},
	}
	if !reflect.DeepEqual(lock.QualificationProfile.Phases, wantPhases) {
		t.Fatal("compiled phase/case order does not match authority.lock.json")
	}
}

func TestStartupIdentityAndEncoding(t *testing.T) {
	startup, err := NewStartupIdentity(testRelease("caller-v1"), testRelease("adapter-v1"), testRequirements())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := EncodeStartup(&output, startup); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(output.Bytes(), []byte{'\n'}) != 1 || output.Bytes()[output.Len()-1] != '\n' || bytes.Contains(output.Bytes(), []byte{'\r'}) {
		t.Fatalf("startup output framing is invalid: %q", output.Bytes())
	}
	if !bytes.Contains(output.Bytes(), []byte(ProtocolSchemaDigest)) || !bytes.Contains(output.Bytes(), []byte(ProtocolSemanticsDigest)) {
		t.Fatal("startup output does not embed locked protocol authority")
	}
}

func TestStartupRejectsInvalidAuthorityAndRequirements(t *testing.T) {
	startup, err := NewStartupIdentity(testRelease("caller-v1"), testRelease("adapter-v1"), testRequirements())
	if err != nil {
		t.Fatal(err)
	}
	startup.ProtocolSchemaDigest = "sha256:" + strings.Repeat("0", 64)
	if err := ValidateStartup(startup); !errors.Is(err, ErrSchema) {
		t.Fatalf("ValidateStartup(authority drift) error = %v", err)
	}
	startup.ProtocolSchemaDigest = ProtocolSchemaDigest
	startup.CredentialChannelRequirements = append(startup.CredentialChannelRequirements, startup.CredentialChannelRequirements[0])
	if err := ValidateStartup(startup); !errors.Is(err, ErrSchema) {
		t.Fatalf("ValidateStartup(duplicate channel) error = %v", err)
	}
}

func TestInvocationDecoderAcceptsOneStrictDocumentThroughEOF(t *testing.T) {
	document := testInvocationJSON(t, testInvocation())
	decoder := &InvocationDecoder{}
	invocation, err := decoder.Decode(bytes.NewReader(append([]byte(" \n"), append(document, []byte("\n ")...)...)))
	if err != nil {
		t.Fatal(err)
	}
	if invocation.InvocationID != "run.initial" || invocation.Phase != "initial" {
		t.Fatalf("decoded invocation = %#v", invocation)
	}
	if _, err := decoder.Decode(bytes.NewReader(document)); !errors.Is(err, ErrDecoderConsumed) {
		t.Fatalf("second Decode() error = %v, want ErrDecoderConsumed", err)
	}
}

func TestInvocationDecoderFailureClasses(t *testing.T) {
	valid := string(testInvocationJSON(t, testInvocation()))
	tests := []struct {
		name   string
		reader io.Reader
		want   error
	}{
		{name: "empty", reader: strings.NewReader(""), want: ErrInvalidJSON},
		{name: "oversized", reader: strings.NewReader(strings.Repeat(" ", MaxInvocationBytes+1)), want: ErrInvocationByteLimit},
		{name: "stream", reader: failingReader{}, want: ErrStreamIO},
		{name: "duplicate", reader: strings.NewReader(strings.Replace(valid, `"format_version":1`, `"format_version":1,"format_version":1`, 1)), want: ErrInvalidJSON},
		{name: "invalid surrogate", reader: strings.NewReader(strings.Replace(valid, `run.initial`, `run.\uD800`, 1)), want: ErrInvalidJSON},
		{name: "multiple documents", reader: strings.NewReader(valid + `{}`), want: ErrInvalidJSON},
		{name: "unknown field", reader: strings.NewReader(strings.Replace(valid, `"caller_state_root"`, `"unknown":true,"caller_state_root"`, 1)), want: ErrSchema},
		{name: "unknown message", reader: strings.NewReader(strings.Replace(valid, `"message_type":"invocation"`, `"message_type":"unknown"`, 1)), want: ErrSchema},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (&InvocationDecoder{}).Decode(test.reader)
			if !errors.Is(err, test.want) {
				t.Fatalf("Decode() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestInvocationDecoderRejectsValidStartupAsWrongDirection(t *testing.T) {
	startup, err := NewStartupIdentity(testRelease("caller-v1"), testRelease("adapter-v1"), testRequirements())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := EncodeStartup(&output, startup); err != nil {
		t.Fatal(err)
	}
	_, err = (&InvocationDecoder{}).Decode(bytes.NewReader(output.Bytes()))
	if !errors.Is(err, ErrMessageDirection) {
		t.Fatalf("Decode(startup) error = %v, want ErrMessageDirection", err)
	}
}

func TestInvocationLocationProfiles(t *testing.T) {
	validOrigins := []string{"https://provider.example", "https://127.0.0.1:8443", "https://[2001:db8::1]:8443"}
	for _, value := range validOrigins {
		if !validProviderOrigin(value) {
			t.Errorf("validProviderOrigin(%q) = false", value)
		}
	}
	invalidOrigins := []string{"http://provider.example", "https://Provider.example", "https://provider.example/", "https://user@provider.example", "https://provider.example:443", "https://provider.example:0443", "https://provider.1", "https://2130706433", "https://127.0.0.01", "https://[::ffff:127.0.0.1]"}
	for _, value := range invalidOrigins {
		if validProviderOrigin(value) {
			t.Errorf("validProviderOrigin(%q) = true", value)
		}
	}
	validEndpoints := []string{"https://gateway.example/probe", "wss://gateway.example/a:b/c_d", "https://[2001:db8::1]/"}
	for _, value := range validEndpoints {
		if !validGatewayEndpoint(value) {
			t.Errorf("validGatewayEndpoint(%q) = false", value)
		}
	}
	invalidEndpoints := []string{"https://gateway.example", "ws://gateway.example/probe", "https://gateway.example/a/../b", "https://gateway.example/a/", "https://gateway.example/%61", "https://gateway.example/probe?q=1"}
	for _, value := range invalidEndpoints {
		if validGatewayEndpoint(value) {
			t.Errorf("validGatewayEndpoint(%q) = true", value)
		}
		if err := ValidateGatewayEndpoint(value); !errors.Is(err, ErrSchema) {
			t.Errorf("ValidateGatewayEndpoint(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"/profile.json", "/a_b/c-d.json"} {
		if !validAbsoluteCleanPOSIXPath(value) {
			t.Errorf("validAbsoluteCleanPOSIXPath(%q) = false", value)
		}
	}
	for _, value := range []string{"/", "relative", "/a/../b", "/a//b", "/a/", "/a b"} {
		if validAbsoluteCleanPOSIXPath(value) {
			t.Errorf("validAbsoluteCleanPOSIXPath(%q) = true", value)
		}
	}
}

func TestCredentialRequirementMatching(t *testing.T) {
	requirements := testRequirements()
	descriptors := testDescriptors()
	if err := MatchCredentialRequirements(requirements, descriptors); err != nil {
		t.Fatal(err)
	}
	descriptors[1].FileDescriptor = descriptors[0].FileDescriptor
	if err := MatchCredentialRequirements(requirements, descriptors); !errors.Is(err, ErrSchema) {
		t.Fatalf("duplicate file descriptor error = %v", err)
	}
	descriptors = testDescriptors()
	descriptors[0].MediaType = "application/pem"
	if err := MatchCredentialRequirements(requirements, descriptors); !errors.Is(err, ErrSchema) {
		t.Fatalf("descriptor mismatch error = %v", err)
	}
}

func TestSourceIdentityShapes(t *testing.T) {
	valid := []SourceIdentity{
		{Kind: "source-revision", Value: strings.Repeat("a", 40), Immutable: true},
		{Kind: "build-attestation", Value: "sha256:" + strings.Repeat("b", 64), Immutable: true},
		{Kind: "release-id", Value: "caller-v1.0.0", Immutable: true},
	}
	for _, identity := range valid {
		if !validSourceIdentity(identity) {
			t.Errorf("validSourceIdentity(%#v) = false", identity)
		}
	}
	invalid := []SourceIdentity{
		{Kind: "source-revision", Value: "abcdef1", Immutable: true},
		{Kind: "release-id", Value: "has space", Immutable: true},
		{Kind: "release-id", Value: "caller-v1", Immutable: false},
	}
	for _, identity := range invalid {
		if validSourceIdentity(identity) {
			t.Errorf("validSourceIdentity(%#v) = true", identity)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic read failure")
}

func testRelease(value string) SourceIdentity {
	return SourceIdentity{Kind: "release-id", Value: value, Immutable: true}
}

func testRequirements() []ChannelRequirement {
	return []ChannelRequirement{
		{ChannelID: "provider-credentials-a", Role: "provider_credentials", Actor: NamedActor("controller_a"), MediaType: "application/json", MaxBytes: 4096},
		{ChannelID: "provider-trust", Role: "provider_trust", Actor: NullActor(), MediaType: "application/pem-certificate-chain", MaxBytes: 4096},
	}
}

func testDescriptors() []ChannelDescriptor {
	return []ChannelDescriptor{
		{ChannelID: "provider-credentials-a", Role: "provider_credentials", Actor: NamedActor("controller_a"), MediaType: "application/json", MaxBytes: 4096, FileDescriptor: 3},
		{ChannelID: "provider-trust", Role: "provider_trust", Actor: NullActor(), MediaType: "application/pem-certificate-chain", MaxBytes: 4096, FileDescriptor: 4},
	}
}

func testInvocation() Invocation {
	return Invocation{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion, MessageType: "invocation",
		InvocationID: "run.initial", Phase: "initial", ProfilePath: "/qualification/profile.json", ProviderOrigin: "https://provider.example:8443",
		GatewayProbeEndpoint: "wss://gateway.example:9443/probe", CredentialChannelDescriptors: testDescriptors(), CallerStateRoot: "/state/caller",
	}
}

func testInvocationJSON(t *testing.T, invocation Invocation) []byte {
	t.Helper()
	document, err := jsonMarshal(invocation)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func jsonMarshal(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}
