// Package protocol implements the caller side of the locked public
// sandbox-runtime external-caller adapter protocol. It has no dependency on
// Provider implementation code.
package protocol

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const (
	FormatVersion   = 1
	ProtocolID      = "sandbox-runtime-external-caller-adapter-v1"
	ProtocolVersion = "1.0.0"

	ProtocolSchemaDigest    = "sha256:0c3783bb4014d1e04d61f1987fa77f0c27a158c65552704f69f3f340bbaa6b20"
	ProtocolSemanticsDigest = "sha256:deeef0edf5cc63705d84e45a8f64f657e97346a3616259c2d8b718b1e38b0bd5"
	ContractRevision        = "9206e601f75a54db0b66969239d7e8cc5bcc8af9"
	ContractTree            = "c5e4221f2ceaaaad53c8038e1ebaacfe0c5a4daf"
	ProfileID               = "sandbox-runtime-external-caller-coding-shell-v1"
	ProfileVersion          = "1.0.0"
	ProfileDigest           = "sha256:baee769c0acc395448af61faef99cd97fbb63ccb83c70eb51915952be519991a"

	MaxInvocationBytes          = 32 << 10
	MaxAdapterOutputRecordBytes = 64 << 10
	MaxCredentialChannels       = 8
	MaxCredentialChannelBytes   = 1 << 20
	MaxCredentialTotalBytes     = 4 << 20
)

var (
	ErrInvocationByteLimit = errors.New("adapter invocation byte limit exceeded")
	ErrStreamIO            = errors.New("adapter protocol stream failure")
	ErrInvalidJSON         = errors.New("adapter protocol JSON encoding or structure is invalid")
	ErrSchema              = errors.New("adapter protocol message does not match the locked schema")
	ErrMessageDirection    = errors.New("adapter protocol message direction is invalid")
	ErrDecoderConsumed     = errors.New("adapter invocation decoder is already consumed")
)

var (
	idPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]*$`)
	mediaTypePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)
	hexRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	releasePattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]*$`)
)

type SourceIdentity struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Immutable bool   `json:"immutable"`
}

// NullableActor preserves the schema distinction between a required null
// actor and an omitted actor.
type NullableActor struct {
	value   string
	null    bool
	present bool
}

func NullActor() NullableActor {
	return NullableActor{null: true, present: true}
}

func NamedActor(value string) NullableActor {
	return NullableActor{value: value, present: true}
}

func (a NullableActor) Value() (string, bool) {
	return a.value, a.present && !a.null
}

func (a NullableActor) IsNull() bool {
	return a.present && a.null
}

func (a NullableActor) MarshalJSON() ([]byte, error) {
	if !a.present {
		return nil, errors.New("actor is absent")
	}
	if a.null {
		return []byte("null"), nil
	}
	return json.Marshal(a.value)
}

func (a *NullableActor) UnmarshalJSON(document []byte) error {
	a.present = true
	if string(document) == "null" {
		a.value = ""
		a.null = true
		return nil
	}
	var value string
	if err := json.Unmarshal(document, &value); err != nil {
		return err
	}
	a.value = value
	a.null = false
	return nil
}

type ChannelRequirement struct {
	ChannelID string        `json:"channel_id"`
	Role      string        `json:"role"`
	Actor     NullableActor `json:"actor"`
	MediaType string        `json:"media_type"`
	MaxBytes  int           `json:"max_bytes"`
}

type ChannelDescriptor struct {
	ChannelID      string        `json:"channel_id"`
	Role           string        `json:"role"`
	Actor          NullableActor `json:"actor"`
	MediaType      string        `json:"media_type"`
	MaxBytes       int           `json:"max_bytes"`
	FileDescriptor int           `json:"file_descriptor"`
}

type StartupIdentity struct {
	FormatVersion                   int                  `json:"format_version"`
	ProtocolID                      string               `json:"protocol_id"`
	ProtocolVersion                 string               `json:"protocol_version"`
	MessageType                     string               `json:"message_type"`
	Sequence                        int                  `json:"sequence"`
	ProtocolSchemaDigest            string               `json:"protocol_schema_digest"`
	ProtocolSemanticsDigest         string               `json:"protocol_semantics_digest"`
	CallerReleaseIdentity           SourceIdentity       `json:"caller_release_identity"`
	AdapterReleaseIdentity          SourceIdentity       `json:"adapter_release_identity"`
	ContractRevision                string               `json:"contract_revision"`
	ContractTree                    string               `json:"contract_tree"`
	ProfileID                       string               `json:"profile_id"`
	ProfileVersion                  string               `json:"profile_version"`
	ProfileDigest                   string               `json:"profile_digest"`
	ExpectedValuesInjectedByHarness bool                 `json:"expected_values_injected_by_harness"`
	CredentialChannelRequirements   []ChannelRequirement `json:"credential_channel_requirements"`
}

type Invocation struct {
	FormatVersion                int                 `json:"format_version"`
	ProtocolID                   string              `json:"protocol_id"`
	ProtocolVersion              string              `json:"protocol_version"`
	MessageType                  string              `json:"message_type"`
	InvocationID                 string              `json:"invocation_id"`
	Phase                        string              `json:"phase"`
	ProfilePath                  string              `json:"profile_path"`
	ProviderOrigin               string              `json:"provider_origin"`
	GatewayProbeEndpoint         string              `json:"gateway_probe_endpoint"`
	CredentialChannelDescriptors []ChannelDescriptor `json:"credential_channel_descriptors"`
	CallerStateRoot              string              `json:"caller_state_root"`
}

func NewStartupIdentity(callerRelease, adapterRelease SourceIdentity, requirements []ChannelRequirement) (StartupIdentity, error) {
	startup := StartupIdentity{
		FormatVersion:                   FormatVersion,
		ProtocolID:                      ProtocolID,
		ProtocolVersion:                 ProtocolVersion,
		MessageType:                     "startup_identity",
		Sequence:                        0,
		ProtocolSchemaDigest:            ProtocolSchemaDigest,
		ProtocolSemanticsDigest:         ProtocolSemanticsDigest,
		CallerReleaseIdentity:           callerRelease,
		AdapterReleaseIdentity:          adapterRelease,
		ContractRevision:                ContractRevision,
		ContractTree:                    ContractTree,
		ProfileID:                       ProfileID,
		ProfileVersion:                  ProfileVersion,
		ProfileDigest:                   ProfileDigest,
		ExpectedValuesInjectedByHarness: false,
		CredentialChannelRequirements:   append([]ChannelRequirement(nil), requirements...),
	}
	if err := ValidateStartup(startup); err != nil {
		return StartupIdentity{}, err
	}
	return startup, nil
}

func ValidateStartup(startup StartupIdentity) error {
	if startup.FormatVersion != FormatVersion || startup.ProtocolID != ProtocolID || startup.ProtocolVersion != ProtocolVersion || startup.MessageType != "startup_identity" || startup.Sequence != 0 ||
		startup.ProtocolSchemaDigest != ProtocolSchemaDigest || startup.ProtocolSemanticsDigest != ProtocolSemanticsDigest || startup.ContractRevision != ContractRevision || startup.ContractTree != ContractTree ||
		startup.ProfileID != ProfileID || startup.ProfileVersion != ProfileVersion || startup.ProfileDigest != ProfileDigest || startup.ExpectedValuesInjectedByHarness {
		return ErrSchema
	}
	if !validSourceIdentity(startup.CallerReleaseIdentity) || !validSourceIdentity(startup.AdapterReleaseIdentity) || !validRequirements(startup.CredentialChannelRequirements) {
		return ErrSchema
	}
	return nil
}

// EncodeStartup writes exactly one schema-valid JSON record followed by one LF.
func EncodeStartup(writer io.Writer, startup StartupIdentity) error {
	return NewOutputEncoder(writer).Write(startup)
}

type InvocationDecoder struct {
	consumed bool
}

// Decode consumes one bounded JSON document through EOF. The decoder is
// one-shot even after failure, matching one fresh adapter process per phase.
func (d *InvocationDecoder) Decode(reader io.Reader) (Invocation, error) {
	if d.consumed {
		return Invocation{}, ErrDecoderConsumed
	}
	d.consumed = true
	if reader == nil {
		return Invocation{}, ErrStreamIO
	}
	document, err := io.ReadAll(io.LimitReader(reader, MaxInvocationBytes+1))
	if len(document) > MaxInvocationBytes {
		return Invocation{}, ErrInvocationByteLimit
	}
	if err != nil {
		return Invocation{}, ErrStreamIO
	}
	if err := validateJSONDocument(document); err != nil {
		return Invocation{}, ErrInvalidJSON
	}

	messageType, err := messageType(document)
	if err != nil {
		return Invocation{}, ErrSchema
	}
	if messageType != "invocation" {
		if validOutputDocument(document, messageType) {
			return Invocation{}, ErrMessageDirection
		}
		return Invocation{}, ErrSchema
	}

	var invocation Invocation
	if !hasExactKeys(document, invocationKeys) || decodeStrict(document, &invocation) != nil || ValidateInvocation(invocation) != nil {
		return Invocation{}, ErrSchema
	}
	return invocation, nil
}

func ValidateInvocation(invocation Invocation) error {
	if invocation.FormatVersion != FormatVersion || invocation.ProtocolID != ProtocolID || invocation.ProtocolVersion != ProtocolVersion || invocation.MessageType != "invocation" ||
		!validID(invocation.InvocationID) || (invocation.Phase != "initial" && invocation.Phase != "reconstruction") ||
		!validAbsoluteCleanPOSIXPath(invocation.ProfilePath) || !validProviderOrigin(invocation.ProviderOrigin) || !validGatewayEndpoint(invocation.GatewayProbeEndpoint) ||
		!validAbsoluteCleanPOSIXPath(invocation.CallerStateRoot) || !validDescriptors(invocation.CredentialChannelDescriptors) {
		return ErrSchema
	}
	return nil
}

// ValidateGatewayEndpoint exposes the locked canonical HTTPS/WSS endpoint
// profile to candidate-owned Gateway components without widening the wire DTO.
func ValidateGatewayEndpoint(value string) error {
	if !validGatewayEndpoint(value) {
		return ErrSchema
	}
	return nil
}

// ValidateProviderOrigin exposes the locked canonical HTTPS origin profile to
// candidate-private process-control codecs.
func ValidateProviderOrigin(value string) error {
	if !validProviderOrigin(value) {
		return ErrSchema
	}
	return nil
}

// ValidateAbsoluteCleanPOSIXPath exposes the locked portable path shape to
// candidate-private process-control codecs. Filesystem identity and permission
// checks remain the responsibility of the component that opens the path.
func ValidateAbsoluteCleanPOSIXPath(value string) error {
	if !validAbsoluteCleanPOSIXPath(value) {
		return ErrSchema
	}
	return nil
}

// MatchCredentialRequirements checks the ordered descriptor projection. File
// descriptors are transport bindings and therefore have no startup counterpart.
func MatchCredentialRequirements(requirements []ChannelRequirement, descriptors []ChannelDescriptor) error {
	if !validRequirements(requirements) || !validDescriptors(descriptors) || len(requirements) != len(descriptors) {
		return ErrSchema
	}
	for index, requirement := range requirements {
		descriptor := descriptors[index]
		if requirement.ChannelID != descriptor.ChannelID || requirement.Role != descriptor.Role || requirement.MediaType != descriptor.MediaType || requirement.MaxBytes != descriptor.MaxBytes || !equalActor(requirement.Actor, descriptor.Actor) {
			return ErrSchema
		}
	}
	return nil
}

func validSourceIdentity(identity SourceIdentity) bool {
	if !identity.Immutable {
		return false
	}
	switch identity.Kind {
	case "source-revision":
		return hexRevisionPattern.MatchString(identity.Value)
	case "oci-digest", "build-attestation":
		return digestPattern.MatchString(identity.Value)
	case "release-id", "operator-release":
		return len(identity.Value) <= 128 && releasePattern.MatchString(identity.Value)
	default:
		return false
	}
}

func validRequirements(requirements []ChannelRequirement) bool {
	if len(requirements) < 1 || len(requirements) > MaxCredentialChannels {
		return false
	}
	seen := make(map[string]struct{}, len(requirements))
	total := 0
	for _, requirement := range requirements {
		if !validID(requirement.ChannelID) || !validRole(requirement.Role) || !validActor(requirement.Actor) || !validMediaType(requirement.MediaType) || requirement.MaxBytes < 1 || requirement.MaxBytes > MaxCredentialChannelBytes {
			return false
		}
		if _, duplicate := seen[requirement.ChannelID]; duplicate {
			return false
		}
		seen[requirement.ChannelID] = struct{}{}
		total += requirement.MaxBytes
	}
	return total <= MaxCredentialTotalBytes
}

func validDescriptors(descriptors []ChannelDescriptor) bool {
	if len(descriptors) < 1 || len(descriptors) > MaxCredentialChannels {
		return false
	}
	seenIDs := make(map[string]struct{}, len(descriptors))
	seenFDs := make(map[int]struct{}, len(descriptors))
	total := 0
	for _, descriptor := range descriptors {
		if !validID(descriptor.ChannelID) || !validRole(descriptor.Role) || !validActor(descriptor.Actor) || !validMediaType(descriptor.MediaType) || descriptor.MaxBytes < 1 || descriptor.MaxBytes > MaxCredentialChannelBytes || descriptor.FileDescriptor < 3 || descriptor.FileDescriptor > 1024 {
			return false
		}
		if _, duplicate := seenIDs[descriptor.ChannelID]; duplicate {
			return false
		}
		if _, duplicate := seenFDs[descriptor.FileDescriptor]; duplicate {
			return false
		}
		seenIDs[descriptor.ChannelID] = struct{}{}
		seenFDs[descriptor.FileDescriptor] = struct{}{}
		total += descriptor.MaxBytes
	}
	return total <= MaxCredentialTotalBytes
}

func validID(value string) bool {
	return len(value) >= 1 && len(value) <= 200 && idPattern.MatchString(value)
}

func validRole(value string) bool {
	switch value {
	case "provider_credentials", "provider_trust", "gateway_credentials", "gateway_trust":
		return true
	default:
		return false
	}
}

func validActor(actor NullableActor) bool {
	if actor.IsNull() {
		return true
	}
	value, ok := actor.Value()
	if !ok {
		return false
	}
	switch value {
	case "controller_a", "controller_b", "same_ca_unadmitted":
		return true
	default:
		return false
	}
}

func equalActor(left, right NullableActor) bool {
	if left.IsNull() || right.IsNull() {
		return left.IsNull() && right.IsNull()
	}
	leftValue, leftOK := left.Value()
	rightValue, rightOK := right.Value()
	return leftOK && rightOK && leftValue == rightValue
}

func validMediaType(value string) bool {
	return len(value) >= 3 && len(value) <= 127 && mediaTypePattern.MatchString(value)
}

func messageType(document []byte) (string, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(document, &envelope); err != nil {
		return "", err
	}
	raw, ok := envelope["message_type"]
	if !ok {
		return "", errors.New("message type is absent")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", errors.New("message type is invalid")
	}
	return value, nil
}

var startupKeys = []string{
	"format_version", "protocol_id", "protocol_version", "message_type", "sequence",
	"protocol_schema_digest", "protocol_semantics_digest", "caller_release_identity",
	"adapter_release_identity", "contract_revision", "contract_tree", "profile_id",
	"profile_version", "profile_digest", "expected_values_injected_by_harness",
	"credential_channel_requirements",
}

var invocationKeys = []string{
	"format_version", "protocol_id", "protocol_version", "message_type", "invocation_id",
	"phase", "profile_path", "provider_origin", "gateway_probe_endpoint",
	"credential_channel_descriptors", "caller_state_root",
}

func hasExactKeys(document []byte, expected []string) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil || len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}
