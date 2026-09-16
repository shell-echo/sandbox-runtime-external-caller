// Package scenariocontrol defines the caller-private, credential-free
// adapter-to-caller protocol for a fixed ordered prefix of explicitly authorized
// scenarios. It is not Provider wire API, public adapter output, or
// qualification evidence.
package scenariocontrol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const (
	FormatVersion                   = 1
	ProtocolID                      = "sandbox-runtime-external-caller-private-scenario-v20"
	ProtocolVersion                 = "20.0.0"
	CapabilityCaseID                = "initial.locked-capability-discovery"
	LifecycleCaseID                 = "initial.protected-lifecycle-create"
	ReplayCaseID                    = "initial.replay-semantics"
	LifecycleCompletionCaseID       = "initial.lifecycle-completion-and-status"
	ExecResultUsageCaseID           = "initial.exec-result-and-usage-evidence"
	StaleFencingCaseID              = "initial.stale-fencing-rejection"
	ExecCancellationCaseID          = "initial.exec-cancellation"
	TerminalSessionCaseID           = "initial.terminal-session-and-opaque-handoff"
	GatewayRoundTripCaseID          = "initial.gateway-terminal-byte-round-trip"
	GatewayAuthorityRejectionCaseID = "initial.gateway-wrong-caller-and-cross-tenant-rejection"
	GatewayGrantExpiryCaseID        = "initial.gateway-grant-expiry"
	GatewayRevocationCaseID         = "initial.gateway-revocation"
	ArtifactStagingCaseID           = "initial.artifact-staging-and-evidence"
	CrossTenantArtifactCaseID       = "initial.provider-cross-tenant-artifact-rejection"
	MTLSCallerBindingCaseID         = "initial.provider-mtls-caller-binding-rejection"
	ReconstructionCapabilityCaseID  = "reconstruction.locked-capability-discovery"
	ReconstructionLifecycleCaseID   = "reconstruction.durable-lifecycle"
	ReconstructionEvidenceCaseID    = "reconstruction.retained-exec-usage-and-artifact-evidence"
	ReconstructionHandoffCaseID     = "reconstruction.durable-opaque-handoff"
	ReconstructionReconnectCaseID   = "reconstruction.same-shell-reconnect"
	MaxRequestBytes                 = 32 << 10
	MaxCommandBytes                 = 8 << 10
	MaxResultBytes                  = 64 << 10
)

var (
	ErrRequest = errors.New("private scenario request is invalid")
	ErrResult  = errors.New("private scenario result is invalid")
	ErrIO      = errors.New("private scenario stream failed")
	idPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]*$`)
)

type Request struct {
	FormatVersion                int                          `json:"format_version"`
	ProtocolID                   string                       `json:"protocol_id"`
	ProtocolVersion              string                       `json:"protocol_version"`
	MessageType                  string                       `json:"message_type"`
	InvocationID                 string                       `json:"invocation_id"`
	Phase                        string                       `json:"phase"`
	CaseID                       string                       `json:"case_id"`
	ProviderOrigin               string                       `json:"provider_origin"`
	GatewayProbeEndpoint         string                       `json:"gateway_probe_endpoint"`
	CallerStateRoot              string                       `json:"caller_state_root"`
	Deadline                     time.Time                    `json:"deadline"`
	CredentialChannelDescriptors []protocol.ChannelDescriptor `json:"credential_channel_descriptors"`
}

type Result struct {
	FormatVersion   int                          `json:"format_version"`
	ProtocolID      string                       `json:"protocol_id"`
	ProtocolVersion string                       `json:"protocol_version"`
	MessageType     string                       `json:"message_type"`
	InvocationID    string                       `json:"invocation_id"`
	Phase           string                       `json:"phase"`
	CaseID          string                       `json:"case_id"`
	ProcessID       int                          `json:"process_id"`
	Disposition     string                       `json:"disposition"`
	Interactions    []protocol.InteractionResult `json:"interactions"`
	Assertions      []protocol.AssertionResult   `json:"assertions"`
	ObservationIDs  []string                     `json:"observation_ids"`
	ReasonCode      *string                      `json:"reason_code"`
}

type Command struct {
	FormatVersion   int       `json:"format_version"`
	ProtocolID      string    `json:"protocol_id"`
	ProtocolVersion string    `json:"protocol_version"`
	MessageType     string    `json:"message_type"`
	InvocationID    string    `json:"invocation_id"`
	Phase           string    `json:"phase"`
	CaseID          string    `json:"case_id"`
	Deadline        time.Time `json:"deadline"`
}

func NewRequest(invocation protocol.Invocation, caseID string, descriptors []protocol.ChannelDescriptor, deadline time.Time) (Request, error) {
	request := Request{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "run_scenario", InvocationID: invocation.InvocationID, Phase: invocation.Phase,
		CaseID: caseID, ProviderOrigin: invocation.ProviderOrigin, GatewayProbeEndpoint: invocation.GatewayProbeEndpoint,
		CallerStateRoot: invocation.CallerStateRoot, Deadline: deadline.UTC(),
		CredentialChannelDescriptors: append([]protocol.ChannelDescriptor(nil), descriptors...),
	}
	if validateRequest(request) != nil {
		return Request{}, ErrRequest
	}
	return request, nil
}

func DecodeRequest(reader io.Reader) (Request, error) {
	document, err := readBounded(reader, MaxRequestBytes, ErrRequest)
	if err != nil {
		return Request{}, err
	}
	canonical, err := jcs.Canonicalize(document)
	if err != nil || !hasExactKeys(canonical, requestKeys) {
		return Request{}, ErrRequest
	}
	var request Request
	if decodeStrict(canonical, &request) != nil || validateRequest(request) != nil {
		return Request{}, ErrRequest
	}
	return request, nil
}

func DecodeRequestRecord(reader *bufio.Reader) (Request, error) {
	document, err := readBoundedRecord(reader, MaxRequestBytes, ErrRequest)
	if err != nil {
		return Request{}, err
	}
	canonical, err := jcs.Canonicalize(document)
	if err != nil || !hasExactKeys(canonical, requestKeys) {
		return Request{}, ErrRequest
	}
	var request Request
	if decodeStrict(canonical, &request) != nil || validateRequest(request) != nil {
		return Request{}, ErrRequest
	}
	return request, nil
}

func EncodeRequest(writer io.Writer, request Request) error {
	if validateRequest(request) != nil {
		return ErrRequest
	}
	return encodeLine(writer, request, MaxRequestBytes)
}

func NewCommand(request Request, caseID string, deadline time.Time) (Command, error) {
	command := Command{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "run_scenario", InvocationID: request.InvocationID, Phase: request.Phase,
		CaseID: caseID, Deadline: deadline.UTC(),
	}
	if validateCommand(command) != nil {
		return Command{}, ErrRequest
	}
	return command, nil
}

func DecodeCommandRecord(reader *bufio.Reader) (Command, error) {
	document, err := readBoundedRecord(reader, MaxCommandBytes, ErrRequest)
	if err != nil {
		return Command{}, err
	}
	canonical, err := jcs.Canonicalize(document)
	if err != nil || !hasExactKeys(canonical, commandKeys) {
		return Command{}, ErrRequest
	}
	var command Command
	if decodeStrict(canonical, &command) != nil || validateCommand(command) != nil {
		return Command{}, ErrRequest
	}
	return command, nil
}

func EncodeCommand(writer io.Writer, command Command) error {
	if validateCommand(command) != nil {
		return ErrRequest
	}
	return encodeLine(writer, command, MaxCommandBytes)
}

func NewResult(request Request, processID int, data protocol.ScenarioResultData) (Result, error) {
	result := Result{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "scenario_result", InvocationID: request.InvocationID, Phase: request.Phase,
		CaseID: data.CaseID, ProcessID: processID, Disposition: data.Disposition,
		Interactions: cloneInteractions(data.Interactions), Assertions: cloneSlice(data.Assertions),
		ObservationIDs: cloneSlice(data.ObservationIDs), ReasonCode: cloneString(data.ReasonCode),
	}
	if validateResult(result) != nil {
		return Result{}, ErrResult
	}
	return result, nil
}

func (result Result) Data() protocol.ScenarioResultData {
	return protocol.ScenarioResultData{
		CaseID: result.CaseID, Disposition: result.Disposition,
		Interactions: cloneInteractions(result.Interactions), Assertions: cloneSlice(result.Assertions),
		ObservationIDs: cloneSlice(result.ObservationIDs), ReasonCode: cloneString(result.ReasonCode),
	}
}

func DecodeResult(reader io.Reader) (Result, error) {
	document, err := readBounded(reader, MaxResultBytes, ErrResult)
	if err != nil {
		return Result{}, err
	}
	if len(document) == 0 || document[len(document)-1] != '\n' || bytes.Count(document, []byte{'\n'}) != 1 {
		return Result{}, ErrResult
	}
	document = document[:len(document)-1]
	canonical, err := jcs.Canonicalize(document)
	if err != nil || !hasExactKeys(canonical, resultKeys) {
		return Result{}, ErrResult
	}
	var result Result
	if decodeStrict(canonical, &result) != nil || validateResult(result) != nil {
		return Result{}, ErrResult
	}
	return result, nil
}

func DecodeResultRecord(reader *bufio.Reader) (Result, error) {
	document, err := readBoundedRecord(reader, MaxResultBytes, ErrResult)
	if err != nil {
		return Result{}, err
	}
	canonical, err := jcs.Canonicalize(document)
	if err != nil || !hasExactKeys(canonical, resultKeys) {
		return Result{}, ErrResult
	}
	var result Result
	if decodeStrict(canonical, &result) != nil || validateResult(result) != nil {
		return Result{}, ErrResult
	}
	return result, nil
}

func EncodeResult(writer io.Writer, result Result) error {
	if validateResult(result) != nil {
		return ErrResult
	}
	return encodeLine(writer, result, MaxResultBytes)
}

func validateRequest(request Request) error {
	if request.FormatVersion != FormatVersion || request.ProtocolID != ProtocolID || request.ProtocolVersion != ProtocolVersion || request.MessageType != "run_scenario" ||
		(!validInitialRequest(request.Phase, request.CaseID) && !validReconstructionRequest(request.Phase, request.CaseID)) || !validID(request.InvocationID) || protocol.ValidateProviderOrigin(request.ProviderOrigin) != nil ||
		protocol.ValidateGatewayEndpoint(request.GatewayProbeEndpoint) != nil || protocol.ValidateAbsoluteCleanPOSIXPath(request.CallerStateRoot) != nil ||
		request.Deadline.IsZero() || request.Deadline.Location() != time.UTC || protocol.MatchCredentialRequirements(credentials.Requirements(), request.CredentialChannelDescriptors) != nil {
		return ErrRequest
	}
	return nil
}

func validateCommand(command Command) error {
	if command.FormatVersion != FormatVersion || command.ProtocolID != ProtocolID || command.ProtocolVersion != ProtocolVersion || command.MessageType != "run_scenario" ||
		!validID(command.InvocationID) || !allowedCommandCase(command.Phase, command.CaseID) || command.Deadline.IsZero() || command.Deadline.Location() != time.UTC {
		return ErrRequest
	}
	return nil
}

func validateResult(result Result) error {
	data := result.Data()
	if result.FormatVersion != FormatVersion || result.ProtocolID != ProtocolID || result.ProtocolVersion != ProtocolVersion || result.MessageType != "scenario_result" ||
		!validID(result.InvocationID) || !allowedResultCase(result.Phase, result.CaseID) || result.ProcessID < 1 || result.ProcessID > 1<<31-1 ||
		result.Disposition != "completed" || result.ReasonCode != nil || protocol.ValidateScenarioResultData(result.Phase, data) != nil {
		return ErrResult
	}
	return nil
}

func allowedResultCase(phase, caseID string) bool {
	return validInitialRequest(phase, caseID) || allowedCommandCase(phase, caseID) || validReconstructionRequest(phase, caseID)
}

func validInitialRequest(phase, caseID string) bool {
	return phase == "initial" && caseID == CapabilityCaseID
}

func validReconstructionRequest(phase, caseID string) bool {
	return phase == "reconstruction" && caseID == ReconstructionCapabilityCaseID
}

func allowedCommandCase(phase, caseID string) bool {
	if phase == "reconstruction" {
		return caseID == ReconstructionLifecycleCaseID || caseID == ReconstructionEvidenceCaseID || caseID == ReconstructionHandoffCaseID || caseID == ReconstructionReconnectCaseID
	}
	return phase == "initial" && (caseID == LifecycleCaseID || caseID == ReplayCaseID || caseID == LifecycleCompletionCaseID || caseID == ExecResultUsageCaseID || caseID == StaleFencingCaseID || caseID == ExecCancellationCaseID || caseID == TerminalSessionCaseID || caseID == GatewayRoundTripCaseID || caseID == GatewayAuthorityRejectionCaseID || caseID == GatewayGrantExpiryCaseID || caseID == GatewayRevocationCaseID || caseID == ArtifactStagingCaseID || caseID == CrossTenantArtifactCaseID || caseID == MTLSCallerBindingCaseID)
}

func validID(value string) bool { return len(value) <= 120 && idPattern.MatchString(value) }

func cloneSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	result := make([]T, len(values))
	copy(result, values)
	return result
}

func cloneInteractions(values []protocol.InteractionResult) []protocol.InteractionResult {
	if values == nil {
		return nil
	}
	result := make([]protocol.InteractionResult, len(values))
	for index, value := range values {
		result[index] = value
		result[index].ReplayOf = cloneString(value.ReplayOf)
		result[index].TransientOutcomes = cloneOutcomes(value.TransientOutcomes)
		result[index].FinalOutcome = cloneOutcome(value.FinalOutcome)
		result[index].ObservationIDs = cloneSlice(value.ObservationIDs)
	}
	return result
}

func cloneOutcomes(values []protocol.Outcome) []protocol.Outcome {
	if values == nil {
		return nil
	}
	result := make([]protocol.Outcome, len(values))
	for index, value := range values {
		result[index] = cloneOutcome(value)
	}
	return result
}

func cloneOutcome(value protocol.Outcome) protocol.Outcome {
	value.StatusCode = cloneInt(value.StatusCode)
	value.ErrorCode = cloneString(value.ErrorCode)
	return value
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func readBounded(reader io.Reader, limit int64, limitError error) ([]byte, error) {
	if reader == nil {
		return nil, ErrIO
	}
	document, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, ErrIO
	}
	if int64(len(document)) > limit {
		return nil, limitError
	}
	return document, nil
}

func readBoundedRecord(reader *bufio.Reader, limit int, limitError error) ([]byte, error) {
	if reader == nil {
		return nil, ErrIO
	}
	document := make([]byte, 0, 1024)
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(document)+len(fragment) > limit {
			return nil, limitError
		}
		document = append(document, fragment...)
		switch {
		case err == nil:
			if len(document) < 2 || document[len(document)-1] != '\n' {
				return nil, limitError
			}
			return document[:len(document)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, ErrIO
		}
	}
}

func encodeLine(writer io.Writer, value any, limit int) error {
	if writer == nil {
		return ErrIO
	}
	document, err := json.Marshal(value)
	if err != nil || len(document)+1 > limit {
		return ErrIO
	}
	document = append(document, '\n')
	for len(document) > 0 {
		written, writeErr := writer.Write(document)
		if writeErr != nil || written <= 0 || written > len(document) {
			return ErrIO
		}
		document = document[written:]
	}
	return nil
}

func decodeStrict(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrRequest
	}
	return nil
}

func hasExactKeys(document []byte, keys []string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(document, &object) != nil || len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

var requestKeys = []string{
	"format_version", "protocol_id", "protocol_version", "message_type", "invocation_id", "phase", "case_id",
	"provider_origin", "gateway_probe_endpoint", "caller_state_root", "deadline", "credential_channel_descriptors",
}

var commandKeys = []string{
	"format_version", "protocol_id", "protocol_version", "message_type", "invocation_id", "phase", "case_id", "deadline",
}

var resultKeys = []string{
	"format_version", "protocol_id", "protocol_version", "message_type", "invocation_id", "phase", "case_id", "process_id",
	"disposition", "interactions", "assertions", "observation_ids", "reason_code",
}
