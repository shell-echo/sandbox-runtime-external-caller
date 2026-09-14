package protocol

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
)

const (
	MaxAdapterOutputRecords  = 33
	MaxAdapterOutputSequence = 32
	MaxAdapterStdoutBytes    = 2 << 20
)

var (
	ErrOutputRecordLimit     = errors.New("adapter output record limit exceeded")
	ErrOutputRecordByteLimit = errors.New("adapter output record byte limit exceeded")
	ErrOutputByteLimit       = errors.New("adapter stdout byte limit exceeded")
	ErrOutputEncoderFailed   = errors.New("adapter output encoder is failed")
)

var (
	caseIDPattern    = regexp.MustCompile(`^(?:initial|reconstruction)\.[a-z0-9][a-z0-9-]*$`)
	routePattern     = regexp.MustCompile(`^(?:/v1/[A-Za-z0-9._:{}-]+(?:/[A-Za-z0-9._:{}-]+)*|consumer-defined:[a-z0-9][a-z0-9-]*)$`)
	errorCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,99}$`)
)

var (
	invocationAcceptedKeys = []string{
		"format_version", "protocol_id", "protocol_version", "message_type", "sequence", "invocation_id", "phase",
	}
	scenarioStartedKeys = []string{
		"format_version", "protocol_id", "protocol_version", "message_type", "sequence", "invocation_id", "phase", "case_id",
	}
	scenarioResultKeys = []string{
		"format_version", "protocol_id", "protocol_version", "message_type", "sequence", "invocation_id", "phase", "case_id",
		"disposition", "interactions", "assertions", "observation_ids", "reason_code",
	}
	interactionResultKeys = []string{
		"interaction_id", "surface", "actor", "method", "route_template", "logical_request_id", "replay_of", "wire_attempts",
		"transient_outcomes", "final_outcome", "mutation_write_observed", "observation_ids",
	}
	outcomeKeys = []string{
		"transport", "status_code", "error_code", "retryable", "retry_after_present",
	}
	assertionResultKeys    = []string{"assertion_id", "result"}
	invocationFinishedKeys = []string{
		"format_version", "protocol_id", "protocol_version", "message_type", "sequence", "invocation_id", "phase", "completion",
	}
	protocolErrorKeys = []string{
		"format_version", "protocol_id", "protocol_version", "message_type", "sequence", "invocation_id", "phase", "error_code", "terminal",
	}
)

type InvocationAccepted struct {
	FormatVersion   int    `json:"format_version"`
	ProtocolID      string `json:"protocol_id"`
	ProtocolVersion string `json:"protocol_version"`
	MessageType     string `json:"message_type"`
	Sequence        int    `json:"sequence"`
	InvocationID    string `json:"invocation_id"`
	Phase           string `json:"phase"`
}

type ScenarioStarted struct {
	FormatVersion   int    `json:"format_version"`
	ProtocolID      string `json:"protocol_id"`
	ProtocolVersion string `json:"protocol_version"`
	MessageType     string `json:"message_type"`
	Sequence        int    `json:"sequence"`
	InvocationID    string `json:"invocation_id"`
	Phase           string `json:"phase"`
	CaseID          string `json:"case_id"`
}

type Outcome struct {
	Transport         string  `json:"transport"`
	StatusCode        *int    `json:"status_code"`
	ErrorCode         *string `json:"error_code"`
	Retryable         bool    `json:"retryable"`
	RetryAfterPresent bool    `json:"retry_after_present"`
}

type InteractionResult struct {
	InteractionID         string    `json:"interaction_id"`
	Surface               string    `json:"surface"`
	Actor                 string    `json:"actor"`
	Method                string    `json:"method"`
	RouteTemplate         string    `json:"route_template"`
	LogicalRequestID      string    `json:"logical_request_id"`
	ReplayOf              *string   `json:"replay_of"`
	WireAttempts          int       `json:"wire_attempts"`
	TransientOutcomes     []Outcome `json:"transient_outcomes"`
	FinalOutcome          Outcome   `json:"final_outcome"`
	MutationWriteObserved bool      `json:"mutation_write_observed"`
	ObservationIDs        []string  `json:"observation_ids"`
}

type AssertionResult struct {
	AssertionID string `json:"assertion_id"`
	Result      string `json:"result"`
}

type ScenarioResult struct {
	FormatVersion   int                 `json:"format_version"`
	ProtocolID      string              `json:"protocol_id"`
	ProtocolVersion string              `json:"protocol_version"`
	MessageType     string              `json:"message_type"`
	Sequence        int                 `json:"sequence"`
	InvocationID    string              `json:"invocation_id"`
	Phase           string              `json:"phase"`
	CaseID          string              `json:"case_id"`
	Disposition     string              `json:"disposition"`
	Interactions    []InteractionResult `json:"interactions"`
	Assertions      []AssertionResult   `json:"assertions"`
	ObservationIDs  []string            `json:"observation_ids"`
	ReasonCode      *string             `json:"reason_code"`
}

type InvocationFinished struct {
	FormatVersion   int    `json:"format_version"`
	ProtocolID      string `json:"protocol_id"`
	ProtocolVersion string `json:"protocol_version"`
	MessageType     string `json:"message_type"`
	Sequence        int    `json:"sequence"`
	InvocationID    string `json:"invocation_id"`
	Phase           string `json:"phase"`
	Completion      string `json:"completion"`
}

type ProtocolError struct {
	FormatVersion   int     `json:"format_version"`
	ProtocolID      string  `json:"protocol_id"`
	ProtocolVersion string  `json:"protocol_version"`
	MessageType     string  `json:"message_type"`
	Sequence        int     `json:"sequence"`
	InvocationID    *string `json:"invocation_id"`
	Phase           *string `json:"phase"`
	ErrorCode       string  `json:"error_code"`
	Terminal        bool    `json:"terminal"`
}

type OutputStats struct {
	CompleteRecords int
	WireBytes       int
}

// OutputEncoder emits only complete, schema-valid, single-LF records. It does
// not enforce message ordering; PhaseMachine owns that responsibility.
type OutputEncoder struct {
	mu      sync.Mutex
	writer  io.Writer
	records int
	bytes   int
	failed  bool
}

func NewOutputEncoder(writer io.Writer) *OutputEncoder {
	return &OutputEncoder{writer: writer}
}

func (e *OutputEncoder) Write(record any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed {
		return ErrOutputEncoderFailed
	}
	if e.writer == nil {
		e.failed = true
		return ErrStreamIO
	}
	document, err := marshalOutputRecord(record)
	if err != nil {
		e.failed = true
		return err
	}
	if e.bytes+len(document)+1 > MaxAdapterStdoutBytes {
		e.failed = true
		return ErrOutputByteLimit
	}
	if e.records >= MaxAdapterOutputRecords {
		e.failed = true
		return ErrOutputRecordLimit
	}
	if len(document) > MaxAdapterOutputRecordBytes {
		e.failed = true
		return ErrOutputRecordByteLimit
	}
	document = append(document, '\n')
	for len(document) > 0 {
		written, writeErr := e.writer.Write(document)
		if written < 0 || written > len(document) {
			e.failed = true
			return ErrStreamIO
		}
		if written > 0 {
			e.bytes += written
			document = document[written:]
		}
		if writeErr != nil || written == 0 {
			e.failed = true
			return ErrStreamIO
		}
	}
	e.records++
	return nil
}

func (e *OutputEncoder) Stats() OutputStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return OutputStats{CompleteRecords: e.records, WireBytes: e.bytes}
}

func marshalOutputRecord(record any) ([]byte, error) {
	if err := validateOutputRecord(record); err != nil {
		return nil, err
	}
	document, err := json.Marshal(record)
	if err != nil {
		return nil, ErrSchema
	}
	return document, nil
}

// validOutputDocument applies schema validation before classifying an input
// record as adapter-to-harness traffic. This preserves schema-before-direction
// error precedence for malformed records that merely claim an output type.
func validOutputDocument(document []byte, messageType string) bool {
	var record any
	var keys []string
	switch messageType {
	case "startup_identity":
		record = &StartupIdentity{}
		keys = startupKeys
	case "invocation_accepted":
		record = &InvocationAccepted{}
		keys = invocationAcceptedKeys
	case "scenario_started":
		record = &ScenarioStarted{}
		keys = scenarioStartedKeys
	case "scenario_result":
		record = &ScenarioResult{}
		keys = scenarioResultKeys
	case "invocation_finished":
		record = &InvocationFinished{}
		keys = invocationFinishedKeys
	case "protocol_error":
		record = &ProtocolError{}
		keys = protocolErrorKeys
	default:
		return false
	}
	if !hasExactKeys(document, keys) || decodeStrict(document, record) != nil {
		return false
	}
	if messageType == "scenario_result" && !hasExactScenarioResultShape(document) {
		return false
	}
	switch value := record.(type) {
	case *StartupIdentity:
		return validateOutputRecord(*value) == nil
	case *InvocationAccepted:
		return validateOutputRecord(*value) == nil
	case *ScenarioStarted:
		return validateOutputRecord(*value) == nil
	case *ScenarioResult:
		return validateOutputRecord(*value) == nil
	case *InvocationFinished:
		return validateOutputRecord(*value) == nil
	case *ProtocolError:
		return validateOutputRecord(*value) == nil
	default:
		return false
	}
}

func hasExactScenarioResultShape(document []byte) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(document, &object) != nil {
		return false
	}
	var interactions []json.RawMessage
	if json.Unmarshal(object["interactions"], &interactions) != nil {
		return false
	}
	for _, interaction := range interactions {
		if !hasExactKeys(interaction, interactionResultKeys) {
			return false
		}
		var interactionObject map[string]json.RawMessage
		if json.Unmarshal(interaction, &interactionObject) != nil || !hasExactOutcomeArrayShape(interactionObject["transient_outcomes"]) || !hasExactKeys(interactionObject["final_outcome"], outcomeKeys) {
			return false
		}
	}
	var assertions []json.RawMessage
	if json.Unmarshal(object["assertions"], &assertions) != nil {
		return false
	}
	for _, assertion := range assertions {
		if !hasExactKeys(assertion, assertionResultKeys) {
			return false
		}
	}
	return true
}

func hasExactOutcomeArrayShape(document []byte) bool {
	var outcomes []json.RawMessage
	if json.Unmarshal(document, &outcomes) != nil {
		return false
	}
	for _, outcome := range outcomes {
		if !hasExactKeys(outcome, outcomeKeys) {
			return false
		}
	}
	return true
}

func validateOutputRecord(record any) error {
	switch value := record.(type) {
	case StartupIdentity:
		return ValidateStartup(value)
	case InvocationAccepted:
		if !validOutputBase(value.FormatVersion, value.ProtocolID, value.ProtocolVersion, value.MessageType, "invocation_accepted", value.Sequence, value.InvocationID, value.Phase) {
			return ErrSchema
		}
	case ScenarioStarted:
		if !validOutputBase(value.FormatVersion, value.ProtocolID, value.ProtocolVersion, value.MessageType, "scenario_started", value.Sequence, value.InvocationID, value.Phase) || !validCaseID(value.CaseID, value.Phase) {
			return ErrSchema
		}
	case ScenarioResult:
		if !validScenarioResult(value) {
			return ErrSchema
		}
	case InvocationFinished:
		if !validOutputBase(value.FormatVersion, value.ProtocolID, value.ProtocolVersion, value.MessageType, "invocation_finished", value.Sequence, value.InvocationID, value.Phase) || (value.Completion != "completed" && value.Completion != "stopped") {
			return ErrSchema
		}
	case ProtocolError:
		if !validProtocolError(value) {
			return ErrSchema
		}
	default:
		return ErrSchema
	}
	return nil
}

func validOutputBase(formatVersion int, protocolID, protocolVersion, messageType, expectedType string, sequence int, invocationID, phase string) bool {
	return formatVersion == FormatVersion && protocolID == ProtocolID && protocolVersion == ProtocolVersion && messageType == expectedType &&
		sequence >= 1 && sequence <= MaxAdapterOutputSequence && validID(invocationID) && (phase == "initial" || phase == "reconstruction")
}

func validCaseID(caseID, phase string) bool {
	return len(caseID) <= 120 && caseIDPattern.MatchString(caseID) && stringsHasPrefix(caseID, phase+".")
}

func validScenarioResult(result ScenarioResult) bool {
	if !validOutputBase(result.FormatVersion, result.ProtocolID, result.ProtocolVersion, result.MessageType, "scenario_result", result.Sequence, result.InvocationID, result.Phase) || !validCaseID(result.CaseID, result.Phase) ||
		result.Interactions == nil || len(result.Interactions) > 12 || result.Assertions == nil || len(result.Assertions) > 20 || result.ObservationIDs == nil || len(result.ObservationIDs) > 20 || !uniqueValidIDs(result.ObservationIDs) {
		return false
	}
	for _, interaction := range result.Interactions {
		if !validInteraction(interaction) {
			return false
		}
	}
	seenAssertions := map[AssertionResult]struct{}{}
	for _, assertion := range result.Assertions {
		if !validID(assertion.AssertionID) || (assertion.Result != "asserted" && assertion.Result != "not_asserted" && assertion.Result != "contradicted") {
			return false
		}
		if _, duplicate := seenAssertions[assertion]; duplicate {
			return false
		}
		seenAssertions[assertion] = struct{}{}
	}
	switch result.Disposition {
	case "completed":
		return len(result.Interactions) >= 1 && result.ReasonCode == nil
	case "not_executed":
		return len(result.Interactions) == 0 && len(result.Assertions) == 0 && len(result.ObservationIDs) == 0 && result.ReasonCode != nil && validNotExecutedReason(*result.ReasonCode)
	default:
		return false
	}
}

func validInteraction(interaction InteractionResult) bool {
	if !validID(interaction.InteractionID) || !oneOf(interaction.Surface, "provider_http", "caller_gateway") ||
		!oneOf(interaction.Actor, "controller_a", "controller_b", "same_ca_unadmitted", "unauthenticated_client") || !oneOf(interaction.Method, "GET", "POST", "CONNECT", "CONTROL") ||
		len(interaction.RouteTemplate) < 1 || len(interaction.RouteTemplate) > 240 || !routePattern.MatchString(interaction.RouteTemplate) || !validID(interaction.LogicalRequestID) ||
		interaction.WireAttempts < 1 || interaction.WireAttempts > 64 || interaction.TransientOutcomes == nil || len(interaction.TransientOutcomes) > 63 || interaction.ObservationIDs == nil || len(interaction.ObservationIDs) < 1 || len(interaction.ObservationIDs) > 20 || !uniqueValidIDs(interaction.ObservationIDs) {
		return false
	}
	// replay_of is pattern-constrained by the locked report schema but, unlike
	// the shared id definition, has no maxLength keyword.
	if interaction.ReplayOf != nil && !idPattern.MatchString(*interaction.ReplayOf) {
		return false
	}
	for _, outcome := range interaction.TransientOutcomes {
		if !validOutcome(outcome) {
			return false
		}
	}
	return validOutcome(interaction.FinalOutcome)
}

func validOutcome(outcome Outcome) bool {
	if !oneOf(outcome.Transport, "http-response", "tls-rejected", "authorized-byte-round-trip", "gateway-upgrade-rejected", "gateway-closed-before-data", "gateway-closed-at-grant-expiry", "revocation-acknowledged", "transport-unavailable", "deadline-exceeded") {
		return false
	}
	if outcome.StatusCode != nil && (*outcome.StatusCode < 100 || *outcome.StatusCode > 599) {
		return false
	}
	return outcome.ErrorCode == nil || errorCodePattern.MatchString(*outcome.ErrorCode)
}

func validProtocolError(output ProtocolError) bool {
	if output.FormatVersion != FormatVersion || output.ProtocolID != ProtocolID || output.ProtocolVersion != ProtocolVersion || output.MessageType != "protocol_error" || output.Sequence < 1 || output.Sequence > MaxAdapterOutputSequence || !output.Terminal {
		return false
	}
	if output.ErrorCode == "invalid_invocation" {
		return output.Sequence == 1 && output.InvocationID == nil && output.Phase == nil
	}
	if !oneOf(output.ErrorCode, "credential_channel_failed", "caller_start_failed", "scenario_execution_failed", "output_failed", "internal_failure") || output.Sequence < 2 || output.InvocationID == nil || output.Phase == nil {
		return false
	}
	return validID(*output.InvocationID) && (*output.Phase == "initial" || *output.Phase == "reconstruction")
}

func validNotExecutedReason(value string) bool {
	return oneOf(value, "prerequisite_not_satisfied", "invocation_canceled", "time_budget_exhausted", "adapter_unavailable")
}

func uniqueValidIDs(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validID(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func stringsHasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
