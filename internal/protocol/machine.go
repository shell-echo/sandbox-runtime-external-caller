package protocol

import (
	"errors"
	"io"
	"sync"
)

var (
	ErrInvalidTransition = errors.New("adapter protocol state transition is invalid")
	ErrOutputBinding     = errors.New("adapter output does not bind the accepted invocation")
	ErrScenarioOrder     = errors.New("adapter scenario order differs from the locked profile")
)

type State string

const (
	StateAwaitingStartup              State = "awaiting-startup"
	StateReadyForInvocation           State = "ready-for-invocation"
	StateAwaitingInvocationAcceptance State = "awaiting-invocation-acceptance"
	StateAwaitingNextScenario         State = "awaiting-next-scenario"
	StateAwaitingStartedResult        State = "awaiting-started-result"
	StateAwaitingTerminal             State = "awaiting-terminal"
	StateTerminalObserved             State = "terminal-observed"
	StateTerminalEOFObserved          State = "terminal-eof-observed"
	StateComplete                     State = "complete"
	StateFailed                       State = "failed"
)

var initialCaseIDs = []string{
	"initial.locked-capability-discovery",
	"initial.protected-lifecycle-create",
	"initial.replay-semantics",
	"initial.lifecycle-completion-and-status",
	"initial.exec-result-and-usage-evidence",
	"initial.stale-fencing-rejection",
	"initial.exec-cancellation",
	"initial.terminal-session-and-opaque-handoff",
	"initial.gateway-terminal-byte-round-trip",
	"initial.gateway-wrong-caller-and-cross-tenant-rejection",
	"initial.gateway-grant-expiry",
	"initial.gateway-revocation",
	"initial.artifact-staging-and-evidence",
	"initial.provider-cross-tenant-artifact-rejection",
	"initial.provider-mtls-caller-binding-rejection",
}

var reconstructionCaseIDs = []string{
	"reconstruction.locked-capability-discovery",
	"reconstruction.durable-lifecycle",
	"reconstruction.retained-exec-usage-and-artifact-evidence",
	"reconstruction.durable-opaque-handoff",
	"reconstruction.same-shell-reconnect",
}

func CaseIDs(phase string) ([]string, bool) {
	var source []string
	switch phase {
	case "initial":
		source = initialCaseIDs
	case "reconstruction":
		source = reconstructionCaseIDs
	default:
		return nil, false
	}
	return append([]string(nil), source...), true
}

type ScenarioResultData struct {
	CaseID         string
	Disposition    string
	Interactions   []InteractionResult
	Assertions     []AssertionResult
	ObservationIDs []string
	ReasonCode     *string
}

// PhaseMachine owns output ordering for one fresh adapter process and one
// phase. Complete means the protocol reached terminal, EOF, and clean exit; it
// is not a scenario or qualification pass result.
type PhaseMachine struct {
	mu             sync.Mutex
	encoder        *OutputEncoder
	startup        StartupIdentity
	phase          string
	cases          []string
	state          State
	invocation     *Invocation
	nextCase       int
	nextSequence   int
	anyNotExecuted bool
}

func NewPhaseMachine(writer io.Writer, startup StartupIdentity, expectedPhase ...string) (*PhaseMachine, error) {
	if err := ValidateStartup(startup); err != nil {
		return nil, err
	}
	if len(expectedPhase) > 1 {
		return nil, ErrSchema
	}
	phase := ""
	var cases []string
	if len(expectedPhase) == 1 {
		var ok bool
		phase = expectedPhase[0]
		cases, ok = CaseIDs(phase)
		if !ok {
			return nil, ErrSchema
		}
	}
	startup.CredentialChannelRequirements = append([]ChannelRequirement(nil), startup.CredentialChannelRequirements...)
	return &PhaseMachine{
		encoder:      NewOutputEncoder(writer),
		startup:      startup,
		phase:        phase,
		cases:        cases,
		state:        StateAwaitingStartup,
		nextSequence: 1,
	}, nil
}

func (m *PhaseMachine) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *PhaseMachine) Stats() OutputStats {
	return m.encoder.Stats()
}

// AcceptedInvocation returns a detached copy of the single validated inbound
// invocation. It exposes only the locked harness fields and never mutable
// machine-owned descriptor storage.
func (m *PhaseMachine) AcceptedInvocation() (Invocation, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.invocation == nil || m.state == StateFailed {
		return Invocation{}, false
	}
	invocation := *m.invocation
	invocation.CredentialChannelDescriptors = append([]ChannelDescriptor(nil), m.invocation.CredentialChannelDescriptors...)
	return invocation, true
}

func (m *PhaseMachine) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateAwaitingStartup {
		return m.invalidTransition()
	}
	if err := m.encoder.Write(m.startup); err != nil {
		m.state = StateFailed
		return err
	}
	m.state = StateReadyForInvocation
	return nil
}

func (m *PhaseMachine) ConsumeInvocation(reader io.Reader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateReadyForInvocation {
		return m.invalidTransition()
	}
	invocation, decodeErr := (&InvocationDecoder{}).Decode(reader)
	m.state = StateAwaitingInvocationAcceptance
	phaseMismatch := m.phase != "" && invocation.Phase != m.phase
	cases, phaseOK := CaseIDs(invocation.Phase)
	if decodeErr != nil || phaseMismatch || !phaseOK || MatchCredentialRequirements(m.startup.CredentialChannelRequirements, invocation.CredentialChannelDescriptors) != nil {
		if err := m.writeInvalidInvocation(); err != nil {
			return err
		}
		if decodeErr != nil {
			return decodeErr
		}
		return ErrSchema
	}
	if m.phase == "" {
		m.phase = invocation.Phase
		m.cases = cases
	}
	copy := invocation
	copy.CredentialChannelDescriptors = append([]ChannelDescriptor(nil), invocation.CredentialChannelDescriptors...)
	m.invocation = &copy
	m.state = StateAwaitingInvocationAcceptance
	return nil
}

func (m *PhaseMachine) writeInvalidInvocation() error {
	if m.state != StateAwaitingInvocationAcceptance || m.invocation != nil || m.nextSequence != 1 {
		return m.invalidTransition()
	}
	record := ProtocolError{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "protocol_error", Sequence: 1, ErrorCode: "invalid_invocation", Terminal: true,
	}
	if err := m.encoder.Write(record); err != nil {
		m.state = StateFailed
		return err
	}
	m.nextSequence = 2
	m.state = StateTerminalObserved
	return nil
}

func (m *PhaseMachine) AcceptInvocation() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateAwaitingInvocationAcceptance || m.invocation == nil || m.nextSequence != 1 {
		return m.invalidTransition()
	}
	record := InvocationAccepted{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "invocation_accepted", Sequence: m.nextSequence, InvocationID: m.invocation.InvocationID, Phase: m.phase,
	}
	if err := m.write(record); err != nil {
		return err
	}
	m.state = StateAwaitingNextScenario
	return nil
}

func (m *PhaseMachine) StartScenario(caseID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateAwaitingNextScenario || m.invocation == nil {
		return m.invalidTransition()
	}
	if m.nextCase >= len(m.cases) || caseID != m.cases[m.nextCase] {
		m.state = StateFailed
		return ErrScenarioOrder
	}
	record := ScenarioStarted{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "scenario_started", Sequence: m.nextSequence, InvocationID: m.invocation.InvocationID, Phase: m.phase, CaseID: caseID,
	}
	if err := m.write(record); err != nil {
		return err
	}
	m.state = StateAwaitingStartedResult
	return nil
}

func (m *PhaseMachine) Result(data ScenarioResultData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if (m.state != StateAwaitingNextScenario && m.state != StateAwaitingStartedResult) || m.invocation == nil {
		return m.invalidTransition()
	}
	if m.nextCase >= len(m.cases) || data.CaseID != m.cases[m.nextCase] {
		m.state = StateFailed
		return ErrScenarioOrder
	}
	if (m.state == StateAwaitingStartedResult && data.Disposition != "completed") || (m.state == StateAwaitingNextScenario && data.Disposition != "not_executed") {
		m.state = StateFailed
		return ErrInvalidTransition
	}
	record := ScenarioResult{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "scenario_result", Sequence: m.nextSequence, InvocationID: m.invocation.InvocationID, Phase: m.phase, CaseID: data.CaseID,
		Disposition: data.Disposition, Interactions: copyInteractions(data.Interactions), Assertions: copyAssertions(data.Assertions), ObservationIDs: copyStrings(data.ObservationIDs), ReasonCode: copyString(data.ReasonCode),
	}
	if err := m.write(record); err != nil {
		return err
	}
	if data.Disposition == "not_executed" {
		m.anyNotExecuted = true
	}
	m.nextCase++
	if m.nextCase == len(m.cases) {
		m.state = StateAwaitingTerminal
	} else {
		m.state = StateAwaitingNextScenario
	}
	return nil
}

func (m *PhaseMachine) Finish() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateAwaitingTerminal || m.invocation == nil || m.nextCase != len(m.cases) {
		return m.invalidTransition()
	}
	completion := "completed"
	if m.anyNotExecuted {
		completion = "stopped"
	}
	record := InvocationFinished{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "invocation_finished", Sequence: m.nextSequence, InvocationID: m.invocation.InvocationID, Phase: m.phase, Completion: completion,
	}
	if err := m.write(record); err != nil {
		return err
	}
	m.state = StateTerminalObserved
	return nil
}

func (m *PhaseMachine) Fail(errorCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if (m.state != StateAwaitingNextScenario && m.state != StateAwaitingStartedResult && m.state != StateAwaitingTerminal) || m.invocation == nil || !oneOf(errorCode, "credential_channel_failed", "caller_start_failed", "scenario_execution_failed", "output_failed", "internal_failure") {
		return m.invalidTransition()
	}
	invocationID, phase := m.invocation.InvocationID, m.phase
	record := ProtocolError{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "protocol_error", Sequence: m.nextSequence, InvocationID: &invocationID, Phase: &phase, ErrorCode: errorCode, Terminal: true,
	}
	if err := m.write(record); err != nil {
		return err
	}
	m.state = StateTerminalObserved
	return nil
}

func (m *PhaseMachine) ObserveEOF() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateTerminalObserved {
		return m.invalidTransition()
	}
	m.state = StateTerminalEOFObserved
	return nil
}

func (m *PhaseMachine) ObserveCleanProcessExit(clean bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateTerminalEOFObserved || !clean {
		return m.invalidTransition()
	}
	m.state = StateComplete
	return nil
}

func (m *PhaseMachine) ObserveByteAfterTerminal() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == StateTerminalObserved || m.state == StateTerminalEOFObserved {
		m.state = StateFailed
		return ErrInvalidTransition
	}
	return m.invalidTransition()
}

func (m *PhaseMachine) write(record any) error {
	if m.nextSequence < 1 || m.nextSequence > MaxAdapterOutputSequence {
		m.state = StateFailed
		return ErrSchema
	}
	if err := m.encoder.Write(record); err != nil {
		m.state = StateFailed
		return err
	}
	m.nextSequence++
	return nil
}

func (m *PhaseMachine) invalidTransition() error {
	if m.state != StateComplete && m.state != StateFailed {
		m.state = StateFailed
	}
	return ErrInvalidTransition
}

func copyInteractions(source []InteractionResult) []InteractionResult {
	if source == nil {
		return nil
	}
	result := make([]InteractionResult, len(source))
	for index, interaction := range source {
		result[index] = interaction
		result[index].ReplayOf = copyString(interaction.ReplayOf)
		result[index].TransientOutcomes = copyOutcomes(interaction.TransientOutcomes)
		result[index].FinalOutcome.StatusCode = copyInt(interaction.FinalOutcome.StatusCode)
		result[index].FinalOutcome.ErrorCode = copyString(interaction.FinalOutcome.ErrorCode)
		for outcomeIndex := range result[index].TransientOutcomes {
			result[index].TransientOutcomes[outcomeIndex].StatusCode = copyInt(interaction.TransientOutcomes[outcomeIndex].StatusCode)
			result[index].TransientOutcomes[outcomeIndex].ErrorCode = copyString(interaction.TransientOutcomes[outcomeIndex].ErrorCode)
		}
		result[index].ObservationIDs = copyStrings(interaction.ObservationIDs)
	}
	return result
}

func copyOutcomes(source []Outcome) []Outcome {
	if source == nil {
		return nil
	}
	result := make([]Outcome, len(source))
	copy(result, source)
	return result
}

func copyAssertions(source []AssertionResult) []AssertionResult {
	if source == nil {
		return nil
	}
	result := make([]AssertionResult, len(source))
	copy(result, source)
	return result
}

func copyStrings(source []string) []string {
	if source == nil {
		return nil
	}
	result := make([]string, len(source))
	copy(result, source)
	return result
}

func copyString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyInt(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
