// Package callercontrol implements the candidate-private, credential-free
// adapter-to-caller control protocol. It is not Provider wire API or evidence.
package callercontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const (
	FormatVersion   = 1
	ProtocolID      = "sandbox-runtime-external-caller-private-control-v4"
	ProtocolVersion = "4.0.0"
	MaxRequestBytes = 32 << 10
	MaxResultBytes  = 4 << 10
)

var (
	ErrControlRequest = errors.New("caller control request is invalid")
	ErrControlResult  = errors.New("caller control result is invalid")
	ErrControlIO      = errors.New("caller control stream failed")
)

type Request struct {
	FormatVersion                int                          `json:"format_version"`
	ProtocolID                   string                       `json:"protocol_id"`
	ProtocolVersion              string                       `json:"protocol_version"`
	MessageType                  string                       `json:"message_type"`
	Phase                        string                       `json:"phase"`
	ProviderOrigin               string                       `json:"provider_origin"`
	GatewayProbeEndpoint         string                       `json:"gateway_probe_endpoint"`
	CallerStateRoot              string                       `json:"caller_state_root"`
	Deadline                     time.Time                    `json:"deadline"`
	CredentialChannelDescriptors []protocol.ChannelDescriptor `json:"credential_channel_descriptors"`
}

type Result struct {
	FormatVersion   int    `json:"format_version"`
	ProtocolID      string `json:"protocol_id"`
	ProtocolVersion string `json:"protocol_version"`
	MessageType     string `json:"message_type"`
	Phase           string `json:"phase"`
	Status          string `json:"status"`
	ProcessID       int    `json:"process_id"`
}

func NewRequest(invocation protocol.Invocation, descriptors []protocol.ChannelDescriptor, deadline time.Time) (Request, error) {
	request := Request{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "run_phase", Phase: invocation.Phase, ProviderOrigin: invocation.ProviderOrigin,
		GatewayProbeEndpoint: invocation.GatewayProbeEndpoint, CallerStateRoot: invocation.CallerStateRoot,
		Deadline:                     deadline.UTC(),
		CredentialChannelDescriptors: append([]protocol.ChannelDescriptor(nil), descriptors...),
	}
	if validateRequest(request) != nil {
		return Request{}, ErrControlRequest
	}
	return request, nil
}

func DecodeRequest(reader io.Reader) (Request, error) {
	document, err := readBounded(reader, MaxRequestBytes, ErrControlRequest)
	if err != nil {
		return Request{}, err
	}
	canonical, err := jcs.Canonicalize(document)
	if err != nil || !hasExactKeys(canonical, requestKeys) {
		return Request{}, ErrControlRequest
	}
	var request Request
	if decodeStrict(canonical, &request) != nil || validateRequest(request) != nil {
		return Request{}, ErrControlRequest
	}
	return request, nil
}

func EncodeRequest(writer io.Writer, request Request) error {
	if validateRequest(request) != nil {
		return ErrControlRequest
	}
	return encodeLine(writer, request, MaxRequestBytes)
}

func NewResult(phase string, processID int) (Result, error) {
	result := Result{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "phase_lifecycle_complete", Phase: phase, Status: "provider_lifecycle_and_gateway_coordination_complete_no_scenario_results", ProcessID: processID,
	}
	if validateResult(result) != nil {
		return Result{}, ErrControlResult
	}
	return result, nil
}

func DecodeResult(reader io.Reader) (Result, error) {
	document, err := readBounded(reader, MaxResultBytes, ErrControlResult)
	if err != nil {
		return Result{}, err
	}
	if len(document) == 0 || document[len(document)-1] != '\n' || bytes.Count(document, []byte{'\n'}) != 1 {
		return Result{}, ErrControlResult
	}
	document = document[:len(document)-1]
	canonical, err := jcs.Canonicalize(document)
	if err != nil || !hasExactKeys(canonical, resultKeys) {
		return Result{}, ErrControlResult
	}
	var result Result
	if decodeStrict(canonical, &result) != nil || validateResult(result) != nil {
		return Result{}, ErrControlResult
	}
	return result, nil
}

func EncodeResult(writer io.Writer, result Result) error {
	if validateResult(result) != nil {
		return ErrControlResult
	}
	return encodeLine(writer, result, MaxResultBytes)
}

func validateRequest(request Request) error {
	if request.FormatVersion != FormatVersion || request.ProtocolID != ProtocolID || request.ProtocolVersion != ProtocolVersion || request.MessageType != "run_phase" ||
		(request.Phase != "initial" && request.Phase != "reconstruction") || protocol.ValidateProviderOrigin(request.ProviderOrigin) != nil ||
		protocol.ValidateGatewayEndpoint(request.GatewayProbeEndpoint) != nil || protocol.ValidateAbsoluteCleanPOSIXPath(request.CallerStateRoot) != nil ||
		request.Deadline.IsZero() || request.Deadline.Location() != time.UTC ||
		protocol.MatchCredentialRequirements(credentials.Requirements(), request.CredentialChannelDescriptors) != nil {
		return ErrControlRequest
	}
	return nil
}

func validateResult(result Result) error {
	if result.FormatVersion != FormatVersion || result.ProtocolID != ProtocolID || result.ProtocolVersion != ProtocolVersion || result.MessageType != "phase_lifecycle_complete" ||
		(result.Phase != "initial" && result.Phase != "reconstruction") || result.Status != "provider_lifecycle_and_gateway_coordination_complete_no_scenario_results" || result.ProcessID < 1 || result.ProcessID > 1<<31-1 {
		return ErrControlResult
	}
	return nil
}

func readBounded(reader io.Reader, limit int64, limitError error) ([]byte, error) {
	if reader == nil {
		return nil, ErrControlIO
	}
	document, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, ErrControlIO
	}
	if int64(len(document)) > limit {
		return nil, limitError
	}
	return document, nil
}

func encodeLine(writer io.Writer, value any, limit int) error {
	if writer == nil {
		return ErrControlIO
	}
	document, err := json.Marshal(value)
	if err != nil || len(document)+1 > limit {
		return ErrControlIO
	}
	document = append(document, '\n')
	for len(document) > 0 {
		written, writeErr := writer.Write(document)
		if writeErr != nil || written <= 0 || written > len(document) {
			return ErrControlIO
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
		return ErrControlRequest
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
	"format_version", "protocol_id", "protocol_version", "message_type", "phase", "provider_origin",
	"gateway_probe_endpoint", "caller_state_root", "deadline", "credential_channel_descriptors",
}

var resultKeys = []string{
	"format_version", "protocol_id", "protocol_version", "message_type", "phase", "status", "process_id",
}
