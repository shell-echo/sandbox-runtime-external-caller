// Package gatewaycontrol implements the candidate-private, credential-free
// caller-to-Gateway bootstrap protocol. It is not Provider wire API or
// qualification evidence.
package gatewaycontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const (
	FormatVersion   = 1
	ProtocolID      = "sandbox-runtime-external-caller-private-gateway-control-v2"
	ProtocolVersion = "2.0.0"
	MaxRequestBytes = 16 << 10
	MaxResultBytes  = 4 << 10
)

var (
	ErrControlRequest = errors.New("Gateway control request is invalid")
	ErrControlResult  = errors.New("Gateway control result is invalid")
	ErrControlIO      = errors.New("Gateway control stream failed")
)

type Request struct {
	FormatVersion                int                          `json:"format_version"`
	ProtocolID                   string                       `json:"protocol_id"`
	ProtocolVersion              string                       `json:"protocol_version"`
	MessageType                  string                       `json:"message_type"`
	Phase                        string                       `json:"phase"`
	GatewayProbeEndpoint         string                       `json:"gateway_probe_endpoint"`
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

func NewRequest(phase, endpoint string, descriptors []protocol.ChannelDescriptor) (Request, error) {
	request := Request{
		FormatVersion: FormatVersion, ProtocolID: ProtocolID, ProtocolVersion: ProtocolVersion,
		MessageType: "bootstrap", Phase: phase, GatewayProbeEndpoint: endpoint,
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
		MessageType: "bootstrap_complete", Phase: phase,
		Status: "server_identity_validated_no_listener", ProcessID: processID,
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
	if request.FormatVersion != FormatVersion || request.ProtocolID != ProtocolID || request.ProtocolVersion != ProtocolVersion || request.MessageType != "bootstrap" ||
		(request.Phase != "initial" && request.Phase != "reconstruction") || protocol.ValidateGatewayEndpoint(request.GatewayProbeEndpoint) != nil ||
		protocol.MatchCredentialRequirements(credentials.GatewayRequirements(), request.CredentialChannelDescriptors) != nil {
		return ErrControlRequest
	}
	return nil
}

func validateResult(result Result) error {
	if result.FormatVersion != FormatVersion || result.ProtocolID != ProtocolID || result.ProtocolVersion != ProtocolVersion || result.MessageType != "bootstrap_complete" ||
		(result.Phase != "initial" && result.Phase != "reconstruction") || result.Status != "server_identity_validated_no_listener" ||
		result.ProcessID < 1 || result.ProcessID > 1<<31-1 {
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
	"format_version", "protocol_id", "protocol_version", "message_type", "phase",
	"gateway_probe_endpoint", "credential_channel_descriptors",
}

var resultKeys = []string{
	"format_version", "protocol_id", "protocol_version", "message_type", "phase", "status", "process_id",
}
