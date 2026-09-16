// Package gatewayservice is the caller-private live Gateway service boundary.
// Its authorization stream is not harness input, Provider API, or evidence.
package gatewayservice

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewaycontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
)

const (
	ProtocolID         = "sandbox-runtime-external-caller-private-gateway-service-v1"
	TerminalProtocolID = "sandbox-runtime-external-caller-private-gateway-service-v2"
	MaxBootstrapBytes  = 20 << 10
	MaxCommandBytes    = 16 << 10
	MaxReplyBytes      = 4 << 10
	MaxCommands        = 256
	MaxLifetime        = 5 * time.Minute
)

var ErrControl = errors.New("Gateway service control rejected")

func validToken(token string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == token
}

// Bootstrap is EOF-framed on stdin. It carries no policy, bearer, handoff, or
// secret. ControlDescriptor explicitly declares a separate caller-owned pipe.
type Bootstrap struct {
	ProtocolID        string                 `json:"protocol_id"`
	Bootstrap         gatewaycontrol.Request `json:"bootstrap"`
	ControlDescriptor int                    `json:"control_descriptor"`
	BackendDescriptor int                    `json:"backend_descriptor,omitempty"`
	Deadline          time.Time              `json:"deadline"`
}

func DecodeBootstrap(raw []byte) (Bootstrap, error) {
	var result Bootstrap
	var routing struct {
		ProtocolID string `json:"protocol_id"`
	}
	if json.Unmarshal(raw, &routing) != nil {
		return Bootstrap{}, ErrControl
	}
	keys := []string{"protocol_id", "bootstrap", "control_descriptor", "deadline"}
	if routing.ProtocolID == TerminalProtocolID {
		keys = append(keys, "backend_descriptor")
	}
	if len(raw) > MaxBootstrapBytes || decode(raw, &result, keys...) != nil || (result.ProtocolID != ProtocolID && result.ProtocolID != TerminalProtocolID) || result.ControlDescriptor < 3 || result.ControlDescriptor > 1024 || result.Deadline.IsZero() {
		return Bootstrap{}, ErrControl
	}
	if result.ProtocolID == ProtocolID && result.BackendDescriptor != 0 || result.ProtocolID == TerminalProtocolID && (result.BackendDescriptor < 3 || result.BackendDescriptor > 1024 || result.BackendDescriptor == result.ControlDescriptor) {
		return Bootstrap{}, ErrControl
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	request, err := gatewaycontrol.DecodeRequest(bytes.NewReader(fields["bootstrap"]))
	if err != nil {
		return Bootstrap{}, ErrControl
	}
	for _, descriptor := range request.CredentialChannelDescriptors {
		if descriptor.FileDescriptor == result.ControlDescriptor {
			return Bootstrap{}, ErrControl
		}
		if descriptor.FileDescriptor == result.BackendDescriptor {
			return Bootstrap{}, ErrControl
		}
	}
	result.Bootstrap = request
	return result, nil
}

func EncodeBootstrap(w io.Writer, value Bootstrap) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrControl
	}
	if _, err := DecodeBootstrap(raw); err != nil {
		return err
	}
	return writeLine(w, raw, MaxBootstrapBytes)
}

// Optional members are forbidden outside their exact command variant. Caller
// actor names select the server credential's fixed subject pins, never a
// caller-supplied subject or TLS identity.
type Command struct {
	Sequence         int       `json:"sequence"`
	Action           string    `json:"action"`
	TenantA          string    `json:"tenant_a,omitempty"`
	TenantB          string    `json:"tenant_b,omitempty"`
	Actor            string    `json:"actor,omitempty"`
	TenantID         string    `json:"tenant_id,omitempty"`
	RuntimeSessionID string    `json:"runtime_session_id,omitempty"`
	HandoffReference string    `json:"handoff_reference,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitzero"`
	Token            string    `json:"token,omitempty"`
}

func DecodeCommand(r *bufio.Reader) (Command, error) {
	raw, err := readLine(r, MaxCommandBytes)
	if err != nil {
		return Command{}, err
	}
	var command Command
	if json.Unmarshal(raw, &command) != nil {
		return Command{}, ErrControl
	}
	keys := []string{"sequence", "action"}
	switch command.Action {
	case "install_policy":
		keys = append(keys, "tenant_a", "tenant_b")
	case "issue_grant":
		keys = append(keys, "actor", "tenant_id", "runtime_session_id", "handoff_reference", "expires_at")
	case "revoke":
		keys = append(keys, "actor", "token")
	case "stop":
	default:
		return Command{}, ErrControl
	}
	if decode(raw, &command, keys...) != nil || command.Sequence < 1 || command.Sequence > MaxCommands {
		return Command{}, ErrControl
	}
	if (command.Action == "issue_grant" || command.Action == "revoke") && command.Actor != "controller_a" && command.Actor != "controller_b" {
		return Command{}, ErrControl
	}
	return command, nil
}

func EncodeCommand(w io.Writer, command Command) error {
	raw, err := json.Marshal(command)
	if err != nil {
		return ErrControl
	}
	if _, err := DecodeCommand(bufio.NewReader(bytes.NewReader(append(raw, '\n')))); err != nil {
		return err
	}
	return writeLine(w, raw, MaxCommandBytes)
}

type Reply struct {
	ProtocolID string `json:"protocol_id"`
	Sequence   int    `json:"sequence"`
	Phase      string `json:"phase"`
	ProcessID  int    `json:"process_id"`
	Status     string `json:"status"`
	Token      string `json:"token,omitempty"`
}

func DecodeReply(r *bufio.Reader) (Reply, error) {
	raw, err := readLine(r, MaxReplyBytes)
	if err != nil {
		return Reply{}, err
	}
	var reply Reply
	if json.Unmarshal(raw, &reply) != nil {
		return Reply{}, ErrControl
	}
	keys := []string{"protocol_id", "sequence", "phase", "process_id", "status"}
	if reply.Status == "grant_issued" {
		keys = append(keys, "token")
	}
	if decode(raw, &reply, keys...) != nil || reply.ProtocolID != ProtocolID || reply.Sequence < 0 || reply.Sequence > MaxCommands || reply.ProcessID < 1 || reply.ProcessID > 1<<31-1 || (reply.Phase != "initial" && reply.Phase != "reconstruction") {
		return Reply{}, ErrControl
	}
	switch reply.Status {
	case "listening_policy_unset":
		if reply.Sequence != 0 {
			return Reply{}, ErrControl
		}
	case "policy_installed", "rejected", "revoked", "stopped":
		if reply.Sequence == 0 {
			return Reply{}, ErrControl
		}
	case "grant_issued":
		if reply.Sequence == 0 || !validToken(reply.Token) {
			return Reply{}, ErrControl
		}
	default:
		return Reply{}, ErrControl
	}
	return reply, nil
}

func EncodeReply(w io.Writer, reply Reply) error {
	raw, err := json.Marshal(reply)
	if err != nil {
		return ErrControl
	}
	if _, err := DecodeReply(bufio.NewReader(bytes.NewReader(append(raw, '\n')))); err != nil {
		return err
	}
	return writeLine(w, raw, MaxReplyBytes)
}

func decode(raw []byte, target any, keys ...string) error {
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return ErrControl
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(canonical, &fields) != nil || len(fields) != len(keys) {
		return ErrControl
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(value, []byte("null")) {
			return ErrControl
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrControl
	}
	return nil
}

// ReadSlice bounds allocation even when the peer withholds LF indefinitely.
// Pretty-printed JSON, CRLF, truncation, and empty frames are rejected.
func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	if r == nil {
		return nil, ErrControl
	}
	var raw []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(raw)+len(part) > limit {
			return nil, ErrControl
		}
		raw = append(raw, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil || len(raw) < 2 || raw[len(raw)-1] != '\n' || bytes.IndexByte(raw, '\r') >= 0 {
			return nil, ErrControl
		}
		return raw[:len(raw)-1], nil
	}
}

func writeLine(w io.Writer, raw []byte, limit int) error {
	if w == nil || len(raw)+1 > limit {
		return ErrControl
	}
	raw = append(raw, '\n')
	for len(raw) != 0 {
		n, err := w.Write(raw)
		if err != nil || n <= 0 || n > len(raw) {
			return ErrControl
		}
		raw = raw[n:]
	}
	return nil
}
