package provider

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
)

const (
	terminalConnectPath       = "/v1/runtime-sessions:connect"
	terminalWebSocketProtocol = "sandbox-runtime-terminal.v1"
	maxTerminalMessageBytes   = 65536
)

// DigestRuntimeSessionConnectDescriptor binds the complete retained handoff;
// the terminal-connect descriptor is intentionally the same closed JSON value.
func DigestRuntimeSessionConnectDescriptor(descriptor RuntimeSessionHandoff) (string, error) {
	if validateRuntimeSessionHandoff(descriptor) != nil {
		return "", ErrInvalidContractDocument
	}
	return jcs.Digest(descriptor)
}

// ConnectRuntimeSession performs the protected controller-only WebSocket
// upgrade. It returns an ordered byte stream; WebSocket message boundaries are
// not exposed as terminal semantics.
func (c *Client) ConnectRuntimeSession(ctx context.Context, descriptor RuntimeSessionHandoff, admission Admission) (io.ReadWriteCloser, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || validateRuntimeSessionHandoff(descriptor) != nil {
		return nil, ErrInvalidContractDocument
	}
	digest, err := DigestRuntimeSessionConnectDescriptor(descriptor)
	if err != nil || validateConnectAdmission(descriptor, digest, admission) != nil {
		return nil, ErrInvalidContractDocument
	}
	document, err := jcs.Marshal(descriptor)
	if err != nil || len(document) > 4096 {
		return nil, ErrInvalidContractDocument
	}
	handoffHeader := base64.RawURLEncoding.EncodeToString(document)
	if len(handoffHeader) == 0 || len(handoffHeader) > 5462 || strings.Contains(handoffHeader, "=") {
		return nil, ErrInvalidContractDocument
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+admission.BearerToken)
	header.Set("X-Sandbox-Runtime-Admission-Context", admission.ContextHeader)
	header.Set("X-Sandbox-Runtime-Session-Handoff", handoffHeader)
	connection, response, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(c.origin, "https")+terminalConnectPath, &websocket.DialOptions{
		HTTPClient: c.http, HTTPHeader: header, Subprotocols: []string{terminalWebSocketProtocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil {
			defer response.Body.Close()
			if _, allowed := statusSet(400, 401, 403, 404, 409, 410, 422, 429, 503)[response.StatusCode]; allowed {
				document, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
				if readErr == nil && len(document) <= maxResponseBytes && isJSONMediaType(response.Header.Values("Content-Type")) {
					var standard StandardError
					if decodeStandardError(document, &standard) == nil {
						retryAfter, retryErr := parseRetryAfter(response.Header.Values("Retry-After"))
						if retryErr == nil {
							return nil, &HTTPError{StatusCode: response.StatusCode, Document: standard, RetryAfterSeconds: retryAfter}
						}
					}
				}
			}
		}
		return nil, ErrTransport
	}
	if response == nil || response.StatusCode != http.StatusSwitchingProtocols || connection.Subprotocol() != terminalWebSocketProtocol || response.Header.Get("Sec-WebSocket-Extensions") != "" {
		_ = connection.CloseNow()
		return nil, ErrUnexpectedStatus
	}
	stream := websocket.NetConn(ctx, connection, websocket.MessageBinary)
	// NetConn disables the library default; restore the Contract message bound
	// on the underlying connection after adapting it to bytes.
	connection.SetReadLimit(maxTerminalMessageBytes)
	return stream, nil
}

func validateConnectAdmission(descriptor RuntimeSessionHandoff, digest string, admission Admission) error {
	if validateAdmissionEnvelope(admission) != nil {
		return ErrAdmissionBinding
	}
	context := admission.Context
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, context.DeadlineAt)
	handoffExpiry, expiryErr := time.Parse(time.RFC3339Nano, descriptor.ExpiresAt)
	if context.Operation != "connect_runtime_session" || context.SandboxID != descriptor.SandboxID || context.OperationID != descriptor.OperationID || context.AttemptID != descriptor.AttemptID || context.FencingToken != descriptor.FencingToken || deadlineErr != nil || expiryErr != nil || deadline.After(handoffExpiry) || context.RequestContractID != RuntimeSessionConnectDescriptorContractID || context.RequestDigestProfile != DescriptorDigestProfile || context.RequestDigest != digest || context.HTTPTarget.Method != http.MethodGet || context.HTTPTarget.Path != terminalConnectPath || len(context.HTTPTarget.NormalizedQuery) != 0 {
		return ErrAdmissionBinding
	}
	return nil
}
