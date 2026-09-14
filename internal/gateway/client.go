package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const maxResponseHeaderBytes = 16 << 10

var (
	ErrClientConfiguration = errors.New("gateway client configuration is invalid")
	ErrGatewayTransport    = errors.New("gateway transport failed")
	ErrUpgradeRejected     = errors.New("gateway CONNECT upgrade was rejected")
	ErrResponseHeader      = errors.New("gateway response header is invalid or oversized")
)

// DialTunnel performs the candidate-private HTTP/1.1 CONNECT handshake over
// direct mTLS. It does not use environment proxy settings.
func DialTunnel(ctx context.Context, endpoint, token string, config *tls.Config) (net.Conn, error) {
	return dialTunnel(ctx, endpoint, token, config, true)
}

// DialTunnelWithoutClientCertificate performs the locked unauthenticated
// negative probe. It deliberately permits no client certificate while keeping
// every server-authentication requirement enforced.
func DialTunnelWithoutClientCertificate(ctx context.Context, endpoint, token string, config *tls.Config) (net.Conn, error) {
	return dialTunnel(ctx, endpoint, token, config, false)
}

func dialTunnel(ctx context.Context, endpoint, token string, config *tls.Config, requireClientCertificate bool) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if protocol.ValidateGatewayEndpoint(endpoint) != nil {
		return nil, ErrClientConfiguration
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || config == nil || config.InsecureSkipVerify || config.RootCAs == nil || config.ServerName != parsed.Hostname() || config.MinVersion < tls.VersionTLS12 || len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" {
		return nil, ErrClientConfiguration
	}
	certificateCount := len(config.Certificates)
	if (requireClientCertificate && certificateCount != 1) || (!requireClientCertificate && certificateCount != 0) {
		return nil, ErrClientConfiguration
	}
	if _, ok := tokenKey(token); !ok {
		return nil, ErrClientConfiguration
	}
	address := parsed.Host
	if parsed.Port() == "" {
		address = net.JoinHostPort(parsed.Hostname(), "443")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	rawConnection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, ErrGatewayTransport
	}
	connection := tls.Client(rawConnection, config.Clone())
	cancelWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-cancelWatch:
		}
	}()
	defer close(cancelWatch)
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, ErrGatewayTransport
	}
	negotiated := connection.ConnectionState()
	if !negotiated.NegotiatedProtocolIsMutual || negotiated.NegotiatedProtocol != "http/1.1" {
		_ = connection.Close()
		return nil, ErrGatewayTransport
	}
	requestHeader := "CONNECT " + parsed.EscapedPath() + " HTTP/1.1\r\nHost: " + parsed.Host + "\r\nAuthorization: Bearer " + token + "\r\nConnection: keep-alive\r\n\r\n"
	if err := writeAll(connection, []byte(requestHeader)); err != nil {
		_ = connection.Close()
		return nil, ErrGatewayTransport
	}
	reader := bufio.NewReaderSize(connection, 4096)
	header, err := readResponseHeader(reader)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, endpoint, nil)
	if err != nil {
		_ = connection.Close()
		return nil, ErrClientConfiguration
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), request)
	if err != nil {
		_ = connection.Close()
		return nil, ErrResponseHeader
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > 0 || len(response.TransferEncoding) != 0 {
		_ = connection.Close()
		return nil, ErrUpgradeRejected
	}
	_ = connection.SetDeadline(time.Time{})
	return &bufferedConn{Conn: connection, reader: reader}, nil
}

func readResponseHeader(reader *bufio.Reader) ([]byte, error) {
	var header bytes.Buffer
	for {
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasSuffix(line, "\r\n") || header.Len()+len(line) > maxResponseHeaderBytes {
			return nil, ErrResponseHeader
		}
		header.WriteString(line)
		if line == "\r\n" {
			return header.Bytes(), nil
		}
	}
}

func writeAll(writer io.Writer, document []byte) error {
	for len(document) > 0 {
		written, err := writer.Write(document)
		if err != nil || written <= 0 || written > len(document) {
			return ErrGatewayTransport
		}
		document = document[written:]
	}
	return nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedConn) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}
