package gateway

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
)

type Handler struct {
	gateway *Gateway
	path    string
}

func NewHandler(gateway *Gateway, endpointPath string) (*Handler, error) {
	if gateway == nil || !validEndpointPath(endpointPath) {
		return nil, ErrPolicy
	}
	return &Handler{gateway: gateway, path: endpointPath}, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect || request.ProtoMajor != 1 || request.URL.Path != h.path || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		reject(response, http.StatusForbidden)
		return
	}
	subject, ok := verifiedControllerSubject(request.TLS)
	if !ok {
		reject(response, http.StatusForbidden)
		return
	}
	token, ok := bearerToken(request.Header)
	if !ok {
		reject(response, http.StatusForbidden)
		return
	}
	permit, err := h.gateway.BeginConnect(request.Context(), token, subject)
	if err != nil {
		reject(response, http.StatusForbidden)
		return
	}
	defer permit.Close()
	backend, err := h.gateway.openBackend(permit.Context(), permit.Binding().HandoffReference)
	if err != nil {
		reject(response, http.StatusBadGateway)
		return
	}
	hijacker, ok := response.(http.Hijacker)
	if !ok {
		_ = backend.Close()
		reject(response, http.StatusBadGateway)
		return
	}
	frontend, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = backend.Close()
		return
	}
	if err := permit.Attach(frontend, backend); err != nil {
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n"); err != nil || buffered.Flush() != nil {
		return
	}
	proxyTunnel(permit, frontend, buffered.Reader, backend)
}

func proxyTunnel(permit *Permit, frontend net.Conn, frontendReader *bufio.Reader, backend io.ReadWriteCloser) {
	completed := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(backend, frontendReader)
		completed <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(frontend, backend)
		completed <- struct{}{}
	}()
	<-completed
	_ = permit.Close()
	<-completed
}

func reject(response http.ResponseWriter, status int) {
	response.Header().Set("Connection", "close")
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(status)
}

func bearerToken(header http.Header) (string, bool) {
	values := header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || strings.Contains(values[0], ",") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	_, ok := tokenKey(token)
	return token, ok
}

func verifiedControllerSubject(state *tls.ConnectionState) (string, bool) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", false
	}
	leaf := state.VerifiedChains[0][0]
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil || !leaf.URIs[0].IsAbs() || leaf.URIs[0].Fragment != "" {
		return "", false
	}
	return leaf.URIs[0].String(), true
}

func validEndpointPath(value string) bool {
	if value == "" || value[0] != '/' || len(value) > 512 || pathpkg.Clean(value) != value || strings.ContainsAny(value, "\\?#%") {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Path == value && parsed.RawQuery == ""
}
