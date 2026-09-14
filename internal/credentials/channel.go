// Package credentials owns the external caller candidate's private credential
// delivery formats. None of these payloads are Provider wire API or evidence.
package credentials

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const (
	ProviderCredentialMediaType = "application/vnd.shell-echo.sandbox-provider-client-credentials-v1+json"
	GatewayCredentialMediaType  = "application/vnd.shell-echo.sandbox-gateway-client-credentials-v1+json"
	GatewayServerMediaType      = "application/vnd.shell-echo.sandbox-gateway-server-credentials-v1+json"
	TrustMediaType              = "application/pem-certificate-chain"

	credentialChannelBytes = 256 << 10
	trustChannelBytes      = 256 << 10
)

var (
	ErrUnsupportedPlatform = errors.New("credential channel transport is unsupported on this platform")
	ErrReaderConsumed      = errors.New("credential channel reader is already consumed")
	ErrDescriptorMismatch  = errors.New("credential channel descriptors do not match startup requirements")
	ErrNotPipe             = errors.New("credential channel file descriptor is not a pipe")
	ErrChannelRead         = errors.New("credential channel read failed")
	ErrChannelLimit        = errors.New("credential channel byte limit exceeded")
	ErrUnknownChannel      = errors.New("credential channel is not present")
)

// Requirements returns the candidate's fixed, ordered startup declaration.
// It contains no file descriptors and is safe to emit before harness input or
// credential delivery.
func Requirements() []protocol.ChannelRequirement {
	return []protocol.ChannelRequirement{
		{ChannelID: "provider-controller-a", Role: "provider_credentials", Actor: protocol.NamedActor("controller_a"), MediaType: ProviderCredentialMediaType, MaxBytes: credentialChannelBytes},
		{ChannelID: "provider-controller-b", Role: "provider_credentials", Actor: protocol.NamedActor("controller_b"), MediaType: ProviderCredentialMediaType, MaxBytes: credentialChannelBytes},
		{ChannelID: "provider-same-ca-unadmitted", Role: "provider_credentials", Actor: protocol.NamedActor("same_ca_unadmitted"), MediaType: ProviderCredentialMediaType, MaxBytes: credentialChannelBytes},
		{ChannelID: "provider-trust", Role: "provider_trust", Actor: protocol.NullActor(), MediaType: TrustMediaType, MaxBytes: trustChannelBytes},
		{ChannelID: "gateway-controller-a", Role: "gateway_credentials", Actor: protocol.NamedActor("controller_a"), MediaType: GatewayCredentialMediaType, MaxBytes: credentialChannelBytes},
		{ChannelID: "gateway-controller-b", Role: "gateway_credentials", Actor: protocol.NamedActor("controller_b"), MediaType: GatewayCredentialMediaType, MaxBytes: credentialChannelBytes},
		{ChannelID: "gateway-trust", Role: "gateway_trust", Actor: protocol.NullActor(), MediaType: TrustMediaType, MaxBytes: trustChannelBytes},
		{ChannelID: "gateway-server", Role: "gateway_credentials", Actor: protocol.NullActor(), MediaType: GatewayServerMediaType, MaxBytes: credentialChannelBytes},
	}
}

// GatewayRequirements returns the exact credential subset remapped onto the
// private caller-to-Gateway process boundary. The Provider-facing startup
// declaration is the full eight-channel Requirements set. The Gateway must
// never receive Provider or Gateway client private keys.
func GatewayRequirements() []protocol.ChannelRequirement {
	requirements := Requirements()
	return []protocol.ChannelRequirement{requirements[7], requirements[6]}
}

// Reader consumes one exact descriptor set once. The descriptors are expected
// to name inherited readable anonymous-pipe file descriptors.
type Reader struct {
	mu           sync.Mutex
	requirements []protocol.ChannelRequirement
	consumed     bool
}

func NewReader(requirements []protocol.ChannelRequirement) *Reader {
	return &Reader{requirements: append([]protocol.ChannelRequirement(nil), requirements...)}
}

// Bundle owns credential bytes until Destroy. Callers must not retain slices
// passed to Use after the callback returns. Go cannot guarantee locked memory,
// so zeroing here is best-effort process-local hygiene, not a secrecy proof.
type Bundle struct {
	mu        sync.Mutex
	payloads  map[string][]byte
	total     int
	destroyed bool
}

func (r *Reader) Read(descriptors []protocol.ChannelDescriptor) (*Bundle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.consumed {
		return nil, ErrReaderConsumed
	}
	r.consumed = true

	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, ErrUnsupportedPlatform
	}
	if err := protocol.MatchCredentialRequirements(r.requirements, descriptors); err != nil {
		return nil, ErrDescriptorMismatch
	}

	bundle := &Bundle{payloads: make(map[string][]byte, len(descriptors))}
	for _, descriptor := range descriptors {
		payload, err := readPipe(descriptor)
		if err != nil {
			bundle.Destroy()
			return nil, err
		}
		bundle.payloads[descriptor.ChannelID] = payload
		bundle.total += len(payload)
		if bundle.total > protocol.MaxCredentialTotalBytes {
			bundle.Destroy()
			return nil, ErrChannelLimit
		}
	}
	return bundle, nil
}

func readPipe(descriptor protocol.ChannelDescriptor) ([]byte, error) {
	file := os.NewFile(uintptr(descriptor.FileDescriptor), descriptor.ChannelID)
	if file == nil {
		return nil, ErrChannelRead
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, ErrChannelRead
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return nil, ErrNotPipe
	}
	payload, err := io.ReadAll(io.LimitReader(file, int64(descriptor.MaxBytes)+1))
	if err != nil {
		zero(payload)
		return nil, ErrChannelRead
	}
	if len(payload) > descriptor.MaxBytes {
		zero(payload)
		return nil, ErrChannelLimit
	}
	return payload, nil
}

// Use exposes one payload only for the duration of callback. It does not copy
// the secret. Destroy remains mandatory after all required payloads are used.
func (b *Bundle) Use(channelID string, callback func([]byte) error) error {
	if callback == nil {
		return ErrUnknownChannel
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return ErrUnknownChannel
	}
	payload, ok := b.payloads[channelID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownChannel, channelID)
	}
	return callback(payload)
}

// UsePair exposes two payloads under one bundle lock. It avoids copying trust
// material when constructing multiple caller-owned transports.
func (b *Bundle) UsePair(firstChannelID, secondChannelID string, callback func([]byte, []byte) error) error {
	if callback == nil || firstChannelID == secondChannelID {
		return ErrUnknownChannel
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return ErrUnknownChannel
	}
	first, firstOK := b.payloads[firstChannelID]
	second, secondOK := b.payloads[secondChannelID]
	if !firstOK || !secondOK {
		return ErrUnknownChannel
	}
	return callback(first, second)
}

func (b *Bundle) TotalBytes() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return 0
	}
	return b.total
}

func (b *Bundle) Destroy() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return
	}
	for channelID, payload := range b.payloads {
		zero(payload)
		delete(b.payloads, channelID)
	}
	b.total = 0
	b.destroyed = true
}

func zero(payload []byte) {
	for index := range payload {
		payload[index] = 0
	}
}
