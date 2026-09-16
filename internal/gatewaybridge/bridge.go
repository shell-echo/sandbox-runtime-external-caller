// Package gatewaybridge carries one authorized terminal byte stream between
// the public-facing Gateway child and its credential-owning Caller parent.
// The private socket carries no Provider credential, origin, or Admission key.
package gatewaybridge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerterminal"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gateway"
)

const maxReferenceBytes = 256

var ErrBridge = errors.New("Gateway backend bridge failed")

// Resolver is the child side of a one-connection bridge.
type Resolver struct {
	file *os.File
	mu   sync.Mutex
	used bool
}

func NewResolver(file *os.File) (*Resolver, error) {
	if file == nil {
		return nil, ErrBridge
	}
	return &Resolver{file: file}, nil
}

func (r *Resolver) Open(ctx context.Context, reference string) (io.ReadWriteCloser, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || len(reference) == 0 || len(reference) > maxReferenceBytes {
		return nil, gateway.ErrBackendUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used || r.file == nil {
		return nil, gateway.ErrBackendUnavailable
	}
	r.used = true
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(reference)))
	stop := context.AfterFunc(ctx, func() { _ = r.file.Close() })
	defer stop()
	if writeAll(r.file, header[:]) != nil || writeAll(r.file, []byte(reference)) != nil {
		_ = r.file.Close()
		return nil, gateway.ErrBackendUnavailable
	}
	var status [1]byte
	if _, err := io.ReadFull(r.file, status[:]); err != nil || status[0] != 1 {
		_ = r.file.Close()
		return nil, gateway.ErrBackendUnavailable
	}
	return r.file, nil
}

func (r *Resolver) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	return r.file.Close()
}

// Server owns the caller side and invokes a late-bound credential-owning
// opener once. Closing the service closes both forwarding directions.
type Server struct {
	file   *os.File
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	opener callerterminal.BackendOpener
	set    bool
	closed bool
}

func NewServer(parent context.Context, file *os.File) (*Server, error) {
	if parent == nil || file == nil {
		return nil, ErrBridge
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{file: file, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go s.serve()
	return s, nil
}

func (s *Server) SetOpener(opener callerterminal.BackendOpener) error {
	if s == nil || opener == nil {
		return ErrBridge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set || s.closed || s.ctx.Err() != nil {
		return ErrBridge
	}
	s.opener, s.set = opener, true
	return nil
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	_ = s.file.Close()
	<-s.done
	return nil
}

func (s *Server) serve() {
	defer func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		close(s.done)
	}()
	stop := context.AfterFunc(s.ctx, func() { _ = s.file.Close() })
	defer stop()
	var header [2]byte
	if _, err := io.ReadFull(s.file, header[:]); err != nil {
		return
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < 1 || size > maxReferenceBytes {
		return
	}
	reference := make([]byte, size)
	if _, err := io.ReadFull(s.file, reference); err != nil {
		return
	}
	s.mu.Lock()
	opener := s.opener
	s.mu.Unlock()
	if opener == nil {
		clear(reference)
		_, _ = s.file.Write([]byte{0})
		return
	}
	backend, err := opener(s.ctx, string(reference))
	clear(reference)
	if err != nil || backend == nil {
		_, _ = s.file.Write([]byte{0})
		return
	}
	defer backend.Close()
	if writeAll(s.file, []byte{1}) != nil {
		return
	}
	finished := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(backend, s.file); finished <- struct{}{} }()
	go func() { _, _ = io.Copy(s.file, backend); finished <- struct{}{} }()
	<-finished
	_ = s.file.Close()
	_ = backend.Close()
	<-finished
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil || n < 1 || n > len(value) {
			return ErrBridge
		}
		value = value[n:]
	}
	return nil
}
