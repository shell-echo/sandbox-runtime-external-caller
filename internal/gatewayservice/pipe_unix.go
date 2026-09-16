//go:build darwin || linux

package gatewayservice

import (
	"os"
	"runtime"
	"syscall"
)

// OpenCommandPipe adopts the explicitly declared inherited descriptor. Go's
// NewFile cannot interrupt a blocking inherited FD: enable nonblocking mode
// before wrapping it so Close/deadline cancellation uses the runtime poller.
func OpenCommandPipe(fd int) (*os.File, error) {
	if fd < 3 || fd > 1024 {
		return nil, ErrControl
	}
	return adoptPollablePipe(fd)
}

func OpenBackendPipe(fd int) (*os.File, error) {
	if fd < 3 || fd > 1024 {
		return nil, ErrControl
	}
	var status syscall.Stat_t
	if syscall.Fstat(fd, &status) != nil || status.Mode&syscall.S_IFMT != syscall.S_IFSOCK || syscall.SetNonblock(fd, true) != nil {
		_ = syscall.Close(fd)
		return nil, ErrControl
	}
	syscall.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "gateway-backend-bridge")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrControl
	}
	return file, nil
}

// DuplicateOutputPipe preserves the caller's File ownership. Only this returned
// wrapper performs service output; the original must not be used concurrently.
func DuplicateOutputPipe(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, ErrControl
	}
	fd, err := syscall.Dup(int(source.Fd()))
	runtime.KeepAlive(source)
	if err != nil {
		return nil, ErrControl
	}
	return adoptPollablePipe(fd)
}

func adoptPollablePipe(fd int) (*os.File, error) {
	var status syscall.Stat_t
	if syscall.Fstat(fd, &status) != nil || status.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		_ = syscall.Close(fd)
		return nil, ErrControl
	}
	if syscall.SetNonblock(fd, true) != nil {
		_ = syscall.Close(fd)
		return nil, ErrControl
	}
	syscall.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "gateway-service-pipe")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrControl
	}
	return file, nil
}
