//go:build darwin || linux

package gatewayprocess

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func processTransportSupported() bool { return true }

func openBackendPair() (*os.File, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	if syscall.SetNonblock(fds[0], true) != nil || syscall.SetNonblock(fds[1], true) != nil {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		return nil, nil, ErrProcessIO
	}
	parent := os.NewFile(uintptr(fds[0]), "caller-gateway-backend")
	child := os.NewFile(uintptr(fds[1]), "gateway-caller-backend")
	if parent == nil || child == nil {
		if parent != nil {
			_ = parent.Close()
		} else {
			_ = syscall.Close(fds[0])
		}
		if child != nil {
			_ = child.Close()
		} else {
			_ = syscall.Close(fds[1])
		}
		return nil, nil, ErrProcessIO
	}
	return parent, child, nil
}

func configureProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateProcessGroup(process *os.Process) error {
	if process == nil {
		return nil
	}
	err := syscall.Kill(-process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
