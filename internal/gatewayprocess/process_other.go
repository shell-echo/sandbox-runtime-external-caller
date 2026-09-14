//go:build !darwin && !linux

package gatewayprocess

import (
	"os"
	"os/exec"
)

func processTransportSupported() bool { return false }

func configureProcessGroup(*exec.Cmd) {}

func terminateProcessGroup(process *os.Process) error {
	if process == nil {
		return nil
	}
	return process.Kill()
}
