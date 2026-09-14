package main

import (
	"io"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayservice"
)

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, gatewayservice.MaxBootstrapBytes+1))
	if err != nil || len(raw) > gatewayservice.MaxBootstrapBytes {
		os.Exit(65)
	}
	bootstrap, err := gatewayservice.DecodeBootstrap(raw)
	if err != nil {
		os.Exit(65)
	}
	reply := gatewayservice.Reply{
		ProtocolID: gatewayservice.ProtocolID, Sequence: 0,
		Phase: bootstrap.Bootstrap.Phase, ProcessID: os.Getpid(), Status: "listening_policy_unset",
	}
	if gatewayservice.EncodeReply(os.Stdout, reply) != nil {
		os.Exit(74)
	}
	// Deliberately ignore the caller control pipe. The supervisor must interrupt
	// a pending reply read and kill/reap this adversarial helper.
	for {
		time.Sleep(time.Hour)
	}
}
