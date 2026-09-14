package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayprocess"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

type request struct {
	Phase    string    `json:"phase"`
	Endpoint string    `json:"endpoint"`
	Deadline time.Time `json:"deadline"`
}

type result struct {
	GatewayPID int    `json:"gateway_pid"`
	Token      string `json:"token"`
}

func main() {
	if len(os.Args) != 1 {
		os.Exit(64)
	}
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()
	var input request
	if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		os.Exit(65)
	}
	requirements := credentials.Requirements()
	descriptors := make([]protocol.ChannelDescriptor, 0, len(requirements))
	for index, requirement := range requirements {
		descriptors = append(descriptors, protocol.ChannelDescriptor{
			ChannelID: requirement.ChannelID, Role: requirement.Role, Actor: requirement.Actor,
			MediaType: requirement.MediaType, MaxBytes: requirement.MaxBytes, FileDescriptor: 3 + index,
		})
	}
	bundle, err := credentials.NewReader(requirements).Read(descriptors)
	if err != nil {
		os.Exit(65)
	}
	defer bundle.Destroy()
	ctx, cancel := context.WithDeadline(context.Background(), input.Deadline)
	defer cancel()
	service, err := gatewayprocess.NewSiblingServiceRunner().Start(ctx, input.Phase, input.Endpoint, bundle)
	if err != nil {
		os.Exit(70)
	}
	operation, operationCancel := context.WithTimeout(ctx, 3*time.Second)
	defer operationCancel()
	if service.InstallPolicy(operation, "tenant-a", "tenant-b") != nil {
		os.Exit(70)
	}
	token, err := service.IssueGrant(operation, "controller_a", "tenant-a", "session-a", "opaque-test-handoff", input.Deadline.Add(-time.Second))
	if err != nil {
		os.Exit(70)
	}
	if json.NewEncoder(os.Stdout).Encode(result{GatewayPID: service.PID(), Token: token}) != nil {
		os.Exit(74)
	}
	trigger := os.NewFile(11, "abrupt-parent-trigger")
	if trigger == nil {
		os.Exit(65)
	}
	var one [1]byte
	if count, err := trigger.Read(one[:]); err != nil || count != 1 {
		os.Exit(74)
	}
	// Intentionally bypass defers and Service.Stop. Closing process-owned FDs is
	// the behavior under test: the Gateway must observe liveness-pipe EOF.
	os.Exit(0)
}
