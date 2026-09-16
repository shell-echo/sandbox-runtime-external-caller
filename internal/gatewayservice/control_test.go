package gatewayservice

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewaycontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func testBootstrap(t *testing.T) Bootstrap {
	t.Helper()
	var descriptors []protocol.ChannelDescriptor
	for i, r := range credentials.GatewayRequirements() {
		descriptors = append(descriptors, protocol.ChannelDescriptor{ChannelID: r.ChannelID, Role: r.Role, Actor: r.Actor, MediaType: r.MediaType, MaxBytes: r.MaxBytes, FileDescriptor: 3 + i})
	}
	request, err := gatewaycontrol.NewRequest("initial", "https://gateway.example/tunnel", descriptors)
	if err != nil {
		t.Fatal(err)
	}
	return Bootstrap{ProtocolID: ProtocolID, Bootstrap: request, ControlDescriptor: 5, Deadline: time.Now().UTC().Add(time.Minute)}
}

func TestBootstrapClosedAndDistinctFromValidation(t *testing.T) {
	bootstrap := testBootstrap(t)
	var buffer bytes.Buffer
	if err := EncodeBootstrap(&buffer, bootstrap); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBootstrap(buffer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := gatewaycontrol.DecodeRequest(bytes.NewReader(buffer.Bytes())); err == nil {
		t.Fatal("service accepted as finite validation")
	}
	raw := buffer.String()
	for name, value := range map[string]string{
		"missing":          strings.Replace(raw, `"control_descriptor":5,`, "", 1),
		"credential alias": strings.Replace(raw, `"control_descriptor":5`, `"control_descriptor":3`, 1),
		"stdio":            strings.Replace(raw, `"control_descriptor":5`, `"control_descriptor":0`, 1),
		"unknown":          strings.Replace(raw, `"control_descriptor":5`, `"control_descriptor":5,"tenant_id":"injected"`, 1),
		"duplicate":        strings.Replace(raw, `"control_descriptor":5`, `"control_descriptor":5,"control_descriptor":6`, 1),
		"nested secret":    strings.Replace(raw, `"message_type":"bootstrap"`, `"message_type":"bootstrap","private_key":"marker"`, 1),
		"null deadline":    strings.Replace(raw, `"deadline":"`+bootstrap.Deadline.Format(time.RFC3339Nano)+`"`, `"deadline":null`, 1),
		"oversize":         strings.Repeat(" ", MaxBootstrapBytes) + raw,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBootstrap([]byte(value)); err == nil {
				t.Fatal("accepted invalid bootstrap")
			}
		})
	}
}

func TestTerminalBootstrapRequiresDistinctBackendDescriptor(t *testing.T) {
	bootstrap := testBootstrap(t)
	bootstrap.ProtocolID = TerminalProtocolID
	bootstrap.BackendDescriptor = 6
	var buffer bytes.Buffer
	if err := EncodeBootstrap(&buffer, bootstrap); err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeBootstrap(buffer.Bytes()); err != nil || got.BackendDescriptor != 6 {
		t.Fatalf("terminal bootstrap roundtrip: %v", err)
	}
	raw := buffer.String()
	for name, value := range map[string]string{
		"missing":          strings.Replace(raw, `,"backend_descriptor":6`, "", 1),
		"control alias":    strings.Replace(raw, `"backend_descriptor":6`, `"backend_descriptor":5`, 1),
		"credential alias": strings.Replace(raw, `"backend_descriptor":6`, `"backend_descriptor":3`, 1),
		"stdio":            strings.Replace(raw, `"backend_descriptor":6`, `"backend_descriptor":1`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBootstrap([]byte(value)); err == nil {
				t.Fatal("accepted invalid terminal bootstrap")
			}
		})
	}
}

func TestCommandFramingClosedVariantsAndBounds(t *testing.T) {
	commands := []Command{
		{Sequence: 1, Action: "install_policy", TenantA: "tenant-a", TenantB: "tenant-b"},
		{Sequence: 2, Action: "issue_grant", Actor: "controller_a", TenantID: "tenant-a", RuntimeSessionID: "session-a", HandoffReference: "opaque-handoff", ExpiresAt: time.Now().UTC().Add(time.Minute)},
		{Sequence: 3, Action: "revoke", Actor: "controller_a", Token: strings.Repeat("A", 43)},
		{Sequence: 4, Action: "stop"},
	}
	var buffer bytes.Buffer
	for _, command := range commands {
		if err := EncodeCommand(&buffer, command); err != nil {
			t.Fatal(err)
		}
	}
	reader := bufio.NewReaderSize(&buffer, 32)
	for _, expected := range commands {
		got, err := DecodeCommand(reader)
		if err != nil || got != expected {
			t.Fatalf("command roundtrip: %v", err)
		}
	}
	for _, raw := range []string{
		`{"sequence":1,"action":"stop","token":"secret"}` + "\n",
		`{"sequence":1,"sequence":2,"action":"stop"}` + "\n",
		`{"sequence":1,"action":null}` + "\n",
		`{"sequence":0,"action":"stop"}` + "\n",
		`{"sequence":257,"action":"stop"}` + "\n",
		`{"sequence":1,"action":"stop"}`,
		`{"sequence":1,"action":"stop"}` + "\r\n",
		`{"sequence":1,"action":"stop"} {}` + "\n",
		"{\n\"sequence\":1,\"action\":\"stop\"}\n",
		strings.Repeat("a", MaxCommandBytes+1) + "\n",
		`{"sequence":1,"action":"install_policy","tenant_a":"a","tenant_b":null}` + "\n",
	} {
		if _, err := DecodeCommand(bufio.NewReader(strings.NewReader(raw))); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
}

func TestReplyCannotClaimQualificationOrLeakExtraData(t *testing.T) {
	ready := Reply{ProtocolID: ProtocolID, Sequence: 0, Phase: "initial", ProcessID: 123, Status: "listening_policy_unset"}
	var buffer bytes.Buffer
	if err := EncodeReply(&buffer, ready); err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeReply(bufio.NewReader(&buffer)); err != nil || got != ready {
		t.Fatal("ready roundtrip")
	}
	for _, status := range []string{"passed", "failed", "compatible", "server_identity_validated_no_listener", "grant_issued", "stopped"} {
		changed := ready
		changed.Status = status
		if err := EncodeReply(&buffer, changed); err == nil {
			t.Fatal("invalid status/sequence accepted")
		}
	}
	ready.Status, ready.Sequence, ready.Token = "grant_issued", 1, strings.Repeat("A", 43)
	if err := EncodeReply(&buffer, ready); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ready)
	raw = []byte(strings.Replace(string(raw), `"status":"grant_issued"`, `"status":"grant_issued","endpoint":"secret"`, 1) + "\n")
	if _, err := DecodeReply(bufio.NewReader(bytes.NewReader(raw))); err == nil {
		t.Fatal("extra evidence data accepted")
	}
}
