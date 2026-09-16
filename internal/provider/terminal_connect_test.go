package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTerminalConnectDigestAndAdmissionAreFullDescriptorBound(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	descriptor := RuntimeSessionHandoff{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 3, SandboxID: "sandbox-1",
		RuntimeSessionID: "session-1", RuntimeType: "terminal", CapabilityProfileID: "terminal-v1", Protocol: "websocket",
		InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	digest, err := DigestRuntimeSessionConnectDescriptor(descriptor)
	if err != nil || !strings.HasPrefix(digest, "sha256:") {
		t.Fatal("descriptor digest failed")
	}
	admission := Admission{Context: AdmissionContext{
		Operation: "connect_runtime_session", SandboxID: descriptor.SandboxID, OperationID: descriptor.OperationID, AttemptID: descriptor.AttemptID,
		FencingToken: descriptor.FencingToken, DeadlineAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), RequestContractID: RuntimeSessionConnectDescriptorContractID,
		RequestDigestProfile: DescriptorDigestProfile, RequestDigest: digest, HTTPTarget: AdmissionTarget{Method: http.MethodGet, Path: terminalConnectPath, NormalizedQuery: []QueryParameter{}},
	}}
	// Envelope validation intentionally fails before transport for this partial
	// test value; mutate the descriptor and prove its digest changes separately.
	changed := descriptor
	changed.ConnectionGeneration++
	changedDigest, err := DigestRuntimeSessionConnectDescriptor(changed)
	if err != nil || changedDigest == digest {
		t.Fatal("connection generation was not digest-bound")
	}
	client := &Client{}
	if stream, err := client.ConnectRuntimeSession(context.Background(), descriptor, admission); err == nil || stream != nil {
		t.Fatal("partial admission reached transport")
	}
}

func TestTerminalConnectRejectsMalformedDescriptorBeforeTransport(t *testing.T) {
	client := &Client{}
	for _, descriptor := range []RuntimeSessionHandoff{{}, {OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1", RuntimeSessionID: "session-1", RuntimeType: "terminal", CapabilityProfileID: "terminal-v1", Protocol: "websocket", InternalEndpointReference: "https://raw.invalid", ConnectionGeneration: 1, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}} {
		if stream, err := client.ConnectRuntimeSession(context.Background(), descriptor, Admission{}); err == nil || stream != nil {
			t.Fatal("malformed descriptor reached transport")
		}
	}
}
