package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestExecAndSessionRejectMismatchedAdmissionBeforeHTTP(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer, _ := testSigner(t)
	base := testCreateRequest(now)
	exec, err := BindExecRequest(ExecRequest{OperationID: base.OperationID, AttemptID: base.AttemptID, FencingToken: 2, IdempotencyKey: "exec-idempotency", DeadlineAt: base.DeadlineAt, ExpectedGeneration: 1, Command: []string{"true"}, WorkingDirectory: "/workspace", ResultRetentionSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	session, err := BindRuntimeSessionOpenRequest(RuntimeSessionOpenRequest{OperationID: base.OperationID, AttemptID: base.AttemptID, FencingToken: 3, IdempotencyKey: "session-idempotency", DeadlineAt: base.DeadlineAt, ExpectedGeneration: 1, RuntimeSessionID: "session-1", RuntimeType: "terminal", CapabilityProfileID: "terminal-v1", ExpiresAt: base.DeadlineAt})
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"exec", "session"} {
		for _, changed := range []string{"none", "sandbox", "attempt", "fence", "deadline", "digest", "expired", "envelope"} {
			t.Run(family+"/"+changed, func(t *testing.T) {
				binding := testCreateBinding(base, now)
				binding.Operation, binding.RequestContractID, binding.RequestDigest, binding.FencingToken = "exec", ExecRequestContractID, exec.RequestDigest, exec.FencingToken
				binding.HTTPTarget.Path = "/v1/sandboxes/sandbox-1/exec"
				if family == "session" {
					binding.Operation, binding.RequestContractID, binding.RequestDigest, binding.FencingToken = "open_runtime_session", RuntimeSessionRequestContractID, session.RequestDigest, session.FencingToken
					binding.HTTPTarget.Path = "/v1/sandboxes/sandbox-1/runtime-sessions"
				}
				switch changed {
				case "sandbox":
					binding.SandboxID = "sandbox-other"
					binding.HTTPTarget.Path = strings.ReplaceAll(binding.HTTPTarget.Path, "sandbox-1", "sandbox-other")
				case "attempt":
					binding.AttemptID = "other"
				case "fence":
					binding.FencingToken++
				case "deadline":
					binding.DeadlineAt = now.Add(3 * time.Minute).Format(time.RFC3339)
				case "digest":
					binding.RequestDigest = "sha256:" + strings.Repeat("f", 64)
				}
				admission, err := BuildAdmission(testAuthority(), binding, signer)
				if err != nil {
					t.Fatal(err)
				}
				if changed == "envelope" {
					admission.ContextHeader += "A"
				}
				calls := 0
				client, err := NewClient("https://provider.example", roundTripFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					if changed != "none" {
						t.Fatal("invalid binding reached transport")
					}
					if request.URL.Path != binding.HTTPTarget.Path || request.Method != "POST" {
						t.Fatal("wrong route")
					}
					return jsonResponse(t, 202, ProviderOperation{OperationID: binding.OperationID, AttemptID: binding.AttemptID, FencingToken: binding.FencingToken, SandboxID: "sandbox-1", Type: binding.Operation, Status: "accepted", ObservedAt: now.Format(time.RFC3339)}), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				client.now = func() time.Time {
					if changed == "expired" {
						return now.Add(time.Hour)
					}
					return now
				}
				if family == "exec" {
					_, err = client.CreateExec(context.Background(), "sandbox-1", exec, admission)
				} else {
					_, err = client.OpenRuntimeSession(context.Background(), "sandbox-1", session, admission)
				}
				if changed == "none" {
					if err != nil || calls != 1 {
						t.Fatalf("call = %v, %d", err, calls)
					}
				} else if !errors.Is(err, ErrAdmissionBinding) || calls != 0 {
					t.Fatalf("rejection = %v, %d", err, calls)
				}
			})
		}
	}
}

func TestExecRequestBoundsAndOpaqueReferences(t *testing.T) {
	base := ExecRequest{OperationID: "exec-1", AttemptID: "attempt-1", FencingToken: 2, IdempotencyKey: "key-1", DeadlineAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), ExpectedGeneration: 1, Command: []string{"true"}, WorkingDirectory: "/workspace", ResultRetentionSeconds: 60}
	for _, dir := range []string{"/workspace-other", "/workspace/../etc", "/tmp/./x", "/tmp//x", "/etc"} {
		candidate := base
		candidate.WorkingDirectory = dir
		if _, err := BindExecRequest(candidate); err == nil {
			t.Fatalf("accepted %s", dir)
		}
	}
	for name, mutate := range map[string]func(*ExecRequest){
		"capture overflow": func(r *ExecRequest) { r.Capture = &ExecCapture{MaxBytes: 8388609} },
		"bad environment":  func(r *ExecRequest) { r.Environment = map[string]string{"KEY": "envref:"} },
		"bad stdin":        func(r *ExecRequest) { r.StdinReference = "ref:bad\n" },
		"bad secret id":    func(r *ExecRequest) { r.SecretReferenceIDs = []string{"bad secret"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if _, err := BindExecRequest(candidate); err == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
}

func TestNewResponseDecodersEnforceClosedShapesAndBounds(t *testing.T) {
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	result := map[string]any{"operation_id": "exec-1", "attempt_id": "attempt-1", "fencing_token": 2, "sandbox_id": "sandbox-1", "status": "completed", "exit_code": nil, "started_at": stamp, "completed_at": stamp, "retained_until": stamp}
	handoff := map[string]any{"operation_id": "session-op", "attempt_id": "attempt-1", "fencing_token": 3, "sandbox_id": "sandbox-1", "runtime_session_id": "session-1", "runtime_type": "terminal", "capability_profile_id": "terminal-v1", "protocol": "websocket", "internal_endpoint_reference": "ref:session:opaque-1", "connection_generation": 1, "expires_at": stamp}
	usage := map[string]any{"evidence_id": "usage-1", "operation_id": "exec-1", "attempt_id": "attempt-1", "fencing_token": 2, "sandbox_id": "sandbox-1", "entries": []any{map[string]any{"entry_id": "count-1", "sandbox_id": "sandbox-1", "operation_id": "exec-1", "meter": "sandbox.exec_count", "quantity": 1, "unit": "count", "meter_source": "reconciled", "evidence_reference": "ref:usage:1", "occurred_at": stamp}}, "reconciliation_status": "partial", "observed_at": stamp, "retained_until": stamp, "evidence_digest": "sha256:" + strings.Repeat("d", 64)}
	for _, test := range []struct {
		name   string
		base   map[string]any
		decode func([]byte) error
	}{
		{"result", result, func(b []byte) error { return decodeExecResult(b, &ExecResult{}) }},
		{"handoff", handoff, func(b []byte) error { return decodeRuntimeSessionHandoff(b, &RuntimeSessionHandoff{}) }},
		{"usage", usage, func(b []byte) error { return decodeUsageEvidence(b, &UsageEvidence{}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, _ := json.Marshal(test.base)
			if err := test.decode(raw); err != nil {
				t.Fatal(err)
			}
			changes := []func(map[string]any){func(m map[string]any) { m["unknown"] = true }, func(m map[string]any) { delete(m, "operation_id") }, func(m map[string]any) { m["sandbox_id"] = nil }}
			switch test.name {
			case "result":
				changes = append(changes, func(m map[string]any) { m["exit_code"] = 256 }, func(m map[string]any) { m["status"] = "outcome_unknown" }, func(m map[string]any) { m["stdout_reference"] = "https://backend.example" })
			case "handoff":
				changes = append(changes, func(m map[string]any) { m["internal_endpoint_reference"] = "ref:session:host/path" }, func(m map[string]any) { m["connection_generation"] = 0 })
			case "usage":
				changes = append(changes, func(m map[string]any) { m["entries"] = nil }, func(m map[string]any) { m["entries"].([]any)[0].(map[string]any)["sandbox_id"] = "other" }, func(m map[string]any) { m["entries"].([]any)[0].(map[string]any)["unit"] = "bytes" }, func(m map[string]any) { delete(m["entries"].([]any)[0].(map[string]any), "quantity") }, func(m map[string]any) { m["entries"].([]any)[0].(map[string]any)["unknown"] = true })
			}
			for index, mutate := range changes {
				var candidate map[string]any
				_ = json.Unmarshal(raw, &candidate)
				mutate(candidate)
				document, _ := json.Marshal(candidate)
				if err := test.decode(document); !errors.Is(err, ErrInvalidContractDocument) {
					t.Fatalf("change %d accepted", index)
				}
			}
		})
	}
}
