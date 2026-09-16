package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestCancelExecBindsExactBodyAdmissionAndAcceptedOperation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request, err := BindCancelExecRequest(CancelExecRequest{
		OperationID: "cancel-operation-1", AttemptID: "cancel-attempt-1", FencingToken: 4,
		IdempotencyKey: "cancel-idempotency-1", DeadlineAt: now.Add(time.Minute).Format(time.RFC3339), ExpectedGeneration: 1,
		TargetOperationID: "exec-operation-1", TargetAttemptID: "exec-attempt-1", Reason: "caller_requested",
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := testSigner(t)
	binding := testCreateBinding(testCreateRequest(now), now)
	binding.Operation, binding.OperationID, binding.AttemptID, binding.FencingToken = "cancel_exec", request.OperationID, request.AttemptID, request.FencingToken
	binding.DeadlineAt, binding.RequestContractID, binding.RequestDigest = request.DeadlineAt, CancelExecRequestContractID, request.RequestDigest
	binding.HTTPTarget.Path = "/v1/sandboxes/sandbox-1/exec:cancel"
	admission, err := BuildAdmission(testAuthority(), binding, signer)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client, err := NewClient("https://provider.example", roundTripFunc(func(httpRequest *http.Request) (*http.Response, error) {
		calls++
		var got CancelExecRequest
		if httpRequest.Method != http.MethodPost || httpRequest.URL.Path != binding.HTTPTarget.Path || json.NewDecoder(httpRequest.Body).Decode(&got) != nil || !reflect.DeepEqual(got, request) {
			t.Fatalf("cancel HTTP request = %s %s / %#v", httpRequest.Method, httpRequest.URL.Path, got)
		}
		return jsonResponse(t, http.StatusAccepted, ProviderOperation{OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken, SandboxID: "sandbox-1", Type: "cancel_exec", Status: "accepted", ObservedAt: now.Format(time.RFC3339)}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	operation, err := client.CancelExec(context.Background(), "sandbox-1", request, admission)
	if err != nil || calls != 1 || operation.Type != "cancel_exec" || operation.Status != "accepted" {
		t.Fatalf("CancelExec = %#v, %v, calls %d", operation, err, calls)
	}

	badAdmission := admission
	badAdmission.Context.RequestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := client.CancelExec(context.Background(), "sandbox-1", request, badAdmission); !errors.Is(err, ErrAdmissionBinding) || calls != 1 {
		t.Fatalf("mismatched admission = %v, calls %d", err, calls)
	}
}

func TestCancelExecRequestRejectsInvalidAuthorityFields(t *testing.T) {
	base := CancelExecRequest{
		OperationID: "cancel-operation-1", AttemptID: "cancel-attempt-1", FencingToken: 4,
		IdempotencyKey: "cancel-idempotency-1", DeadlineAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), ExpectedGeneration: 1,
		TargetOperationID: "exec-operation-1", TargetAttemptID: "exec-attempt-1", Reason: "caller_requested",
	}
	for name, mutate := range map[string]func(*CancelExecRequest){
		"missing target": func(request *CancelExecRequest) { request.TargetOperationID = "" },
		"bad reason":     func(request *CancelExecRequest) { request.Reason = "unknown" },
		"zero generation": func(request *CancelExecRequest) {
			request.ExpectedGeneration = 0
		},
		"stale digest": func(request *CancelExecRequest) {
			request.RequestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if _, err := BindCancelExecRequest(candidate); err == nil {
				t.Fatal("invalid cancellation request accepted")
			}
		})
	}
}
