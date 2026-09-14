package jcs

import (
	"strings"
	"testing"
)

func TestCanonicalizeSortsUTF16AndUsesRequiredStringEscapes(t *testing.T) {
	document := []byte("{\"\\u20ac\":1,\"\\r\":2,\"\\ufb33\":3,\"1\":4,\"😀\":5,\"\\u0080\":6,\"ö\":7}")
	canonical, err := Canonicalize(document)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"\\r\":2,\"1\":4,\"\":6,\"ö\":7,\"€\":1,\"😀\":5,\"דּ\":3}"
	if string(canonical) != want {
		t.Fatalf("canonical JSON = %q, want %q", canonical, want)
	}
	unicode, err := Canonicalize([]byte("{\"value\":\"<>&\\u2028\\u2029\"}"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unicode), `\u003c`) || strings.Contains(string(unicode), `\u2028`) {
		t.Fatalf("canonical string used non-JCS escaping: %q", unicode)
	}
}

func TestCanonicalizeRejectsUnsafeDocuments(t *testing.T) {
	for _, document := range []string{
		`{"a":1,"a":2}`,
		`{"a":"\uD800"}`,
		`{} {}`,
	} {
		if _, err := Canonicalize([]byte(document)); err == nil {
			t.Fatalf("Canonicalize(%q) accepted unsafe input", document)
		}
	}
	if canonical, err := Canonicalize([]byte(`[-0,1.0,1e0,0.000001,0.0000001,1e21]`)); err != nil || string(canonical) != `[0,1,1,0.000001,1e-7,1e+21]` {
		t.Fatalf("number canonicalization = %q, %v", canonical, err)
	}
	if canonical, err := Canonicalize([]byte(`[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]`)); err != nil || string(canonical) != `[333333333.3333333,1e+30,4.5,0.002,1e-27]` {
		t.Fatalf("RFC number vector = %q, %v", canonical, err)
	}
}

func TestDigestExcludingAdmissionContextFixture(t *testing.T) {
	context := map[string]any{
		"context_contract_id":        "urn:shell-echo:sandbox-runtime:admission-context:v1",
		"context_digest_profile":     "rfc8785-full-document-excluding-context-digest-v1",
		"context_digest":             "sha256:b2a8f83541acfff6edf650d5c2dfd8fcf068915d3009b542a3ebb4670a310633",
		"controller_subject":         "spiffe://provider/controller",
		"provider_revision_id":       "provider-revision-1",
		"provider_instance_audience": "urn:shell-echo:sandbox-runtime:provider-instance:provider-1",
		"tenant_id":                  "tenant-1",
		"work_order_id":              "work-order-1",
		"policy_digest":              "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"policy_decided_at":          "2026-08-20T00:00:00Z",
		"operation":                  "exec",
		"sandbox_id":                 "sandbox-1",
		"operation_id":               "operation-1",
		"attempt_id":                 "attempt-1",
		"fencing_token":              1,
		"deadline_at":                "2026-08-20T00:04:00Z",
		"request_contract_id":        "urn:shell-echo:sandbox-runtime:request:exec:v1",
		"request_digest_profile":     "rfc8785-request-excluding-request-digest-v1",
		"request_digest":             "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"http_target": map[string]any{
			"method": "POST", "path": "/v1/sandboxes/sandbox-1/exec", "normalized_query": []any{},
		},
	}
	digest, err := DigestExcluding(context, "context_digest")
	if err != nil {
		t.Fatal(err)
	}
	want := "sha256:b2a8f83541acfff6edf650d5c2dfd8fcf068915d3009b542a3ebb4670a310633"
	if digest != want {
		t.Fatalf("admission context digest = %q, want %q", digest, want)
	}
}
