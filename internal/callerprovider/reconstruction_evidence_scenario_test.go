//go:build darwin || linux

package callerprovider

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestReconstructionEvidenceReadsRetainedDocumentsWithExactDigests(t *testing.T) {
	_, store, resultDocument, usageDocument, artifactDocument := completeStoreWithEvidence(t)
	defer store.Close()
	before := store.Snapshot()
	capabilities, raw := selectedCapabilities(t)
	resultReads := 0
	retryAfter := 1
	client := &fakeClient{capabilities: capabilities, raw: raw, store: store, result: resultDocument, usage: usageDocument, artifactEvidence: artifactDocument}
	client.hook = func(step string) error {
		if step == "result" {
			resultReads++
			if resultReads == 1 {
				return &provider.HTTPError{StatusCode: http.StatusServiceUnavailable, Document: provider.StandardError{Code: "TEMPORARY", Message: "retry", Retryable: true, TraceID: "test-trace"}, RetryAfterSeconds: &retryAfter}
			}
		}
		return nil
	}
	service := &scenarioGatewayFake{}
	executor, err := NewInitialScenarioExecutorWithGateway("https://provider.example", "https://gateway.example/tunnel", &credentials.Bundle{}, store, func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := 0
	executor.buildProviderAccess = fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionCapabilityCaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionLifecycleCaseID); err != nil {
		t.Fatal(err)
	}
	admissionStart := len(client.admissions)
	result, err := executor.Execute(ctx, scenariocontrol.ReconstructionEvidenceCaseID)
	if err != nil {
		t.Fatal(err)
	}
	wantObservations := []string{"same-exec-result-completed", "same-usage-evidence-digest", "same-artifact-evidence-digest"}
	if result.CaseID != scenariocontrol.ReconstructionEvidenceCaseID || result.Disposition != "completed" || len(result.Interactions) != 3 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, wantObservations) {
		t.Fatalf("reconstruction evidence result = %#v", result)
	}
	for index, interactionID := range []string{"read-retained-exec-result", "read-retained-usage", "read-retained-artifact-evidence"} {
		interaction := result.Interactions[index]
		wantAttempts := 1
		if index == 0 {
			wantAttempts = 2
		}
		if interaction.InteractionID != interactionID || interaction.WireAttempts != wantAttempts || interaction.FinalOutcome.StatusCode == nil || *interaction.FinalOutcome.StatusCode != http.StatusOK || interaction.MutationWriteObserved {
			t.Fatalf("reconstruction evidence interaction %d = %#v", index, interaction)
		}
	}
	if len(result.Interactions[0].TransientOutcomes) != 1 || result.Interactions[0].TransientOutcomes[0].StatusCode == nil || *result.Interactions[0].TransientOutcomes[0].StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("reconstruction evidence retry = %#v", result.Interactions[0])
	}
	newAdmissions := client.admissions[admissionStart:]
	if len(newAdmissions) != 4 {
		t.Fatalf("reconstruction evidence admissions = %#v", newAdmissions)
	}
	seenJTI := make(map[string]struct{}, len(newAdmissions))
	for _, admission := range newAdmissions {
		if _, duplicate := seenJTI[admission.Claims.JTI]; duplicate {
			t.Fatalf("reconstruction evidence reused JTI %q", admission.Claims.JTI)
		}
		seenJTI[admission.Claims.JTI] = struct{}{}
	}
	if executor.next != 3 || service.stopped || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("reconstruction evidence composition = next %d service %#v state %#v", executor.next, service, store.Snapshot())
	}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	if !service.stopped || closed != 1 || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("reconstruction evidence cleanup = service %#v closed %d state %#v", service, closed, store.Snapshot())
	}
}

func TestReconstructionEvidenceRejectsDigestMismatchWithoutStateMutation(t *testing.T) {
	_, store, resultDocument, usageDocument, artifactDocument := completeStoreWithEvidence(t)
	defer store.Close()
	before := store.Snapshot()
	usageDocument.EvidenceID = "different-evidence"
	capabilities, raw := selectedCapabilities(t)
	client := &fakeClient{capabilities: capabilities, raw: raw, store: store, result: resultDocument, usage: usageDocument, artifactEvidence: artifactDocument}
	service := &scenarioGatewayFake{}
	executor, err := NewInitialScenarioExecutorWithGateway("https://provider.example", "https://gateway.example/tunnel", &credentials.Bundle{}, store, func(context.Context, string, string, *credentials.Bundle) (ScenarioGateway, error) {
		return service, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := 0
	executor.buildProviderAccess = fakeFactory(t, map[string]*fakeClient{"controller_a": client}, &closed)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionCapabilityCaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionLifecycleCaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(ctx, scenariocontrol.ReconstructionEvidenceCaseID); !errors.Is(err, ErrInitialScenario) {
		t.Fatalf("digest mismatch error = %v", err)
	}
	if executor.next != 2 || service.stopped || !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatalf("digest mismatch composition = next %d service %#v state %#v", executor.next, service, store.Snapshot())
	}
	_ = executor.Close()
}

func completeStoreWithEvidence(t *testing.T) (string, *callerstate.Store, provider.ExecResult, provider.UsageEvidence, provider.ArtifactStagingEvidence) {
	t.Helper()
	root := privateRoot(t)
	store, err := callerstate.CreateInitial(root)
	if err != nil {
		t.Fatal(err)
	}
	_, raw := selectedCapabilities(t)
	if err := store.BindCapabilities("provider-revision-local-v1", raw, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "2026-09-12T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := store.BindLifecycle(createFencingToken); err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	observed := time.Now().Add(-time.Minute).UTC()
	retained := time.Now().Add(time.Hour).UTC()
	zero := 0
	result := provider.ExecResult{
		OperationID: state.Plan.Exec.OperationID, AttemptID: state.Plan.Exec.AttemptID, FencingToken: execFencingToken, SandboxID: state.Plan.SandboxID,
		Status: "completed", ExitCode: &zero, StdoutReference: "ref:stdout:retained", StartedAt: observed.Format(time.RFC3339Nano), CompletedAt: observed.Format(time.RFC3339Nano), RetainedUntil: retained.Format(time.RFC3339Nano),
	}
	usage := provider.UsageEvidence{
		EvidenceID: "retained-usage", SandboxID: state.Plan.SandboxID, OperationID: state.Plan.Exec.OperationID, AttemptID: state.Plan.Exec.AttemptID, FencingToken: execFencingToken,
		Entries:              []provider.UsageEntry{{EntryID: "retained-exec-count", SandboxID: state.Plan.SandboxID, OperationID: state.Plan.Exec.OperationID, Meter: "sandbox.exec_count", Quantity: 1, Unit: "count", MeterSource: "reconciled", EvidenceReference: "ref:usage:retained", OccurredAt: observed.Format(time.RFC3339Nano)}},
		ReconciliationStatus: "partial", ObservedAt: observed.Format(time.RFC3339Nano), RetainedUntil: retained.Format(time.RFC3339Nano), EvidenceDigest: jcs.DigestBytes([]byte("provider-retained-usage")),
	}
	resultDigest, err := jcs.Digest(result)
	if err != nil {
		t.Fatal(err)
	}
	usageDigest, err := jcs.Digest(usage)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindExec(execFencingToken, resultDigest, usageDigest); err != nil {
		t.Fatal(err)
	}
	if err := store.BindTerminal(terminalFencingToken, "runtime-session-1", "ref:session:retained"); err != nil {
		t.Fatal(err)
	}
	state = store.Snapshot()
	check := func(reference string) provider.ArtifactCheck {
		return provider.ArtifactCheck{Status: "passed", CheckedAt: observed.Format(time.RFC3339Nano), EvidenceReference: reference}
	}
	artifact := provider.ArtifactStagingEvidence{
		OperationID: state.Plan.Artifact.OperationID, AttemptID: state.Plan.Artifact.AttemptID, FencingToken: artifactFencingToken, SandboxID: state.Plan.SandboxID,
		ArtifactReference: "artifact-ref:caller/" + state.Plan.RunID, StagingReference: "ref:staging:retained", Status: "staged", ContentDigest: artifactDigest,
		MediaType: artifactMediaType, SizeBytes: artifactSizeBytes, TenantBindingCheck: check("ref:check:tenant"), ActiveContentCheck: check("ref:check:active"), MalwareCheck: check("ref:check:malware"),
		ObservedAt: observed.Format(time.RFC3339Nano), ExpiresAt: observed.Add(time.Hour).Format(time.RFC3339Nano), EvidenceDigest: jcs.DigestBytes([]byte("provider-retained-artifact")),
	}
	artifactDigestValue, err := jcs.Digest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindArtifact(artifactFencingToken, artifactDigestValue); err != nil {
		t.Fatal(err)
	}
	return root, store, result, usage, artifact
}
