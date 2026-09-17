//go:build darwin || linux

package callerprovider

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/scenariocontrol"
)

func TestArtifactStagingBindsCallerTruthAndFullEvidenceDocument(t *testing.T) {
	executor, client, store := terminalBoundArtifactExecutor(t)
	defer executor.Close()
	defer store.Close()

	beforeAdmissions := len(client.admissions)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executor.Execute(ctx, scenariocontrol.ArtifactStagingCaseID)
	if err != nil {
		t.Fatalf("artifact execution: %v; state=%#v artifacts=%#v operation=%#v evidence=%#v admissions=%d->%d", err, store.Snapshot(), client.artifacts, client.lastOperation, client.artifactEvidence, beforeAdmissions, len(client.admissions))
	}
	if result.CaseID != scenariocontrol.ArtifactStagingCaseID || result.Disposition != "completed" || len(result.Interactions) != 3 || len(result.Assertions) != 1 || !reflect.DeepEqual(result.ObservationIDs, []string{"artifact-operation-accepted", "operation-succeeded", "artifact-status-staged", "content-digest-and-size-match", "opaque-staging-reference"}) {
		t.Fatalf("artifact result = %#v", result)
	}
	for index, status := range []int{202, 200, 200} {
		if result.Interactions[index].WireAttempts != 1 || result.Interactions[index].FinalOutcome.StatusCode == nil || *result.Interactions[index].FinalOutcome.StatusCode != status || result.Interactions[index].MutationWriteObserved != (index == 0) {
			t.Fatalf("artifact interaction %d = %#v", index, result.Interactions[index])
		}
	}
	if len(client.artifacts) != 1 {
		t.Fatalf("artifact stage calls = %d", len(client.artifacts))
	}
	request := client.artifacts[0]
	if request.ArtifactReference != "artifact-ref:caller/"+store.Snapshot().Plan.RunID || request.SourcePath != artifactSourcePath || request.ExpectedDigest != artifactDigest || request.ExpectedMediaType != artifactMediaType || request.MaxBytes != artifactSizeBytes || request.RequestDigest == "" {
		t.Fatalf("caller artifact request = %#v", request)
	}
	requestDeadline, deadlineErr := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if deadlineErr != nil || request.RetentionSeconds < 1 || !requestDeadline.After(time.Now().Add(time.Duration(request.RetentionSeconds)*time.Second)) {
		t.Fatalf("artifact retention is not bounded by deadline: %#v, %v", request, deadlineErr)
	}
	evidenceDigest, _ := jcs.Digest(executor.artifactEvidence)
	state := store.Snapshot()
	if state.Stage != callerstate.StageInitialComplete || state.StoreRevision != 6 || state.Artifact == nil || state.Artifact.Operation.FencingToken != artifactFencingToken || state.Artifact.EvidenceDigest != evidenceDigest || executor.next != 13 {
		t.Fatalf("artifact-bound state = %#v", state)
	}
	public, err := json.Marshal(result)
	if err != nil || containsBytes(public, []byte(executor.artifactEvidence.StagingReference)) || containsBytes(public, []byte(request.ArtifactReference)) {
		t.Fatalf("public artifact result leaked private references: %q / %v", public, err)
	}
}

func TestArtifactStagingRejectsMismatchedEvidenceWithoutStateAdvance(t *testing.T) {
	for _, name := range []string{"digest", "size", "reference", "check", "expired", "over-retained"} {
		t.Run(name, func(t *testing.T) {
			executor, client, store := terminalBoundArtifactExecutor(t)
			defer executor.Close()
			defer store.Close()
			before := store.Snapshot()
			client.artifactEvidenceHook = func(evidence *provider.ArtifactStagingEvidence) {
				switch name {
				case "digest":
					evidence.ContentDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				case "size":
					evidence.SizeBytes--
				case "reference":
					evidence.ArtifactReference = "artifact-ref:caller/other"
				case "check":
					evidence.MalwareCheck.Status = "failed"
				case "expired":
					evidence.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
				case "over-retained":
					evidence.ExpiresAt = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339Nano)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := executor.Execute(ctx, scenariocontrol.ArtifactStagingCaseID); !errors.Is(err, ErrInitialScenario) {
				t.Fatalf("mismatched evidence error = %v", err)
			}
			if executor.next != 12 || !reflect.DeepEqual(store.Snapshot(), before) || executor.artifactEvidence.OperationID != "" {
				t.Fatalf("mismatched evidence advanced state: %#v", store.Snapshot())
			}
		})
	}
}

func terminalBoundArtifactExecutor(t *testing.T) (*InitialScenarioExecutor, *fakeClient, *callerstate.Store) {
	t.Helper()
	executor, client, store := cancellationCompletedScenarioExecutor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executor.Execute(ctx, scenariocontrol.TerminalSessionCaseID); err != nil {
		executor.Close()
		store.Close()
		t.Fatal(err)
	}
	executor.next = 12
	return executor, client, store
}
