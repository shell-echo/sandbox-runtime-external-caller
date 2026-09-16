package releasebuild

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func TestBuildVerifyAndEmbeddedIdentity(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "release")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	manifest, err := Build(ctx, Options{SourceRoot: repositoryRoot, OutputDir: output, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(output)
	if err != nil {
		t.Fatal(err)
	}
	if verified.ManifestDigest != manifest.ManifestDigest || verified.ReleaseIdentity != manifest.ReleaseIdentity ||
		verified.ProvenanceBoundary.QualificationEligible || verified.ProvenanceBoundary.IndependentBuildAttestation ||
		verified.ProvenanceBoundary.IndependentSourceHosting || verified.ProvenanceBoundary.QualificationArtifactObservation {
		t.Fatalf("verified manifest = %#v", verified)
	}
	if len(verified.Artifacts) != 3 || !verified.Reproducibility.ByteIdentical || verified.Reproducibility.BuildRuns != 2 {
		t.Fatalf("release shape = %#v", verified)
	}

	adapter := filepath.Join(output, ArtifactsDirectory, artifactName("qualification-adapter", runtime.GOOS))
	processContext, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	command := exec.CommandContext(processContext, adapter)
	command.Args = []string{adapter}
	command.Env = []string{}
	command.Dir = t.TempDir()
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var startup protocol.StartupIdentity
	if err := json.Unmarshal(line, &startup); err != nil {
		t.Fatal(err)
	}
	want := protocol.SourceIdentity{Kind: manifest.ReleaseIdentity.Kind, Value: manifest.ReleaseIdentity.Value, Immutable: true}
	if startup.CallerReleaseIdentity != want || startup.AdapterReleaseIdentity != want {
		t.Fatalf("embedded release identities = %#v / %#v, want %#v", startup.CallerReleaseIdentity, startup.AdapterReleaseIdentity, want)
	}
	_ = stdin.Close()
	_ = command.Process.Kill()
	_ = command.Wait()

	artifact := filepath.Join(output, filepath.FromSlash(verified.Artifacts[0].File))
	file, err := os.OpenFile(artifact, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tamper")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(output); !errors.Is(err, ErrRelease) {
		t.Fatalf("Verify(tampered) = %v", err)
	}
}

func TestSourceArchiveIsDeterministicAndRejectsUnsafeInput(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "b.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(t.TempDir(), "first.tar")
	second := filepath.Join(t.TempDir(), "second.tar")
	files := []string{"a.txt", "nested/b.sh"}
	if err := writeSourceArchive(root, files, first); err != nil {
		t.Fatal(err)
	}
	if err := writeSourceArchive(root, files, second); err != nil {
		t.Fatal(err)
	}
	left, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatal("source archives differ")
	}
	if validRelativePath("../escape") || validRelativePath("/absolute") || validRelativePath("nested/../a.txt") || validRelativePath("nested\\a.txt") || validRelativePath("line\nbreak") {
		t.Fatal("unsafe source path accepted")
	}
	extracted := filepath.Join(t.TempDir(), "source")
	if err := extractSourceArchive(first, extracted); err != nil {
		t.Fatal(err)
	}
	if document, err := os.ReadFile(filepath.Join(extracted, "nested", "b.sh")); err != nil || string(document) != "#!/bin/sh\n" {
		t.Fatalf("extracted source = %q / %v", document, err)
	}
}

func TestBuildRejectsExistingOutputAndVerifyRejectsNonCanonicalManifest(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	existing := t.TempDir()
	if _, err := Build(context.Background(), Options{SourceRoot: repositoryRoot, OutputDir: existing}); !errors.Is(err, ErrRelease) {
		t.Fatalf("Build(existing) = %v", err)
	}
	bundle := t.TempDir()
	manifest := Manifest{FormatVersion: 1, ManifestID: ManifestID}
	document, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	document = append(document, '\n')
	if err := os.WriteFile(filepath.Join(bundle, ManifestFile), document, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bundle); !errors.Is(err, ErrRelease) {
		t.Fatalf("Verify(noncanonical) = %v", err)
	}
}
