// Package releasebuild creates and verifies content-addressed candidate release
// bundles. A bundle proves only deterministic local rebuilding from its exact
// source archive; it is not an independent source-hosting or build attestation.
package releasebuild

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/authority"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
)

const (
	ManifestID          = "sandbox-runtime-external-caller-release-v1"
	ManifestFile        = "release-manifest.json"
	SourceArchiveFile   = "source.tar"
	ArtifactsDirectory  = "artifacts"
	manifestDigestStyle = "rfc8785-full-document-excluding-manifest-digest-v1"
	archiveDigestStyle  = "sha256-raw-bytes-v1"
	maxManifestBytes    = 4 << 20
	maxSourceFiles      = 10_000
	maxSourceFileBytes  = 64 << 20
	maxSourceTotalBytes = 256 << 20
)

var ErrRelease = errors.New("candidate release bundle is invalid")

type Options struct {
	SourceRoot string
	OutputDir  string
	GoBinary   string
	GOOS       string
	GOARCH     string
}

type Identity struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Immutable bool   `json:"immutable"`
}

type Source struct {
	Archive                  string  `json:"archive"`
	ArchiveDigest            string  `json:"archive_digest"`
	ArchiveDigestProfile     string  `json:"archive_digest_profile"`
	ArchiveBytes             int64   `json:"archive_bytes"`
	FileCount                int     `json:"file_count"`
	VCSCommit                string  `json:"vcs_commit"`
	VCSTree                  string  `json:"vcs_tree"`
	VCSWorktreeClean         bool    `json:"vcs_worktree_clean"`
	SourceRepository         *string `json:"source_repository"`
	SourceHostingAttestation *string `json:"source_hosting_attestation"`
}

type Toolchain struct {
	GoVersion      string `json:"go_version"`
	GoBinaryDigest string `json:"go_binary_digest"`
	GoBinaryBytes  int64  `json:"go_binary_bytes"`
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
	Variant        string `json:"variant"`
	CGOEnabled     bool   `json:"cgo_enabled"`
}

type Command struct {
	ArtifactID       string   `json:"artifact_id"`
	WorkingDirectory string   `json:"working_directory"`
	Environment      []string `json:"environment"`
	Arguments        []string `json:"arguments"`
}

type Artifact struct {
	ArtifactID    string   `json:"artifact_id"`
	File          string   `json:"file"`
	DigestSubject string   `json:"digest_subject"`
	Digest        string   `json:"digest"`
	Bytes         int64    `json:"bytes"`
	Source        Identity `json:"source_identity"`
}

type Reproducibility struct {
	BuildRuns                int  `json:"build_runs"`
	ByteIdentical            bool `json:"byte_identical"`
	SourceArchiveReextracted bool `json:"source_archive_reextracted"`
}

type ProvenanceBoundary struct {
	EvidenceKind                     string `json:"evidence_kind"`
	BuilderOwner                     string `json:"builder_owner"`
	IndependentBuildAttestation      bool   `json:"independent_build_attestation"`
	IndependentSourceHosting         bool   `json:"independent_source_hosting"`
	QualificationArtifactObservation bool   `json:"qualification_artifact_observation"`
	QualificationEligible            bool   `json:"qualification_eligible"`
}

type Manifest struct {
	FormatVersion         int                `json:"format_version"`
	ManifestID            string             `json:"manifest_id"`
	ManifestDigestProfile string             `json:"manifest_digest_profile"`
	ManifestDigest        string             `json:"manifest_digest"`
	AuthorityLockDigest   string             `json:"authority_lock_digest"`
	ReleaseIdentity       Identity           `json:"release_identity"`
	Source                Source             `json:"source"`
	Toolchain             Toolchain          `json:"toolchain"`
	Commands              []Command          `json:"commands"`
	Artifacts             []Artifact         `json:"artifacts"`
	Reproducibility       Reproducibility    `json:"reproducibility"`
	ProvenanceBoundary    ProvenanceBoundary `json:"provenance_boundary"`
}

type artifactSpec struct {
	id, name, packagePath string
}

var artifactSpecs = []artifactSpec{
	{id: "qualification_adapter", name: "qualification-adapter", packagePath: "./cmd/qualification-adapter"},
	{id: "external_caller", name: "external-caller", packagePath: "./cmd/external-caller"},
	{id: "caller_gateway", name: "caller-gateway", packagePath: "./cmd/caller-gateway"},
}

// Build creates OutputDir atomically after two byte-identical builds from two
// independent extractions of the same deterministic source archive.
func Build(ctx context.Context, options Options) (Manifest, error) {
	options, err := validateOptions(options)
	if err != nil || ctx == nil {
		return Manifest{}, ErrRelease
	}
	if err := contextError(ctx); err != nil {
		return Manifest{}, err
	}
	if _, err := os.Lstat(options.OutputDir); !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, ErrRelease
	}
	if err := os.MkdirAll(filepath.Dir(options.OutputDir), 0o755); err != nil {
		return Manifest{}, ErrRelease
	}
	staging, err := os.MkdirTemp(filepath.Dir(options.OutputDir), ".release-build-")
	if err != nil {
		return Manifest{}, ErrRelease
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(staging)
		}
	}()

	files, err := sourceFiles(ctx, options.SourceRoot)
	if err != nil {
		return Manifest{}, err
	}
	archivePath := filepath.Join(staging, SourceArchiveFile)
	if err := writeSourceArchive(options.SourceRoot, files, archivePath); err != nil {
		return Manifest{}, err
	}
	archiveDigest, archiveBytes, err := digestFile(archivePath, maxSourceTotalBytes+64<<20)
	if err != nil {
		return Manifest{}, err
	}
	releaseIdentity := Identity{Kind: "source-revision", Value: strings.TrimPrefix(archiveDigest, "sha256:"), Immutable: true}
	goBinary, toolchain, err := inspectToolchain(ctx, options)
	if err != nil {
		return Manifest{}, err
	}
	commands := buildCommands(releaseIdentity, options)
	workRoot := filepath.Join(staging, ".work")
	builds := make([]map[string]string, 0, 2)
	for run := 1; run <= 2; run++ {
		sourceRoot := filepath.Join(workRoot, fmt.Sprintf("run-%d", run), "source")
		if err := extractSourceArchive(archivePath, sourceRoot); err != nil {
			return Manifest{}, err
		}
		outputs, err := runBuild(ctx, goBinary, sourceRoot, commands)
		if err != nil {
			return Manifest{}, err
		}
		builds = append(builds, outputs)
	}
	artifactDir := filepath.Join(staging, ArtifactsDirectory)
	if err := os.Mkdir(artifactDir, 0o755); err != nil {
		return Manifest{}, ErrRelease
	}
	artifacts := make([]Artifact, 0, len(artifactSpecs))
	for _, spec := range artifactSpecs {
		left, err := os.ReadFile(builds[0][spec.id])
		if err != nil {
			return Manifest{}, ErrRelease
		}
		right, err := os.ReadFile(builds[1][spec.id])
		if err != nil || !bytes.Equal(left, right) {
			return Manifest{}, ErrRelease
		}
		name := artifactName(spec.name, options.GOOS)
		finalPath := filepath.Join(artifactDir, name)
		if err := os.WriteFile(finalPath, left, 0o755); err != nil {
			return Manifest{}, ErrRelease
		}
		artifacts = append(artifacts, Artifact{
			ArtifactID: spec.id, File: filepath.ToSlash(filepath.Join(ArtifactsDirectory, name)),
			DigestSubject: "executable_raw_bytes", Digest: digestBytes(left), Bytes: int64(len(left)), Source: releaseIdentity,
		})
	}
	if err := os.RemoveAll(workRoot); err != nil {
		return Manifest{}, ErrRelease
	}
	source, err := sourceMetadata(ctx, options.SourceRoot, archiveDigest, archiveBytes, len(files))
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		FormatVersion: 1, ManifestID: ManifestID, ManifestDigestProfile: manifestDigestStyle,
		AuthorityLockDigest: authority.ExpectedAuthorityLockDigest, ReleaseIdentity: releaseIdentity,
		Source: source, Toolchain: toolchain, Commands: commands, Artifacts: artifacts,
		Reproducibility: Reproducibility{BuildRuns: 2, ByteIdentical: true, SourceArchiveReextracted: true},
		ProvenanceBoundary: ProvenanceBoundary{
			EvidenceKind: "candidate-local-reproducibility-only", BuilderOwner: "external_caller_owner",
			IndependentBuildAttestation: false, IndependentSourceHosting: false,
			QualificationArtifactObservation: false, QualificationEligible: false,
		},
	}
	manifest.ManifestDigest, err = jcs.DigestExcluding(manifest, "manifest_digest")
	if err != nil {
		return Manifest{}, ErrRelease
	}
	canonical, err := jcs.Marshal(manifest)
	if err != nil {
		return Manifest{}, ErrRelease
	}
	canonical = append(canonical, '\n')
	if err := os.WriteFile(filepath.Join(staging, ManifestFile), canonical, 0o644); err != nil {
		return Manifest{}, ErrRelease
	}
	if _, err := Verify(staging); err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(staging, options.OutputDir); err != nil {
		return Manifest{}, ErrRelease
	}
	complete = true
	return manifest, nil
}

// Verify strictly checks the canonical manifest and all retained raw bytes.
func Verify(bundleRoot string) (Manifest, error) {
	root, err := cleanAbsoluteDirectory(bundleRoot)
	if err != nil {
		return Manifest{}, ErrRelease
	}
	document, err := readRegular(filepath.Join(root, ManifestFile), maxManifestBytes)
	if err != nil || len(document) < 2 || document[len(document)-1] != '\n' {
		return Manifest{}, ErrRelease
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(document[:len(document)-1]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, ErrRelease
	}
	if err := requireEOF(decoder); err != nil {
		return Manifest{}, ErrRelease
	}
	canonical, err := jcs.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, document[:len(document)-1]) {
		return Manifest{}, ErrRelease
	}
	wantDigest, err := jcs.DigestExcluding(manifest, "manifest_digest")
	if err != nil || wantDigest != manifest.ManifestDigest || !validManifest(manifest) {
		return Manifest{}, ErrRelease
	}
	archivePath := filepath.Join(root, manifest.Source.Archive)
	digest, size, err := digestFile(archivePath, maxSourceTotalBytes+64<<20)
	if err != nil || digest != manifest.Source.ArchiveDigest || size != manifest.Source.ArchiveBytes {
		return Manifest{}, ErrRelease
	}
	if count, err := inspectSourceArchive(archivePath); err != nil || count != manifest.Source.FileCount {
		return Manifest{}, ErrRelease
	}
	for _, artifact := range manifest.Artifacts {
		path, err := confinedPath(root, artifact.File)
		if err != nil {
			return Manifest{}, ErrRelease
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 || info.Mode()&os.ModeSymlink != 0 {
			return Manifest{}, ErrRelease
		}
		digest, size, err := digestFile(path, 1<<30)
		if err != nil || digest != artifact.Digest || size != artifact.Bytes {
			return Manifest{}, ErrRelease
		}
	}
	return manifest, nil
}

func validateOptions(options Options) (Options, error) {
	var err error
	options.SourceRoot, err = cleanAbsoluteDirectory(options.SourceRoot)
	if err != nil {
		return Options{}, err
	}
	if !filepath.IsAbs(options.OutputDir) || filepath.Clean(options.OutputDir) != options.OutputDir || options.OutputDir == string(filepath.Separator) {
		return Options{}, ErrRelease
	}
	if options.GoBinary == "" {
		options.GoBinary = "go"
	}
	if options.GOOS == "" {
		options.GOOS = runtime.GOOS
	}
	if options.GOARCH == "" {
		options.GOARCH = runtime.GOARCH
	}
	if options.GOOS != "darwin" && options.GOOS != "linux" || options.GOARCH != "amd64" && options.GOARCH != "arm64" {
		return Options{}, ErrRelease
	}
	return options, nil
}

func sourceFiles(ctx context.Context, root string) ([]string, error) {
	command := exec.CommandContext(ctx, "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, ErrRelease
	}
	parts := bytes.Split(output, []byte{0})
	files := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	var total int64
	for _, raw := range parts {
		if len(raw) == 0 {
			continue
		}
		name := string(raw)
		if !validRelativePath(name) {
			return nil, ErrRelease
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, ErrRelease
		}
		seen[name] = struct{}{}
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maxSourceFileBytes {
			return nil, ErrRelease
		}
		total += info.Size()
		if total > maxSourceTotalBytes {
			return nil, ErrRelease
		}
		files = append(files, name)
	}
	if len(files) == 0 || len(files) > maxSourceFiles {
		return nil, ErrRelease
	}
	sort.Strings(files)
	return files, nil
}

func writeSourceArchive(root string, files []string, target string) (resultErr error) {
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrRelease
	}
	defer func() {
		if err := output.Close(); resultErr == nil && err != nil {
			resultErr = ErrRelease
		}
	}()
	writer := tar.NewWriter(output)
	defer func() {
		if err := writer.Close(); resultErr == nil && err != nil {
			resultErr = ErrRelease
		}
	}()
	for _, name := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return ErrRelease
		}
		mode := int64(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		header := &tar.Header{Name: name, Mode: mode, Size: info.Size(), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := writer.WriteHeader(header); err != nil {
			return ErrRelease
		}
		file, err := os.Open(path)
		if err != nil {
			return ErrRelease
		}
		written, copyErr := io.Copy(writer, io.LimitReader(file, info.Size()+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != info.Size() {
			return ErrRelease
		}
	}
	return nil
}

func extractSourceArchive(archivePath, target string) error {
	if err := os.MkdirAll(target, 0o755); err != nil {
		return ErrRelease
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return ErrRelease
	}
	defer archive.Close()
	reader := tar.NewReader(archive)
	count := 0
	var total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg || !validRelativePath(header.Name) || header.Size < 0 || header.Size > maxSourceFileBytes {
			return ErrRelease
		}
		count++
		total += header.Size
		if count > maxSourceFiles || total > maxSourceTotalBytes {
			return ErrRelease
		}
		path, err := confinedPath(target, header.Name)
		if err != nil || os.MkdirAll(filepath.Dir(path), 0o755) != nil {
			return ErrRelease
		}
		mode := os.FileMode(0o644)
		if header.Mode&0o111 != 0 {
			mode = 0o755
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return ErrRelease
		}
		written, copyErr := io.Copy(file, io.LimitReader(reader, header.Size+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != header.Size {
			return ErrRelease
		}
	}
	if count == 0 {
		return ErrRelease
	}
	return nil
}

func inspectSourceArchive(archivePath string) (int, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return 0, ErrRelease
	}
	defer archive.Close()
	reader := tar.NewReader(archive)
	count := 0
	var total int64
	previous := ""
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg || !validRelativePath(header.Name) || header.Name <= previous ||
			header.Size < 0 || header.Size > maxSourceFileBytes || header.Uid != 0 || header.Gid != 0 ||
			!header.ModTime.Equal(time.Unix(0, 0)) || header.Mode != 0o644 && header.Mode != 0o755 {
			return 0, ErrRelease
		}
		previous = header.Name
		count++
		total += header.Size
		if count > maxSourceFiles || total > maxSourceTotalBytes {
			return 0, ErrRelease
		}
		if copied, err := io.Copy(io.Discard, io.LimitReader(reader, header.Size+1)); err != nil || copied != header.Size {
			return 0, ErrRelease
		}
	}
	if count == 0 {
		return 0, ErrRelease
	}
	return count, nil
}

func inspectToolchain(ctx context.Context, options Options) (string, Toolchain, error) {
	path, err := exec.LookPath(options.GoBinary)
	if err != nil {
		return "", Toolchain{}, ErrRelease
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", Toolchain{}, ErrRelease
	}
	digest, size, err := digestFile(path, 512<<20)
	if err != nil {
		return "", Toolchain{}, err
	}
	command := exec.CommandContext(ctx, path, "env", "GOVERSION")
	command.Env = buildEnvironment(options)
	output, err := command.Output()
	version := strings.TrimSpace(string(output))
	if err != nil || !strings.HasPrefix(version, "go1.") || strings.ContainsAny(version, " \t\r\n") {
		return "", Toolchain{}, ErrRelease
	}
	return path, Toolchain{
		GoVersion: version, GoBinaryDigest: digest, GoBinaryBytes: size,
		GOOS: options.GOOS, GOARCH: options.GOARCH, Variant: architectureVariant(options.GOARCH), CGOEnabled: false,
	}, nil
}

func buildCommands(identity Identity, options Options) []Command {
	ldflags := strings.Join([]string{
		"-buildid=",
		"-X", "github.com/shell-echo/sandbox-runtime-external-caller/internal/releaseinfo.CallerKind=" + identity.Kind,
		"-X", "github.com/shell-echo/sandbox-runtime-external-caller/internal/releaseinfo.CallerValue=" + identity.Value,
		"-X", "github.com/shell-echo/sandbox-runtime-external-caller/internal/releaseinfo.AdapterKind=" + identity.Kind,
		"-X", "github.com/shell-echo/sandbox-runtime-external-caller/internal/releaseinfo.AdapterValue=" + identity.Value,
		"-X", "github.com/shell-echo/sandbox-runtime-external-caller/internal/releaseinfo.GatewayKind=" + identity.Kind,
		"-X", "github.com/shell-echo/sandbox-runtime-external-caller/internal/releaseinfo.GatewayValue=" + identity.Value,
	}, " ")
	environment := recordedEnvironment(options)
	commands := make([]Command, 0, len(artifactSpecs))
	for _, spec := range artifactSpecs {
		name := artifactName(spec.name, options.GOOS)
		commands = append(commands, Command{
			ArtifactID: spec.id, WorkingDirectory: "source", Environment: append([]string(nil), environment...),
			Arguments: []string{"go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=" + ldflags, "-o", filepath.ToSlash(filepath.Join(".release-output", name)), spec.packagePath},
		})
	}
	return commands
}

func runBuild(ctx context.Context, goBinary, sourceRoot string, commands []Command) (map[string]string, error) {
	outputRoot := filepath.Join(sourceRoot, ".release-output")
	if err := os.Mkdir(outputRoot, 0o755); err != nil {
		return nil, ErrRelease
	}
	outputs := make(map[string]string, len(commands))
	for _, build := range commands {
		args := append([]string(nil), build.Arguments[1:]...)
		command := exec.CommandContext(ctx, goBinary, args...)
		command.Dir = sourceRoot
		command.Env = mergeEnvironment(os.Environ(), build.Environment)
		var diagnostic bytes.Buffer
		command.Stdout = &diagnostic
		command.Stderr = &diagnostic
		if err := command.Run(); err != nil {
			return nil, fmt.Errorf("%w: build %s: %s", ErrRelease, build.ArtifactID, boundedDiagnostic(diagnostic.Bytes()))
		}
		path := filepath.Join(sourceRoot, filepath.FromSlash(build.Arguments[len(build.Arguments)-2]))
		if _, err := os.Lstat(path); err != nil {
			return nil, ErrRelease
		}
		outputs[build.ArtifactID] = path
	}
	return outputs, nil
}

func sourceMetadata(ctx context.Context, root, archiveDigest string, archiveBytes int64, fileCount int) (Source, error) {
	commit, err := gitText(ctx, root, "rev-parse", "HEAD")
	if err != nil || !hexString(commit, 40) {
		return Source{}, ErrRelease
	}
	tree, err := gitText(ctx, root, "rev-parse", "HEAD^{tree}")
	if err != nil || !hexString(tree, 40) {
		return Source{}, ErrRelease
	}
	status, err := gitText(ctx, root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return Source{}, ErrRelease
	}
	repository, repositoryErr := gitText(ctx, root, "config", "--get", "remote.origin.url")
	var sourceRepository *string
	if repositoryErr == nil && repository != "" && len(repository) <= 2048 && !strings.ContainsAny(repository, "\r\n\x00") {
		sourceRepository = &repository
	}
	return Source{
		Archive: SourceArchiveFile, ArchiveDigest: archiveDigest, ArchiveDigestProfile: archiveDigestStyle,
		ArchiveBytes: archiveBytes, FileCount: fileCount, VCSCommit: commit, VCSTree: tree,
		VCSWorktreeClean: status == "", SourceRepository: sourceRepository, SourceHostingAttestation: nil,
	}, nil
}

func validManifest(manifest Manifest) bool {
	if manifest.FormatVersion != 1 || manifest.ManifestID != ManifestID || manifest.ManifestDigestProfile != manifestDigestStyle ||
		manifest.AuthorityLockDigest != authority.ExpectedAuthorityLockDigest || manifest.Source.Archive != SourceArchiveFile ||
		manifest.Source.ArchiveDigestProfile != archiveDigestStyle || manifest.Source.ArchiveBytes <= 0 || manifest.Source.FileCount <= 0 ||
		manifest.ReleaseIdentity.Kind != "source-revision" || !manifest.ReleaseIdentity.Immutable || !hexString(manifest.ReleaseIdentity.Value, 64) ||
		manifest.Source.ArchiveDigest != "sha256:"+manifest.ReleaseIdentity.Value || !hexString(manifest.Source.VCSCommit, 40) || !hexString(manifest.Source.VCSTree, 40) ||
		manifest.Source.SourceHostingAttestation != nil || manifest.Toolchain.CGOEnabled || manifest.Toolchain.GOOS != "darwin" && manifest.Toolchain.GOOS != "linux" ||
		manifest.Toolchain.GOARCH != "amd64" && manifest.Toolchain.GOARCH != "arm64" || !validDigest(manifest.Toolchain.GoBinaryDigest) || manifest.Toolchain.GoBinaryBytes <= 0 ||
		manifest.Toolchain.Variant != architectureVariant(manifest.Toolchain.GOARCH) || !strings.HasPrefix(manifest.Toolchain.GoVersion, "go1.") || strings.ContainsAny(manifest.Toolchain.GoVersion, " \t\r\n") ||
		len(manifest.Commands) != len(artifactSpecs) || len(manifest.Artifacts) != len(artifactSpecs) || manifest.Reproducibility.BuildRuns != 2 ||
		!manifest.Reproducibility.ByteIdentical || !manifest.Reproducibility.SourceArchiveReextracted ||
		manifest.ProvenanceBoundary != (ProvenanceBoundary{EvidenceKind: "candidate-local-reproducibility-only", BuilderOwner: "external_caller_owner"}) {
		return false
	}
	expectedCommands := buildCommands(manifest.ReleaseIdentity, Options{GOOS: manifest.Toolchain.GOOS, GOARCH: manifest.Toolchain.GOARCH})
	for index, spec := range artifactSpecs {
		command := manifest.Commands[index]
		expectedCommand := expectedCommands[index]
		artifact := manifest.Artifacts[index]
		if command.ArtifactID != expectedCommand.ArtifactID || command.WorkingDirectory != expectedCommand.WorkingDirectory ||
			!equalStrings(command.Environment, expectedCommand.Environment) || !equalStrings(command.Arguments, expectedCommand.Arguments) ||
			artifact.ArtifactID != spec.id || artifact.File != filepath.ToSlash(filepath.Join(ArtifactsDirectory, artifactName(spec.name, manifest.Toolchain.GOOS))) || artifact.DigestSubject != "executable_raw_bytes" ||
			!validDigest(artifact.Digest) || artifact.Bytes <= 0 || artifact.Source != manifest.ReleaseIdentity {
			return false
		}
	}
	return true
}

func recordedEnvironment(options Options) []string {
	return []string{
		"CGO_ENABLED=0", "GOARCH=" + options.GOARCH, "GOENV=off", "GOEXPERIMENT=", "GOFLAGS=", "GOFIPS140=off", "GOOS=" + options.GOOS,
		architectureVariant(options.GOARCH), "GOTOOLCHAIN=local", "GOWORK=off",
	}
}

func buildEnvironment(options Options) []string {
	return mergeEnvironment(os.Environ(), recordedEnvironment(options))
}

func mergeEnvironment(base, fixed []string) []string {
	blocked := map[string]struct{}{}
	for _, item := range fixed {
		blocked[strings.SplitN(item, "=", 2)[0]] = struct{}{}
	}
	for _, key := range []string{"GO386", "GOAMD64", "GOARM", "GOARM64", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOWASM"} {
		blocked[key] = struct{}{}
	}
	result := make([]string, 0, len(base)+len(fixed))
	for _, item := range base {
		if _, ok := blocked[strings.SplitN(item, "=", 2)[0]]; !ok {
			result = append(result, item)
		}
	}
	return append(result, fixed...)
}

func architectureVariant(goarch string) string {
	if goarch == "amd64" {
		return "GOAMD64=v1"
	}
	return "GOARM64=v8.0"
}

func artifactName(name, goos string) string {
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}

func cleanAbsoluteDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return "", ErrRelease
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrRelease
	}
	return path, nil
}

func validRelativePath(name string) bool {
	if name == "" || strings.ContainsRune(name, '\\') || !filepath.IsLocal(filepath.FromSlash(name)) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(name))) != name {
		return false
	}
	for _, character := range name {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func confinedPath(root, relative string) (string, error) {
	if !validRelativePath(relative) {
		return "", ErrRelease
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	if rel, err := filepath.Rel(root, path); err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ErrRelease
	}
	return path, nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > limit {
		return nil, ErrRelease
	}
	document, err := os.ReadFile(path)
	if err != nil || int64(len(document)) != info.Size() {
		return nil, ErrRelease
	}
	return document, nil
}

func digestFile(path string, limit int64) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > limit {
		return "", 0, ErrRelease
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, ErrRelease
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil || n != info.Size() {
		return "", 0, ErrRelease
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), n, nil
}

func digestBytes(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func gitText(ctx context.Context, root string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(output), "\n"), nil
}

func validDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && hexString(strings.TrimPrefix(value, "sha256:"), 64)
}

func hexString(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrRelease
	}
	return nil
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func boundedDiagnostic(document []byte) string {
	if len(document) > 2048 {
		document = document[:2048]
	}
	return strings.TrimSpace(string(document))
}
