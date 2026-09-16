package authority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	LockPath                    = "authority.lock.json"
	ExpectedAuthorityLockDigest = "sha256:5916b07719cc9320a021bbc96669f4a0c0a1d50a8301e9ab69f9fa248cdc03cf"
	maxLockBytes                = 64 << 10
	maxAuthorityFileBytes       = 1 << 20
)

type Lock struct {
	FormatVersion        int              `json:"format_version"`
	LockID               string           `json:"lock_id"`
	Source               SourceIdentity   `json:"source"`
	Contract             ContractIdentity `json:"contract"`
	QualificationProfile ProfileIdentity  `json:"qualification_profile"`
	AdapterProtocol      ProtocolIdentity `json:"adapter_protocol"`
	ReportEvidence       ReportIdentity   `json:"report_evidence"`
	Files                []AuthorityFile  `json:"files"`
}

type SourceIdentity struct {
	Repository   string `json:"repository"`
	Revision     string `json:"revision"`
	ContractTree string `json:"contract_tree"`
}

type ContractIdentity struct {
	Namespace            string        `json:"namespace"`
	Version              string        `json:"version"`
	ManifestDigest       string        `json:"manifest_digest"`
	OpenAPIDigest        string        `json:"openapi_digest"`
	SemanticRulesDigest  string        `json:"semantic_rules_digest"`
	LocalSuite           SuiteIdentity `json:"local_suite"`
	RemoteDiscoverySuite SuiteIdentity `json:"remote_discovery_suite"`
}

type SuiteIdentity struct {
	SuiteID      string `json:"suite_id"`
	SuiteVersion string `json:"suite_version"`
	SuiteDigest  string `json:"suite_digest"`
	ProfileID    string `json:"profile_id"`
	CaseCount    int    `json:"case_count"`
}

type ProfileIdentity struct {
	ProfileID            string          `json:"profile_id"`
	ProfileVersion       string          `json:"profile_version"`
	ProfileDigest        string          `json:"profile_digest"`
	ProfileDigestProfile string          `json:"profile_digest_profile"`
	SchemaDigest         string          `json:"schema_digest"`
	Phases               []PhaseIdentity `json:"phases"`
}

type PhaseIdentity struct {
	PhaseID string   `json:"phase_id"`
	CaseIDs []string `json:"case_ids"`
}

type ProtocolIdentity struct {
	ProtocolID                       string `json:"protocol_id"`
	ProtocolVersion                  string `json:"protocol_version"`
	SchemaDigest                     string `json:"schema_digest"`
	SemanticsDigest                  string `json:"semantics_digest"`
	TranscriptProjectionSchemaDigest string `json:"transcript_projection_schema_digest"`
}

type ReportIdentity struct {
	ReportSchemaDigest       string `json:"report_schema_digest"`
	ValidatorSemanticsDigest string `json:"validator_semantics_digest"`
}

type AuthorityFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Verify checks the immutable local lock before reading the exact public files
// it names from a sandbox-runtime source tree. It does not execute source code.
func Verify(providerSourceRoot, lockFile string) error {
	lockBytes, err := readRegularFile(lockFile, maxLockBytes)
	if err != nil {
		return fmt.Errorf("read authority lock: %w", err)
	}
	if digest(lockBytes) != ExpectedAuthorityLockDigest {
		return errors.New("authority lock digest mismatch")
	}

	var lock Lock
	if err := decodeStrict(lockBytes, &lock); err != nil {
		return fmt.Errorf("decode authority lock: %w", err)
	}
	if lock.FormatVersion != 1 || lock.LockID != "sandbox-runtime-external-caller-authority-v1" || len(lock.Files) != 36 {
		return errors.New("authority lock identity is invalid")
	}

	root, err := filepath.Abs(providerSourceRoot)
	if err != nil {
		return errors.New("resolve provider source root")
	}
	return verifyFiles(root, lock.Files)
}

func verifyFiles(root string, files []AuthorityFile) error {
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		clean := filepath.Clean(filepath.FromSlash(file.Path))
		if file.Path == "" || filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.ToSlash(clean) != file.Path {
			return errors.New("authority lock contains an unsafe path")
		}
		if _, ok := seen[file.Path]; ok {
			return errors.New("authority lock contains a duplicate path")
		}
		seen[file.Path] = struct{}{}

		contents, err := readRegularFile(filepath.Join(root, clean), maxAuthorityFileBytes)
		if err != nil {
			return fmt.Errorf("read locked authority %q: %w", file.Path, err)
		}
		if digest(contents) != file.SHA256 {
			return fmt.Errorf("locked authority %q digest mismatch", file.Path)
		}
	}
	return nil
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, errors.New("file is not a bounded regular file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) != info.Size() {
		return nil, errors.New("file changed while reading")
	}
	return contents, nil
}

func decodeStrict(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("document contains trailing data")
	}
	return nil
}

func digest(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}
