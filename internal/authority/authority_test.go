package authority

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthorityLockMatchesCompiledDigest(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", LockPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := digest(document); got != ExpectedAuthorityLockDigest {
		t.Fatalf("authority lock digest = %q, want %q", got, ExpectedAuthorityLockDigest)
	}
	var lock Lock
	if err := decodeStrict(document, &lock); err != nil {
		t.Fatal(err)
	}
	if len(lock.Files) != 36 {
		t.Fatalf("authority file count = %d, want 36", len(lock.Files))
	}
}

func TestDecodeStrictRejectsUnknownAndTrailingData(t *testing.T) {
	for _, document := range []string{
		`{"format_version":1,"unknown":true}`,
		`{"format_version":1} {}`,
	} {
		var lock Lock
		if err := decodeStrict([]byte(document), &lock); err == nil {
			t.Fatalf("decodeStrict(%q) accepted invalid input", document)
		}
	}
}

func TestReadRegularFileRejectsSymlinkAndOversize(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if contents, err := readRegularFile(regular, 3); err != nil || string(contents) != "abc" {
		t.Fatalf("readRegularFile() = %q, %v", contents, err)
	}
	if _, err := readRegularFile(regular, 2); err == nil {
		t.Fatal("readRegularFile accepted an oversized file")
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(symlink, 3); err == nil {
		t.Fatal("readRegularFile accepted a symlink")
	}
}

func TestDigestIsLowercaseSHA256(t *testing.T) {
	want := "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := digest([]byte("abc")); got != want || strings.ToLower(got) != got {
		t.Fatalf("digest(abc) = %q, want %q", got, want)
	}
}

func TestVerifyFilesAcceptsExactBytesAndRejectsDrift(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "contract", "authority.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("locked"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []AuthorityFile{{Path: "contract/authority.json", SHA256: digest([]byte("locked"))}}
	if err := verifyFiles(root, files); err != nil {
		t.Fatalf("verifyFiles(exact) error = %v", err)
	}
	if err := os.WriteFile(path, []byte("drifted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFiles(root, files); err == nil {
		t.Fatal("verifyFiles accepted drifted authority bytes")
	}
}

func TestVerifyFilesRejectsUnsafeAndDuplicatePaths(t *testing.T) {
	root := t.TempDir()
	for _, files := range [][]AuthorityFile{
		{{Path: "../escape", SHA256: digest(nil)}},
		{{Path: "same", SHA256: digest(nil)}, {Path: "same", SHA256: digest(nil)}},
	} {
		if err := verifyFiles(root, files); err == nil {
			t.Fatalf("verifyFiles(%v) accepted invalid inventory", files)
		}
	}
}
