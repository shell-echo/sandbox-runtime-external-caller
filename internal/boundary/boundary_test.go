package boundary

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const forbiddenProviderModule = "github.com/shell-echo/sandbox-runtime"

func TestSourceDoesNotImportProviderImplementation(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if forbiddenImport(value) {
				t.Errorf("%s imports forbidden Provider implementation package %q", path, value)
			}
			if (value == forbiddenProviderModule+"-external-caller/internal/testcredentials" || value == forbiddenProviderModule+"-external-caller/internal/testprovider") && !strings.HasSuffix(path, "_test.go") {
				t.Errorf("%s imports test-only helpers %q into runtime code", path, value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBoundaryRejectsExactModuleAndAllowsCandidateModule(t *testing.T) {
	for _, value := range []string{forbiddenProviderModule, forbiddenProviderModule + "/internal/provider"} {
		if !forbiddenImport(value) {
			t.Fatalf("forbiddenImport(%q) = false", value)
		}
	}
	if forbiddenImport(forbiddenProviderModule + "-external-caller/internal/authority") {
		t.Fatal("candidate module was classified as a Provider implementation import")
	}
}

func forbiddenImport(value string) bool {
	return value == forbiddenProviderModule || strings.HasPrefix(value, forbiddenProviderModule+"/")
}
