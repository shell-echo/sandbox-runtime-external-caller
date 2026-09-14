package callerstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func TestCreateInitialRequiresEmptyPrivateRootAndGeneratesPlan(t *testing.T) {
	rootPath := newPrivateRoot(t)
	store, err := CreateInitial(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	state := store.Snapshot()
	if state.Stage != StagePlanned || state.StoreRevision != 1 || state.ContractRevision != protocol.ContractRevision || state.ProfileDigest != protocol.ProfileDigest {
		t.Fatalf("initial state identity = %#v", state)
	}
	if err := validateState(state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(rootPath, StateFileName))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file info = %#v, %v", info, err)
	}
	document, err := os.ReadFile(filepath.Join(rootPath, StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jcs.Canonicalize(document)
	if err != nil || !bytes.Equal(document, canonical) {
		t.Fatalf("state file is not canonical JSON: %v", err)
	}

	otherStore, err := CreateInitial(newPrivateRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer otherStore.Close()
	if reflect.DeepEqual(state.Plan, otherStore.Snapshot().Plan) {
		t.Fatal("independent initial stores generated an identical correlation plan")
	}
}

func TestCreateInitialRejectsUnsafeRoots(t *testing.T) {
	t.Run("relative", func(t *testing.T) {
		if _, err := CreateInitial("relative/state"); !errors.Is(err, ErrRootPath) {
			t.Fatalf("CreateInitial(relative) error = %v", err)
		}
	})
	t.Run("non-private mode", func(t *testing.T) {
		rootPath := newPrivateRoot(t)
		if err := os.Chmod(rootPath, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := CreateInitial(rootPath); !errors.Is(err, ErrRootSecurity) {
			t.Fatalf("CreateInitial(0750) error = %v", err)
		}
	})
	t.Run("non-empty", func(t *testing.T) {
		rootPath := newPrivateRoot(t)
		if err := os.WriteFile(filepath.Join(rootPath, "seed"), []byte("sandbox_id=harness"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := CreateInitial(rootPath); !errors.Is(err, ErrRootContents) {
			t.Fatalf("CreateInitial(non-empty) error = %v", err)
		}
	})
	t.Run("root symlink", func(t *testing.T) {
		base := canonicalTempDir(t)
		realRoot := filepath.Join(base, "real-root")
		if err := os.Mkdir(realRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedRoot := filepath.Join(base, "linked-root")
		if err := os.Symlink(realRoot, linkedRoot); err != nil {
			t.Fatal(err)
		}
		if _, err := CreateInitial(linkedRoot); !errors.Is(err, ErrRootSecurity) {
			t.Fatalf("CreateInitial(root symlink) error = %v", err)
		}
	})
	t.Run("symlink component", func(t *testing.T) {
		base := canonicalTempDir(t)
		realParent := filepath.Join(base, "real-parent")
		rootPath := filepath.Join(realParent, "state")
		if err := os.MkdirAll(rootPath, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(base, "linked-parent")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		if _, err := CreateInitial(filepath.Join(linkedParent, "state")); !errors.Is(err, ErrRootSecurity) {
			t.Fatalf("CreateInitial(component symlink) error = %v", err)
		}
	})
}

func TestStateTransitionsPersistAndReconstructExactly(t *testing.T) {
	rootPath := newPrivateRoot(t)
	store, err := CreateInitial(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	completeInitialState(t, store)
	want := store.Snapshot()
	if want.Stage != StageInitialComplete || want.StoreRevision != 6 || want.Terminal.HandoffReference != "ref:session:caller-owned-opaque" || want.Terminal.HandoffReferenceDigest != rawDigest([]byte(want.Terminal.HandoffReference)) {
		t.Fatalf("complete state = %#v", want)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reconstructed, err := OpenReconstruction(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reconstructed.Close()
	if got := reconstructed.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("reconstructed state differs:\n got %#v\nwant %#v", got, want)
	}
	if err := reconstructed.BindArtifact(4, testDigest('d')); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("post-completion transition error = %v", err)
	}
}

func TestStateTransitionsAreOrderedAndOneWriterWins(t *testing.T) {
	store, err := CreateInitial(newPrivateRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.BindLifecycle(1); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("out-of-order BindLifecycle error = %v", err)
	}
	before := store.Snapshot()

	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- store.BindCapabilities("provider-revision-1", []byte(`{"capabilities":[]}`), testDigest('f'), "2026-09-12T00:00:00Z")
		}()
	}
	wait.Wait()
	close(errorsSeen)
	successes, rejected := 0, 0
	for err := range errorsSeen {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrInvalidTransition):
			rejected++
		default:
			t.Fatalf("concurrent transition error = %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("concurrent transition results = success %d rejected %d", successes, rejected)
	}
	after := store.Snapshot()
	if after.Stage != StageCapabilitiesBound || after.StoreRevision != before.StoreRevision+1 || !reflect.DeepEqual(after.Plan, before.Plan) {
		t.Fatalf("state after concurrent transition = %#v", after)
	}
}

func TestBindCapabilitiesRequiresPolicyAuthority(t *testing.T) {
	for _, test := range []struct {
		name      string
		digest    string
		decidedAt string
	}{
		{name: "missing digest", decidedAt: "2026-09-12T00:00:00Z"},
		{name: "invalid digest", digest: "sha256:short", decidedAt: "2026-09-12T00:00:00Z"},
		{name: "missing decision time", digest: testDigest('f')},
		{name: "invalid decision time", digest: testDigest('f'), decidedAt: "2026-09-12 00:00:00Z"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := CreateInitial(newPrivateRoot(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.BindCapabilities("provider-revision-1", []byte(`{}`), test.digest, test.decidedAt); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("BindCapabilities() error = %v", err)
			}
			if state := store.Snapshot(); state.Stage != StagePlanned || state.Provider != nil || state.StoreRevision != 1 {
				t.Fatalf("invalid policy changed state: %#v", state)
			}
		})
	}
}

func TestOpenReconstructionRejectsPartialTamperedAndUnexpectedState(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		rootPath := newPrivateRoot(t)
		store, err := CreateInitial(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReconstruction(rootPath); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("OpenReconstruction(partial) error = %v", err)
		}
	})
	t.Run("state mode", func(t *testing.T) {
		rootPath := completeRoot(t)
		if err := os.Chmod(filepath.Join(rootPath, StateFileName), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReconstruction(rootPath); !errors.Is(err, ErrStateFile) {
			t.Fatalf("OpenReconstruction(0640) error = %v", err)
		}
	})
	t.Run("non-canonical bytes", func(t *testing.T) {
		rootPath := completeRoot(t)
		statePath := filepath.Join(rootPath, StateFileName)
		document, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, append(document, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReconstruction(rootPath); !errors.Is(err, ErrStateFile) {
			t.Fatalf("OpenReconstruction(non-canonical) error = %v", err)
		}
	})
	t.Run("unknown correlation member", func(t *testing.T) {
		rootPath := completeRoot(t)
		statePath := filepath.Join(rootPath, StateFileName)
		document, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if err := json.Unmarshal(document, &object); err != nil {
			t.Fatal(err)
		}
		object["sandbox_id"] = "harness-reinjected"
		tampered, err := jcs.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReconstruction(rootPath); !errors.Is(err, ErrStateFile) {
			t.Fatalf("OpenReconstruction(unknown member) error = %v", err)
		}
	})
	t.Run("extra entry", func(t *testing.T) {
		rootPath := completeRoot(t)
		if err := os.WriteFile(filepath.Join(rootPath, "harness-seed"), []byte("forbidden"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReconstruction(rootPath); !errors.Is(err, ErrRootContents) {
			t.Fatalf("OpenReconstruction(extra entry) error = %v", err)
		}
	})
	t.Run("state symlink", func(t *testing.T) {
		rootPath := completeRoot(t)
		statePath := filepath.Join(rootPath, StateFileName)
		document, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		alternate := filepath.Join(rootPath, "alternate")
		if err := os.WriteFile(alternate, document, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(statePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("alternate", statePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(alternate); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReconstruction(rootPath); !errors.Is(err, ErrStateFile) {
			t.Fatalf("OpenReconstruction(state symlink) error = %v", err)
		}
	})
}

func TestTransitionDetectsOnDiskChangeAndCloseIsTerminal(t *testing.T) {
	rootPath := newPrivateRoot(t)
	store, err := CreateInitial(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(rootPath, StateFileName)
	document, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, append(document, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateUnchanged(); !errors.Is(err, ErrStateFile) {
		t.Fatalf("ValidateUnchanged() after disk change error = %v", err)
	}
	if err := store.BindCapabilities("provider-revision-1", []byte(`{}`), testDigest('f'), "2026-09-12T00:00:00Z"); !errors.Is(err, ErrStateFile) {
		t.Fatalf("transition after disk change error = %v", err)
	}
	if store.Snapshot().Stage != StagePlanned {
		t.Fatal("failed transition changed in-memory state")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateUnchanged(); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("ValidateUnchanged() after Close error = %v", err)
	}
	if err := store.BindCapabilities("provider-revision-1", []byte(`{}`), testDigest('f'), "2026-09-12T00:00:00Z"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("transition after Close error = %v", err)
	}
}

func TestTransitionRejectsValidOutOfBandRevisionAndRootModeChange(t *testing.T) {
	t.Run("valid state replacement", func(t *testing.T) {
		rootPath := newPrivateRoot(t)
		store, err := CreateInitial(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		tampered := store.Snapshot()
		tampered.Plan.RunID = "run-00000000000000000000000000000000"
		document, err := jcs.Marshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rootPath, StateFileName), document, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := store.BindCapabilities("provider-revision-1", []byte(`{}`), testDigest('f'), "2026-09-12T00:00:00Z"); !errors.Is(err, ErrStateChanged) {
			t.Fatalf("transition after valid state replacement error = %v", err)
		}
	})
	t.Run("root mode changed", func(t *testing.T) {
		rootPath := newPrivateRoot(t)
		store, err := CreateInitial(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if err := os.Chmod(rootPath, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := store.BindCapabilities("provider-revision-1", []byte(`{}`), testDigest('f'), "2026-09-12T00:00:00Z"); !errors.Is(err, ErrRootSecurity) {
			t.Fatalf("transition after root mode change error = %v", err)
		}
	})
}

func TestSnapshotIsADeepCopy(t *testing.T) {
	store, err := CreateInitial(newPrivateRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.BindCapabilities("provider-revision-1", []byte(`{}`), testDigest('f'), "2026-09-12T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	snapshot.Provider.ProviderRevisionID = "tampered"
	if store.Snapshot().Provider.ProviderRevisionID != "provider-revision-1" {
		t.Fatal("Snapshot returned shared mutable state")
	}
}

func completeRoot(t *testing.T) string {
	t.Helper()
	rootPath := newPrivateRoot(t)
	store, err := CreateInitial(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	completeInitialState(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return rootPath
}

func completeInitialState(t *testing.T, store *Store) {
	t.Helper()
	for _, step := range []func() error{
		func() error {
			return store.BindCapabilities("provider-revision-1", []byte(`{"api_version":"v1"}`), testDigest('f'), "2026-09-12T00:00:00Z")
		},
		func() error { return store.BindLifecycle(1) },
		func() error { return store.BindExec(2, testDigest('a'), testDigest('b')) },
		func() error { return store.BindTerminal(3, "runtime-session-1", "ref:session:caller-owned-opaque") },
		func() error { return store.BindArtifact(4, testDigest('c')) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
}

func newPrivateRoot(t *testing.T) string {
	t.Helper()
	rootPath := filepath.Join(canonicalTempDir(t), "caller-state")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	return rootPath
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func testDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
