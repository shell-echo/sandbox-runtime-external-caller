package callerstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
)

const (
	StateFileName     = "correlation-state-v1.json"
	maxStateFileBytes = 64 << 10
	maxSnapshotBytes  = 1 << 20
)

var (
	ErrUnsupportedPlatform = errors.New("caller state store is unsupported on this platform")
	ErrRootPath            = errors.New("caller state root path is invalid")
	ErrRootSecurity        = errors.New("caller state root is not a private no-symlink directory")
	ErrRootContents        = errors.New("caller state root has unexpected contents")
	ErrStateFile           = errors.New("caller state file is invalid")
	ErrStateChanged        = errors.New("caller state changed outside this store")
	ErrStoreClosed         = errors.New("caller state store is closed")
)

type Store struct {
	mu    sync.Mutex
	root  *os.Root
	state State
}

// CreateInitial requires a supervisor-created empty 0700 root and generates
// every persisted plan correlation from crypto/rand inside the caller.
func CreateInitial(rootPath string) (*Store, error) {
	root, err := openPrivateRoot(rootPath)
	if err != nil {
		return nil, err
	}
	if err := validateRootEntries(root, true); err != nil {
		root.Close()
		return nil, err
	}
	state, err := newInitialState()
	if err != nil {
		root.Close()
		return nil, err
	}
	if err := atomicWriteState(root, state); err != nil {
		root.Close()
		return nil, err
	}
	written, err := readState(root)
	if err != nil || !reflect.DeepEqual(written, state) || validateRootEntries(root, false) != nil {
		root.Close()
		return nil, ErrStateFile
	}
	return &Store{root: root, state: state}, nil
}

// OpenReconstruction accepts only the one complete state file written by the
// initial caller process. Directory continuity and harness non-modification
// remain independent process-supervisor evidence.
func OpenReconstruction(rootPath string) (*Store, error) {
	root, err := openPrivateRoot(rootPath)
	if err != nil {
		return nil, err
	}
	if err := validateRootEntries(root, false); err != nil {
		root.Close()
		return nil, err
	}
	state, err := readState(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	if state.Stage != StageInitialComplete {
		root.Close()
		return nil, ErrInvalidState
	}
	return &Store{root: root, state: state}, nil
}

func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state)
}

// ValidateUnchanged requires the private root and canonical state bytes to
// still match the revision held by this store. It performs no transition.
func (s *Store) ValidateUnchanged() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return ErrStoreClosed
	}
	if err := validateOpenRoot(s.root); err != nil {
		return err
	}
	if err := validateRootEntries(s.root, false); err != nil {
		return err
	}
	onDisk, err := readState(s.root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(onDisk, s.state) {
		return ErrStateChanged
	}
	return nil
}

func (s *Store) BindCapabilities(providerRevision string, rawCapabilitySnapshot []byte, policyDigest, policyDecidedAt string) error {
	if !validIdentifier(providerRevision) || len(rawCapabilitySnapshot) == 0 || len(rawCapabilitySnapshot) > maxSnapshotBytes || !digestPattern.MatchString(policyDigest) || !validDateTime(policyDecidedAt) {
		return ErrInvalidTransition
	}
	return s.transition(StagePlanned, func(next *State) {
		next.Stage = StageCapabilitiesBound
		next.Provider = &ProviderBinding{
			ProviderRevisionID: providerRevision, CapabilitySnapshotHash: rawDigest(rawCapabilitySnapshot),
			PolicyDigest: policyDigest, PolicyDecidedAt: policyDecidedAt,
		}
	})
}

func (s *Store) BindLifecycle(fencingToken int64) error {
	if fencingToken < 1 || fencingToken > maxSafeInteger {
		return ErrInvalidTransition
	}
	return s.transition(StageCapabilitiesBound, func(next *State) {
		next.Stage = StageLifecycleBound
		binding := operationFromPlan(next.Plan.Create, fencingToken)
		next.Lifecycle = &binding
	})
}

func (s *Store) BindExec(fencingToken int64, resultDigest, usageEvidenceDigest string) error {
	if fencingToken < 1 || fencingToken > maxSafeInteger || !digestPattern.MatchString(resultDigest) || !digestPattern.MatchString(usageEvidenceDigest) {
		return ErrInvalidTransition
	}
	return s.transition(StageLifecycleBound, func(next *State) {
		next.Stage = StageExecBound
		next.Exec = &ExecBinding{
			Operation: operationFromPlan(next.Plan.Exec, fencingToken), ResultDigest: resultDigest, UsageEvidenceDigest: usageEvidenceDigest,
		}
	})
}

func (s *Store) BindTerminal(fencingToken int64, runtimeSessionID, handoffReference string) error {
	if fencingToken < 1 || fencingToken > maxSafeInteger || !validIdentifier(runtimeSessionID) || !validOpaqueReference(handoffReference) {
		return ErrInvalidTransition
	}
	return s.transition(StageExecBound, func(next *State) {
		next.Stage = StageTerminalBound
		next.Terminal = &TerminalBinding{
			Operation: operationFromPlan(next.Plan.Terminal, fencingToken), RuntimeSessionID: runtimeSessionID,
			HandoffReference: handoffReference, HandoffReferenceDigest: rawDigest([]byte(handoffReference)),
		}
	})
}

func (s *Store) BindArtifact(fencingToken int64, evidenceDigest string) error {
	if fencingToken < 1 || fencingToken > maxSafeInteger || !digestPattern.MatchString(evidenceDigest) {
		return ErrInvalidTransition
	}
	return s.transition(StageTerminalBound, func(next *State) {
		next.Stage = StageInitialComplete
		next.Artifact = &ArtifactBinding{
			Operation: operationFromPlan(next.Plan.Artifact, fencingToken), EvidenceDigest: evidenceDigest,
		}
	})
}

func (s *Store) transition(expectedStage string, mutate func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return ErrStoreClosed
	}
	if s.state.Stage != expectedStage {
		return ErrInvalidTransition
	}
	if err := validateOpenRoot(s.root); err != nil {
		return err
	}
	if err := validateRootEntries(s.root, false); err != nil {
		return err
	}
	onDisk, err := readState(s.root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(onDisk, s.state) {
		return ErrStateChanged
	}

	next := cloneState(s.state)
	next.StoreRevision++
	mutate(&next)
	if err := validateState(next); err != nil {
		return ErrInvalidTransition
	}
	if err := atomicWriteState(s.root, next); err != nil {
		return err
	}
	written, err := readState(s.root)
	if err != nil || !reflect.DeepEqual(written, next) {
		return ErrStateFile
	}
	s.state = next
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil
	}
	err := s.root.Close()
	s.root = nil
	return err
}

func cloneState(state State) State {
	cloned := state
	if state.Provider != nil {
		value := *state.Provider
		cloned.Provider = &value
	}
	if state.Lifecycle != nil {
		value := *state.Lifecycle
		cloned.Lifecycle = &value
	}
	if state.Exec != nil {
		value := *state.Exec
		cloned.Exec = &value
	}
	if state.Terminal != nil {
		value := *state.Terminal
		cloned.Terminal = &value
	}
	if state.Artifact != nil {
		value := *state.Artifact
		cloned.Artifact = &value
	}
	return cloned
}

func openPrivateRoot(rootPath string) (*os.Root, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, ErrUnsupportedPlatform
	}
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || rootPath == string(filepath.Separator) || strings.ContainsRune(rootPath, '\x00') {
		return nil, ErrRootPath
	}
	if err := rejectSymlinkComponents(rootPath); err != nil {
		return nil, err
	}
	before, err := os.Lstat(rootPath)
	if err != nil || !privateDirectoryMode(before.Mode()) {
		return nil, ErrRootSecurity
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, ErrRootSecurity
	}
	opened, err := root.Stat(".")
	if err != nil || !privateDirectoryMode(opened.Mode()) || !os.SameFile(before, opened) {
		root.Close()
		return nil, ErrRootSecurity
	}
	after, err := os.Lstat(rootPath)
	if err != nil || !privateDirectoryMode(after.Mode()) || !os.SameFile(opened, after) {
		root.Close()
		return nil, ErrRootSecurity
	}
	return root, nil
}

func rejectSymlinkComponents(path string) error {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			return ErrRootPath
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrRootSecurity
		}
	}
	return nil
}

func privateDirectoryMode(mode os.FileMode) bool {
	return mode.IsDir() && mode.Perm() == 0o700 && mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func privateFileMode(mode os.FileMode) bool {
	return mode.IsRegular() && mode.Perm() == 0o600 && mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func validateOpenRoot(root *os.Root) error {
	info, err := root.Stat(".")
	if err != nil || !privateDirectoryMode(info.Mode()) {
		return ErrRootSecurity
	}
	return nil
}

func validateRootEntries(root *os.Root, initial bool) error {
	directory, err := root.Open(".")
	if err != nil {
		return ErrRootContents
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return ErrRootContents
	}
	if initial {
		if len(entries) != 0 {
			return ErrRootContents
		}
		return nil
	}
	if len(entries) != 1 || entries[0].Name() != StateFileName {
		return ErrRootContents
	}
	return nil
}

func atomicWriteState(root *os.Root, state State) error {
	if err := validateState(state); err != nil {
		return err
	}
	document, err := jcs.Marshal(state)
	if err != nil || len(document) == 0 || len(document) > maxStateFileBytes {
		return ErrStateFile
	}
	defer clear(document)
	tempID, err := randomIdentifier("state")
	if err != nil {
		return err
	}
	tempName := "." + tempID + ".tmp"
	file, err := root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrStateFile
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = root.Remove(tempName)
		}
	}()
	if err := writeAll(file, document); err != nil || file.Chmod(0o600) != nil || file.Sync() != nil || file.Close() != nil {
		_ = file.Close()
		return ErrStateFile
	}
	if err := root.Rename(tempName, StateFileName); err != nil {
		return ErrStateFile
	}
	renamed = true
	directory, err := root.Open(".")
	if err != nil {
		return ErrStateFile
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return ErrStateFile
	}
	return nil
}

func writeAll(writer io.Writer, document []byte) error {
	for len(document) > 0 {
		written, err := writer.Write(document)
		if err != nil || written <= 0 || written > len(document) {
			return ErrStateFile
		}
		document = document[written:]
	}
	return nil
}

func readState(root *os.Root) (State, error) {
	before, err := root.Lstat(StateFileName)
	if err != nil || !privateFileMode(before.Mode()) || before.Size() <= 0 || before.Size() > maxStateFileBytes {
		return State{}, ErrStateFile
	}
	file, err := root.OpenFile(StateFileName, os.O_RDONLY, 0)
	if err != nil {
		return State{}, ErrStateFile
	}
	opened, statErr := file.Stat()
	if statErr != nil || !privateFileMode(opened.Mode()) || !os.SameFile(before, opened) {
		file.Close()
		return State{}, ErrStateFile
	}
	document, readErr := io.ReadAll(io.LimitReader(file, maxStateFileBytes+1))
	defer clear(document)
	afterRead, afterReadErr := file.Stat()
	closeErr := file.Close()
	afterPath, afterPathErr := root.Lstat(StateFileName)
	if readErr != nil || afterReadErr != nil || closeErr != nil || afterPathErr != nil || len(document) > maxStateFileBytes || int64(len(document)) != before.Size() || !os.SameFile(opened, afterRead) || !os.SameFile(opened, afterPath) || !privateFileMode(afterPath.Mode()) || afterPath.Size() != int64(len(document)) {
		return State{}, ErrStateFile
	}
	canonical, err := jcs.Canonicalize(document)
	defer clear(canonical)
	if err != nil || !bytes.Equal(document, canonical) || !hasExactStateKeys(canonical) {
		return State{}, ErrStateFile
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return State{}, ErrStateFile
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || validateState(state) != nil {
		return State{}, ErrStateFile
	}
	return state, nil
}

func hasExactStateKeys(document []byte) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil || len(object) != 13 {
		return false
	}
	for _, key := range []string{
		"format_version", "state_type", "contract_revision", "profile_id", "profile_digest", "store_revision", "stage", "plan", "provider", "lifecycle", "exec", "terminal", "artifact",
	} {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}
