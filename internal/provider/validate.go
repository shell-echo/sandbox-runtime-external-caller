package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
)

const maxSafeInteger = int64(9007199254740991)

var (
	ErrInvalidContractDocument = errors.New("provider document does not match the locked Contract")
	ErrAdmissionBinding        = errors.New("protected admission binding is invalid")
	ErrSigning                 = errors.New("protected admission signing failed")
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	capabilityPattern = regexp.MustCompile(`^sandbox\.[a-z0-9-]+$`)
	semverPattern     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	slotPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{0,127}$`)
	labelPattern      = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,64}$`)
	errorCodePattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	referencePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,399}$`)
)

func validateCapabilities(document ProviderCapabilities) error {
	if !boundedString(document.ProviderRevisionID, 1, 200) || document.APIVersion != "v1" || document.Capabilities == nil || document.RuntimeProfiles == nil || len(document.SnapshotRestoreProfiles) < 1 ||
		document.Limits.MaxCPUMillis < 1 || document.Limits.MaxMemoryBytes < 1 || document.Limits.MaxEphemeralStorageBytes < 1 || document.Limits.MaxLeaseSeconds < 1 || document.Limits.MaxExecSeconds < 1 {
		return ErrInvalidContractDocument
	}
	if document.Limits.MaxWorkspaceBytes != nil && *document.Limits.MaxWorkspaceBytes < 1 || document.Limits.MaxGPUCount != nil && *document.Limits.MaxGPUCount < 0 {
		return ErrInvalidContractDocument
	}
	for _, capability := range document.Capabilities {
		if !capabilityPattern.MatchString(capability.ID) || capability.Versions == nil {
			return ErrInvalidContractDocument
		}
		for _, version := range capability.Versions {
			if version == "" {
				return ErrInvalidContractDocument
			}
		}
		for _, profile := range capability.Profiles {
			if profile == "" {
				return ErrInvalidContractDocument
			}
		}
	}
	for _, profile := range document.RuntimeProfiles {
		if !boundedString(profile.ID, 1, 200) || !oneOf(profile.IsolationClass, "container", "hardened-container", "microvm", "virtual-machine", "local-process") || profile.RuntimeClassName != "" && !boundedString(profile.RuntimeClassName, 1, 1<<20) {
			return ErrInvalidContractDocument
		}
		for _, architecture := range profile.Architecture {
			if !oneOf(architecture, "amd64", "arm64") {
				return ErrInvalidContractDocument
			}
		}
		if len(profile.CapabilityProfileIDs) > 64 || !uniqueIdentifiers(profile.CapabilityProfileIDs) {
			return ErrInvalidContractDocument
		}
	}
	for _, profile := range document.SnapshotRestoreProfiles {
		if !boundedString(profile.ProfileID, 1, 200) || !oneOf(profile.Level, "workspace", "filesystem", "process") || profile.SuiteID != "sandbox-provider" || !semverPattern.MatchString(profile.SuiteVersion) || !digestPattern.MatchString(profile.SuiteDigest) {
			return ErrInvalidContractDocument
		}
	}
	return nil
}

func ValidateCreateRequest(request CreateSandboxRequest) error {
	if !identifierPattern.MatchString(request.OperationID) || !identifierPattern.MatchString(request.AttemptID) || request.FencingToken < 1 || request.FencingToken > maxSafeInteger || !boundedString(request.IdempotencyKey, 1, 200) ||
		!digestPattern.MatchString(request.RequestDigest) || !validDateTime(request.DeadlineAt) || request.ProtocolVersion != "v1" || validateSandboxSpec(request.Spec) != nil || len(request.TraceContext) > 16 {
		return ErrInvalidContractDocument
	}
	for _, value := range request.TraceContext {
		if _, err := jcs.Canonicalize(value); err != nil {
			return ErrInvalidContractDocument
		}
	}
	return nil
}

func validateSandboxSpec(spec SandboxSpec) error {
	for _, value := range []string{spec.SandboxID, spec.TenantID, spec.WorkOrderID, spec.WorkspaceID, spec.BranchID, spec.ProviderResolutionID, spec.ProviderRevisionID} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidContractDocument
		}
	}
	if !boundedString(spec.Image.Reference, 1, 500) || !digestPattern.MatchString(spec.Image.Digest) || spec.Image.Architecture != "" && !oneOf(spec.Image.Architecture, "amd64", "arm64") ||
		!boundedString(spec.RuntimeProfile, 1, 200) || spec.Resources.CPUMillis < 1 || spec.Resources.MemoryBytes < 1 || spec.Resources.EphemeralStorageBytes < 1 || spec.Resources.PIDsLimit < 1 ||
		spec.Resources.WorkspaceBytes != nil && *spec.Resources.WorkspaceBytes < 1 || spec.Resources.GPUCount != nil && *spec.Resources.GPUCount < 0 || spec.RequiredCapabilities == nil || len(spec.RequiredCapabilities) > 64 || len(spec.OptionalCapabilities) > 64 {
		return ErrInvalidContractDocument
	}
	for _, capability := range append(append([]CapabilityRequirement(nil), spec.RequiredCapabilities...), spec.OptionalCapabilities...) {
		if !capabilityPattern.MatchString(capability.ID) || !semverPattern.MatchString(capability.Version) || capability.Profile != "" && !boundedString(capability.Profile, 1, 200) {
			return ErrInvalidContractDocument
		}
	}
	if !oneOf(spec.Network.Mode, "none", "restricted", "full") || spec.Network.PolicyReference != "" && !identifierPattern.MatchString(spec.Network.PolicyReference) {
		return ErrInvalidContractDocument
	}
	if !oneOf(spec.Workspace.Mode, "ephemeral", "persistent") || !identifierPattern.MatchString(spec.Workspace.BaseRevisionID) || !digestPattern.MatchString(spec.Workspace.BaseRevisionDigest) || spec.Workspace.BaseWorkspaceHeadVersion < 0 ||
		!oneOf(spec.Workspace.CommitMode, "read_only", "cas_new_revision") || spec.Workspace.SnapshotReference != "" && !identifierPattern.MatchString(spec.Workspace.SnapshotReference) || spec.Workspace.MountPath != "" && spec.Workspace.MountPath != "/workspace" ||
		!validDateTime(spec.Lease.ExpiresAt) || spec.Lease.MaxExtensionSeconds < 0 {
		return ErrInvalidContractDocument
	}
	if spec.PlacementConstraints != nil && (spec.PlacementConstraints.RegionID != "" && !identifierPattern.MatchString(spec.PlacementConstraints.RegionID) || spec.PlacementConstraints.ResourceClass != "" && !oneOf(spec.PlacementConstraints.ResourceClass, "standard", "browser", "office", "video", "gpu") || spec.PlacementConstraints.Architecture != "" && !oneOf(spec.PlacementConstraints.Architecture, "amd64", "arm64")) {
		return ErrInvalidContractDocument
	}
	if spec.Security.PrivilegeLevel != "unprivileged" || spec.Security.RootFilesystem != "read_only" || !oneOf(spec.Security.ServiceAccountMode, "none", "restricted") || spec.Security.AllowPrivilegeEscalation || spec.Security.HostNamespaceAccess || spec.Security.SeccompProfile != "" && !oneOf(spec.Security.SeccompProfile, "runtime-default", "localhost-profile") || !slotPattern.MatchString(spec.SandboxSlotKey) {
		return ErrInvalidContractDocument
	}
	if spec.AgentRunID != "" && !identifierPattern.MatchString(spec.AgentRunID) || len(spec.Labels) > 32 {
		return ErrInvalidContractDocument
	}
	for key, value := range spec.Labels {
		if !labelPattern.MatchString(key) || !boundedString(value, 0, 200) {
			return ErrInvalidContractDocument
		}
	}
	return nil
}

func validateProviderOperation(document ProviderOperation) error {
	if !identifierPattern.MatchString(document.OperationID) || !identifierPattern.MatchString(document.AttemptID) || document.FencingToken < 1 || !identifierPattern.MatchString(document.SandboxID) ||
		!oneOf(document.Type, "create", "exec", "cancel_exec", "open_runtime_session", "open_browser_session", "artifact_stage") || !oneOf(document.Status, "accepted", "running", "succeeded", "failed", "cancelled", "outcome_unknown") ||
		document.ProviderOperationID != "" && !identifierPattern.MatchString(document.ProviderOperationID) || document.ResultReference != "" && !referencePattern.MatchString(document.ResultReference) || !validDateTime(document.ObservedAt) {
		return ErrInvalidContractDocument
	}
	if document.Error != nil {
		return validateProviderError(*document.Error)
	}
	return nil
}

func validateSandboxStatus(document SandboxStatus) error {
	for _, value := range []string{document.SandboxID, document.TenantID, document.WorkOrderID, document.WorkspaceID, document.ProviderRevisionID} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidContractDocument
		}
	}
	if !oneOf(document.DesiredState, "ready", "suspended", "terminated") || !oneOf(document.ObservedState, "requested", "provisioning", "ready", "suspending", "suspended", "resuming", "terminating", "terminated", "expired", "failed") ||
		document.Generation < 1 || document.ObservedGeneration < 0 || document.RuntimeProfile != "" && !boundedString(document.RuntimeProfile, 1, 200) || document.RuntimeEndpointReference != "" && !referencePattern.MatchString(document.RuntimeEndpointReference) ||
		!validDateTime(document.LeaseExpiresAt) || document.SnapshotReference != "" && !referencePattern.MatchString(document.SnapshotReference) || !validDateTime(document.CreatedAt) || !validDateTime(document.UpdatedAt) || !slotPattern.MatchString(document.SandboxSlotKey) ||
		document.AgentRunID != "" && !identifierPattern.MatchString(document.AgentRunID) || document.ProviderStateReference != "" && !referencePattern.MatchString(document.ProviderStateReference) {
		return ErrInvalidContractDocument
	}
	if document.LastError != nil {
		return validateProviderError(*document.LastError)
	}
	return nil
}

func validateProviderError(document ProviderError) error {
	if !errorCodePattern.MatchString(document.Code) || !boundedString(document.Message, 1, 512) || !oneOf(document.Outcome, "known_failed", "outcome_unknown") || document.ProviderCode != "" && !errorCodePattern.MatchString(document.ProviderCode) || len(document.Details) > 16 {
		return ErrInvalidContractDocument
	}
	for _, value := range document.Details {
		if !boundedString(value, 0, 256) {
			return ErrInvalidContractDocument
		}
	}
	return nil
}

func validateStandardError(document StandardError) error {
	if !errorCodePattern.MatchString(document.Code) || !boundedString(document.Message, 1, 512) || !boundedString(document.TraceID, 1, 200) {
		return ErrInvalidContractDocument
	}
	return nil
}

func decodeStrict(document []byte, target any, requiredKeys []string, nonNullOptionalKeys []string) (map[string]json.RawMessage, error) {
	if _, err := jcs.Canonicalize(document); err != nil {
		return nil, ErrInvalidContractDocument
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nil, ErrInvalidContractDocument
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidContractDocument
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil {
		return nil, ErrInvalidContractDocument
	}
	for _, key := range requiredKeys {
		if value, ok := object[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrInvalidContractDocument
		}
	}
	for _, key := range nonNullOptionalKeys {
		if value, ok := object[key]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrInvalidContractDocument
		}
	}
	return object, nil
}

func boundedString(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func validDateTime(value string) bool {
	if value == "" || strings.Contains(value, " ") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func uniqueIdentifiers(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !identifierPattern.MatchString(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
