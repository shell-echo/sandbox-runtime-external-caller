package provider

import "encoding/json"

const RuntimeSessionConnectDescriptorContractID = "urn:shell-echo:sandbox-runtime:descriptor:runtime-session-connect:v1"

type Capability struct {
	ID       string   `json:"id"`
	Versions []string `json:"versions"`
	Profiles []string `json:"profiles,omitempty"`
}

type RuntimeProfile struct {
	ID                   string   `json:"id"`
	IsolationClass       string   `json:"isolation_class"`
	RuntimeClassName     string   `json:"runtime_class_name,omitempty"`
	Architecture         []string `json:"architecture,omitempty"`
	CapabilityProfileIDs []string `json:"capability_profile_ids,omitempty"`
}

type SnapshotRestoreProfile struct {
	ProfileID    string `json:"profile_id"`
	Level        string `json:"level"`
	SuiteID      string `json:"suite_id"`
	SuiteVersion string `json:"suite_version"`
	SuiteDigest  string `json:"suite_digest"`
}

type ProviderLimits struct {
	MaxCPUMillis             int64  `json:"max_cpu_millis"`
	MaxMemoryBytes           int64  `json:"max_memory_bytes"`
	MaxEphemeralStorageBytes int64  `json:"max_ephemeral_storage_bytes"`
	MaxWorkspaceBytes        *int64 `json:"max_workspace_bytes,omitempty"`
	MaxGPUCount              *int64 `json:"max_gpu_count,omitempty"`
	MaxLeaseSeconds          int64  `json:"max_lease_seconds"`
	MaxExecSeconds           int64  `json:"max_exec_seconds"`
}

type ProviderCapabilities struct {
	ProviderRevisionID      string                   `json:"provider_revision_id"`
	APIVersion              string                   `json:"api_version"`
	Capabilities            []Capability             `json:"capabilities"`
	RuntimeProfiles         []RuntimeProfile         `json:"runtime_profiles"`
	SnapshotRestoreProfiles []SnapshotRestoreProfile `json:"snapshot_restore_profiles"`
	Limits                  ProviderLimits           `json:"limits"`
}

type Image struct {
	Reference    string `json:"reference"`
	Digest       string `json:"digest"`
	Architecture string `json:"architecture,omitempty"`
}

type Resources struct {
	CPUMillis             int64  `json:"cpu_millis"`
	MemoryBytes           int64  `json:"memory_bytes"`
	EphemeralStorageBytes int64  `json:"ephemeral_storage_bytes"`
	WorkspaceBytes        *int64 `json:"workspace_bytes,omitempty"`
	GPUCount              *int64 `json:"gpu_count,omitempty"`
	PIDsLimit             int64  `json:"pids_limit"`
}

type CapabilityRequirement struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Profile string `json:"profile,omitempty"`
}

type NetworkPolicy struct {
	Mode                  string `json:"mode"`
	PolicyReference       string `json:"policy_reference,omitempty"`
	EgressGatewayRequired *bool  `json:"egress_gateway_required,omitempty"`
}

type WorkspacePolicy struct {
	Mode                     string `json:"mode"`
	BaseRevisionID           string `json:"base_revision_id"`
	BaseRevisionDigest       string `json:"base_revision_digest"`
	BaseWorkspaceHeadVersion int64  `json:"base_workspace_head_version"`
	CommitMode               string `json:"commit_mode"`
	SnapshotReference        string `json:"snapshot_reference,omitempty"`
	MountPath                string `json:"mount_path,omitempty"`
}

type LeasePolicy struct {
	ExpiresAt           string `json:"expires_at"`
	MaxExtensionSeconds int64  `json:"max_extension_seconds"`
}

type PlacementConstraints struct {
	RegionID      string `json:"region_id,omitempty"`
	ResourceClass string `json:"resource_class,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
}

type SecurityPolicy struct {
	PrivilegeLevel           string `json:"privilege_level"`
	RootFilesystem           string `json:"root_filesystem"`
	ServiceAccountMode       string `json:"service_account_mode"`
	AllowPrivilegeEscalation bool   `json:"allow_privilege_escalation"`
	HostNamespaceAccess      bool   `json:"host_namespace_access"`
	SeccompProfile           string `json:"seccomp_profile,omitempty"`
}

type SandboxSpec struct {
	SandboxID            string                  `json:"sandbox_id"`
	TenantID             string                  `json:"tenant_id"`
	WorkOrderID          string                  `json:"work_order_id"`
	WorkspaceID          string                  `json:"workspace_id"`
	BranchID             string                  `json:"branch_id"`
	ProviderResolutionID string                  `json:"provider_resolution_id"`
	ProviderRevisionID   string                  `json:"provider_revision_id"`
	Image                Image                   `json:"image"`
	RuntimeProfile       string                  `json:"runtime_profile"`
	Resources            Resources               `json:"resources"`
	RequiredCapabilities []CapabilityRequirement `json:"required_capabilities"`
	OptionalCapabilities []CapabilityRequirement `json:"optional_capabilities,omitempty"`
	Network              NetworkPolicy           `json:"network"`
	Workspace            WorkspacePolicy         `json:"workspace"`
	Lease                LeasePolicy             `json:"lease"`
	PlacementConstraints *PlacementConstraints   `json:"placement_constraints,omitempty"`
	Security             SecurityPolicy          `json:"security"`
	Labels               map[string]string       `json:"labels,omitempty"`
	SandboxSlotKey       string                  `json:"sandbox_slot_key"`
	AgentRunID           string                  `json:"agent_run_id,omitempty"`
}

type CreateSandboxRequest struct {
	OperationID     string                     `json:"operation_id"`
	AttemptID       string                     `json:"attempt_id"`
	FencingToken    int64                      `json:"fencing_token"`
	IdempotencyKey  string                     `json:"idempotency_key"`
	RequestDigest   string                     `json:"request_digest"`
	DeadlineAt      string                     `json:"deadline_at"`
	ProtocolVersion string                     `json:"protocol_version"`
	Spec            SandboxSpec                `json:"spec"`
	TraceContext    map[string]json.RawMessage `json:"trace_context,omitempty"`
}

type ExecCapture struct {
	Stdout   bool  `json:"stdout,omitempty"`
	Stderr   bool  `json:"stderr,omitempty"`
	MaxBytes int64 `json:"max_bytes,omitempty"`
}

type ExecRequest struct {
	OperationID            string            `json:"operation_id"`
	AttemptID              string            `json:"attempt_id"`
	FencingToken           int64             `json:"fencing_token"`
	IdempotencyKey         string            `json:"idempotency_key"`
	RequestDigest          string            `json:"request_digest"`
	DeadlineAt             string            `json:"deadline_at"`
	ExpectedGeneration     int64             `json:"expected_generation"`
	Command                []string          `json:"command"`
	WorkingDirectory       string            `json:"working_directory"`
	ResultRetentionSeconds int64             `json:"result_retention_seconds"`
	Environment            map[string]string `json:"environment,omitempty"`
	SecretReferenceIDs     []string          `json:"secret_reference_ids,omitempty"`
	SecretGrantID          string            `json:"secret_grant_id,omitempty"`
	SecretGrantDigest      string            `json:"secret_grant_digest,omitempty"`
	StdinReference         string            `json:"stdin_reference,omitempty"`
	Capture                *ExecCapture      `json:"capture,omitempty"`
}

type CancelExecRequest struct {
	OperationID        string `json:"operation_id"`
	AttemptID          string `json:"attempt_id"`
	FencingToken       int64  `json:"fencing_token"`
	IdempotencyKey     string `json:"idempotency_key"`
	RequestDigest      string `json:"request_digest"`
	DeadlineAt         string `json:"deadline_at"`
	ExpectedGeneration int64  `json:"expected_generation"`
	TargetOperationID  string `json:"target_operation_id"`
	TargetAttemptID    string `json:"target_attempt_id"`
	Reason             string `json:"reason"`
}

type ExecResult struct {
	OperationID     string         `json:"operation_id"`
	AttemptID       string         `json:"attempt_id"`
	FencingToken    int64          `json:"fencing_token"`
	SandboxID       string         `json:"sandbox_id"`
	Status          string         `json:"status"`
	ExitCode        *int           `json:"exit_code,omitempty"`
	Signal          string         `json:"signal,omitempty"`
	StdoutReference string         `json:"stdout_reference,omitempty"`
	StderrReference string         `json:"stderr_reference,omitempty"`
	StartedAt       string         `json:"started_at"`
	CompletedAt     string         `json:"completed_at"`
	RetainedUntil   string         `json:"retained_until"`
	Error           *ProviderError `json:"error,omitempty"`
}

type UsageEvidence struct {
	EvidenceID           string       `json:"evidence_id"`
	SandboxID            string       `json:"sandbox_id"`
	OperationID          string       `json:"operation_id"`
	AttemptID            string       `json:"attempt_id"`
	FencingToken         int64        `json:"fencing_token"`
	Entries              []UsageEntry `json:"entries"`
	ReconciliationStatus string       `json:"reconciliation_status"`
	ObservedAt           string       `json:"observed_at"`
	RetainedUntil        string       `json:"retained_until"`
	EvidenceDigest       string       `json:"evidence_digest"`
}

type UsageEntry struct {
	EntryID           string `json:"entry_id"`
	SandboxID         string `json:"sandbox_id"`
	OperationID       string `json:"operation_id,omitempty"`
	Meter             string `json:"meter"`
	Quantity          int64  `json:"quantity"`
	Unit              string `json:"unit"`
	MeterSource       string `json:"meter_source"`
	EvidenceReference string `json:"evidence_reference"`
	OccurredAt        string `json:"occurred_at"`
}

type RuntimeSessionOpenRequest struct {
	OperationID         string `json:"operation_id"`
	AttemptID           string `json:"attempt_id"`
	FencingToken        int64  `json:"fencing_token"`
	IdempotencyKey      string `json:"idempotency_key"`
	RequestDigest       string `json:"request_digest"`
	DeadlineAt          string `json:"deadline_at"`
	ExpectedGeneration  int64  `json:"expected_generation"`
	RuntimeSessionID    string `json:"runtime_session_id"`
	RuntimeType         string `json:"runtime_type"`
	CapabilityProfileID string `json:"capability_profile_id"`
	ExpiresAt           string `json:"expires_at"`
}

type RuntimeSessionHandoff struct {
	OperationID               string `json:"operation_id"`
	AttemptID                 string `json:"attempt_id"`
	FencingToken              int64  `json:"fencing_token"`
	SandboxID                 string `json:"sandbox_id"`
	RuntimeSessionID          string `json:"runtime_session_id"`
	RuntimeType               string `json:"runtime_type"`
	CapabilityProfileID       string `json:"capability_profile_id"`
	Protocol                  string `json:"protocol"`
	InternalEndpointReference string `json:"internal_endpoint_reference"`
	ConnectionGeneration      int64  `json:"connection_generation"`
	ExpiresAt                 string `json:"expires_at"`
}

type ArtifactStagingRequest struct {
	OperationID        string `json:"operation_id"`
	AttemptID          string `json:"attempt_id"`
	FencingToken       int64  `json:"fencing_token"`
	IdempotencyKey     string `json:"idempotency_key"`
	RequestDigest      string `json:"request_digest"`
	DeadlineAt         string `json:"deadline_at"`
	ExpectedGeneration int64  `json:"expected_generation"`
	ArtifactReference  string `json:"artifact_reference"`
	SourcePath         string `json:"source_path"`
	ExpectedDigest     string `json:"expected_digest"`
	ExpectedMediaType  string `json:"expected_media_type"`
	MaxBytes           int64  `json:"max_bytes"`
	RetentionSeconds   int64  `json:"retention_seconds"`
}

type ArtifactCheck struct {
	Status            string `json:"status"`
	CheckedAt         string `json:"checked_at"`
	EvidenceReference string `json:"evidence_reference,omitempty"`
}

type ArtifactStagingEvidence struct {
	OperationID        string        `json:"operation_id"`
	AttemptID          string        `json:"attempt_id"`
	FencingToken       int64         `json:"fencing_token"`
	SandboxID          string        `json:"sandbox_id"`
	ArtifactReference  string        `json:"artifact_reference"`
	StagingReference   string        `json:"staging_reference,omitempty"`
	Status             string        `json:"status"`
	ContentDigest      string        `json:"content_digest"`
	MediaType          string        `json:"media_type"`
	SizeBytes          int64         `json:"size_bytes"`
	TenantBindingCheck ArtifactCheck `json:"tenant_binding_check"`
	ActiveContentCheck ArtifactCheck `json:"active_content_check"`
	MalwareCheck       ArtifactCheck `json:"malware_check"`
	ObservedAt         string        `json:"observed_at"`
	ExpiresAt          string        `json:"expires_at"`
	EvidenceDigest     string        `json:"evidence_digest"`
}

type ProviderError struct {
	Code         string            `json:"code"`
	Message      string            `json:"message"`
	Retryable    bool              `json:"retryable"`
	Outcome      string            `json:"outcome"`
	ProviderCode string            `json:"provider_code,omitempty"`
	Details      map[string]string `json:"details,omitempty"`
}

type ProviderOperation struct {
	OperationID         string         `json:"operation_id"`
	AttemptID           string         `json:"attempt_id"`
	FencingToken        int64          `json:"fencing_token"`
	SandboxID           string         `json:"sandbox_id"`
	Type                string         `json:"type"`
	Status              string         `json:"status"`
	ProviderOperationID string         `json:"provider_operation_id,omitempty"`
	ResultReference     string         `json:"result_reference,omitempty"`
	Error               *ProviderError `json:"error,omitempty"`
	ObservedAt          string         `json:"observed_at"`
}

type SandboxStatus struct {
	SandboxID                string         `json:"sandbox_id"`
	TenantID                 string         `json:"tenant_id"`
	WorkOrderID              string         `json:"work_order_id"`
	WorkspaceID              string         `json:"workspace_id"`
	ProviderRevisionID       string         `json:"provider_revision_id"`
	DesiredState             string         `json:"desired_state"`
	ObservedState            string         `json:"observed_state"`
	Generation               int64          `json:"generation"`
	ObservedGeneration       int64          `json:"observed_generation"`
	RuntimeProfile           string         `json:"runtime_profile,omitempty"`
	RuntimeEndpointReference string         `json:"runtime_endpoint_reference,omitempty"`
	LeaseExpiresAt           string         `json:"lease_expires_at"`
	SnapshotReference        string         `json:"snapshot_reference,omitempty"`
	LastError                *ProviderError `json:"last_error,omitempty"`
	CreatedAt                string         `json:"created_at"`
	UpdatedAt                string         `json:"updated_at"`
	SandboxSlotKey           string         `json:"sandbox_slot_key"`
	AgentRunID               string         `json:"agent_run_id,omitempty"`
	ProviderStateReference   string         `json:"provider_state_reference,omitempty"`
}

type StandardError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	TraceID   string `json:"trace_id"`
}

type ReadDescriptor struct {
	Operation    string `json:"operation"`
	SandboxID    string `json:"sandbox_id"`
	OperationID  string `json:"operation_id"`
	AttemptID    string `json:"attempt_id"`
	FencingToken int64  `json:"fencing_token"`
}
