package provider

import "encoding/json"

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
