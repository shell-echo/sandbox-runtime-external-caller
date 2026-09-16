package callerprovider

import (
	"testing"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

func TestLockedCapabilitySelectionAllowsOnlyAtomicProfileAndOptionalConnect(t *testing.T) {
	base := provider.ProviderCapabilities{
		ProviderRevisionID: "provider-revision-1", APIVersion: "v1",
		Capabilities: []provider.Capability{
			{ID: "sandbox.exec", Versions: []string{"1.0.0"}, Profiles: []string{ExecProfileID}},
			{ID: "sandbox.terminal", Versions: []string{"1.0.0"}, Profiles: []string{TerminalProfileID}},
		},
		RuntimeProfiles: []provider.RuntimeProfile{{
			ID: RuntimeProfileID, IsolationClass: "container", CapabilityProfileIDs: []string{ExecProfileID, TerminalProfileID},
		}},
		SnapshotRestoreProfiles: []provider.SnapshotRestoreProfile{{
			ProfileID: "workspace-v1", Level: "workspace", SuiteID: "sandbox-provider", SuiteVersion: "1.0.0",
			SuiteDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
		Limits: provider.ProviderLimits{MaxCPUMillis: 500, MaxMemoryBytes: 268435456, MaxEphemeralStorageBytes: 268435456, MaxLeaseSeconds: 1, MaxExecSeconds: 1},
	}
	if err := validateLockedCapabilitySnapshot(base); err != nil {
		t.Fatalf("required coding-shell profile rejected: %v", err)
	}
	withConnect := base
	withConnect.Capabilities = append(append([]provider.Capability(nil), base.Capabilities...), provider.Capability{ID: "sandbox.terminal-connect", Versions: []string{"1.0.0"}, Profiles: []string{TerminalConnectProfileID}})
	withConnect.RuntimeProfiles = append([]provider.RuntimeProfile(nil), base.RuntimeProfiles...)
	withConnect.RuntimeProfiles[0].CapabilityProfileIDs = []string{ExecProfileID, TerminalProfileID, TerminalConnectProfileID}
	if err := validateLockedCapabilitySnapshot(withConnect); err != nil {
		t.Fatalf("optional terminal-connect profile rejected: %v", err)
	}

	for name, mutate := range map[string]func(*provider.ProviderCapabilities){
		"extra capability": func(value *provider.ProviderCapabilities) {
			value.Capabilities = append(value.Capabilities, provider.Capability{ID: "sandbox.browser", Versions: []string{"1.0.0"}, Profiles: []string{"browser-v1"}})
		},
		"extra runtime": func(value *provider.ProviderCapabilities) {
			value.RuntimeProfiles = append(value.RuntimeProfiles, value.RuntimeProfiles[0])
		},
		"wrong version": func(value *provider.ProviderCapabilities) { value.Capabilities[0].Versions[0] = "1.1.0" },
		"split profile": func(value *provider.ProviderCapabilities) {
			value.RuntimeProfiles[0].CapabilityProfileIDs = []string{ExecProfileID}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.Capabilities = append([]provider.Capability(nil), base.Capabilities...)
			for index := range value.Capabilities {
				value.Capabilities[index].Versions = append([]string(nil), base.Capabilities[index].Versions...)
				value.Capabilities[index].Profiles = append([]string(nil), base.Capabilities[index].Profiles...)
			}
			value.RuntimeProfiles = append([]provider.RuntimeProfile(nil), base.RuntimeProfiles...)
			value.RuntimeProfiles[0].CapabilityProfileIDs = append([]string(nil), base.RuntimeProfiles[0].CapabilityProfileIDs...)
			mutate(&value)
			if err := validateLockedCapabilitySnapshot(value); err == nil {
				t.Fatal("invalid capability snapshot accepted")
			}
		})
	}
}
