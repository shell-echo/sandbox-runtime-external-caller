package callerprovider

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

const capabilityCaseID = "initial.locked-capability-discovery"

var ErrCapabilityScenario = errors.New("locked capability scenario failed")

type capabilityDiscovery struct {
	document   provider.ProviderCapabilities
	raw        []byte
	attempts   int
	transients []protocol.Outcome
	final      protocol.Outcome
}

// RunCapabilityDiscoveryScenario executes exactly the first locked initial
// case. It performs no Provider mutation and never starts or contacts the
// caller Gateway. The caller-owned state advances only to capabilities_bound.
func RunCapabilityDiscoveryScenario(ctx context.Context, origin string, bundle *credentials.Bundle, store *callerstate.Store) (protocol.ScenarioResultData, error) {
	result, _, err := runCapabilityDiscoveryScenario(ctx, origin, bundle, store, time.Now)
	return result, err
}

func runCapabilityDiscoveryScenario(ctx context.Context, origin string, bundle *credentials.Bundle, store *callerstate.Store, now func() time.Time) (protocol.ScenarioResultData, provider.ProviderCapabilities, error) {
	if ctx == nil || bundle == nil || store == nil || now == nil || ctx.Err() != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, preserveContext(ctx, ErrCapabilityScenario)
	}
	startedAt := now()
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(startedAt) || deadline.Sub(startedAt) > 120*time.Second {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}
	state := store.Snapshot()
	if state.Stage != callerstate.StagePlanned || state.Plan.TenantAID == state.Plan.TenantBID {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}
	controllerA, err := credentials.BuildProviderAccessFromBundle(bundle, origin, "controller_a")
	if err != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}
	defer controllerA.Close()
	controllerB, err := credentials.BuildProviderAccessFromBundle(bundle, origin, "controller_b")
	if err != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}
	defer controllerB.Close()
	unadmitted, err := credentials.BuildProviderAccessFromBundle(bundle, origin, "same_ca_unadmitted")
	if err != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}
	defer unadmitted.Close()
	if controllerA.Client == nil || controllerB.Client == nil || unadmitted.Client == nil || controllerA.Admission == nil || controllerB.Admission == nil || unadmitted.Admission != nil ||
		controllerA.ControllerSubject == controllerB.ControllerSubject || controllerA.ControllerSubject == unadmitted.ControllerSubject || controllerB.ControllerSubject == unadmitted.ControllerSubject {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}

	discoveryA, err := discoverAdmittedCapabilities(ctx, controllerA.Client)
	if err != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, preserveContext(ctx, ErrCapabilityScenario)
	}
	discoveryB, err := discoverAdmittedCapabilities(ctx, controllerB.Client)
	if err != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, preserveContext(ctx, ErrCapabilityScenario)
	}
	if validateLockedCapabilitySnapshot(discoveryA.document) != nil || validateLockedCapabilitySnapshot(discoveryB.document) != nil ||
		discoveryA.document.ProviderRevisionID != discoveryB.document.ProviderRevisionID || !bytes.Equal(discoveryA.raw, discoveryB.raw) {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}
	discoveryDenied, err := discoverUnadmittedCapabilities(ctx, unadmitted.Client)
	if err != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, preserveContext(ctx, ErrCapabilityScenario)
	}
	policyDigest, err := policyDigest(state)
	if err != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}

	interactions := []protocol.InteractionResult{
		capabilityInteraction("controller-a-capabilities", "controller_a", discoveryA, []string{
			"schema-valid-capability-document", "exact-provider-revision", "exact-atomic-coding-shell-profile", "caller-and-adapter-startup-identities-observed",
		}),
		capabilityInteraction("controller-b-capabilities", "controller_b", discoveryB, []string{
			"distinct-controller-identity", "distinct-tenant-binding", "byte-identical-capability-snapshot",
		}),
		capabilityInteraction("same-ca-unadmitted-capabilities", "same_ca_unadmitted", discoveryDenied, []string{
			"same-ca-distinct-uri-san", "no-capability-document-returned",
		}),
	}
	observations := []string{
		"schema-valid-capability-document", "exact-provider-revision", "exact-atomic-coding-shell-profile", "caller-and-adapter-startup-identities-observed",
		"distinct-controller-identity", "distinct-tenant-binding", "byte-identical-capability-snapshot",
		"same-ca-distinct-uri-san", "no-capability-document-returned",
	}
	result := protocol.ScenarioResultData{
		CaseID: capabilityCaseID, Disposition: "completed", Interactions: interactions,
		Assertions: []protocol.AssertionResult{
			{AssertionID: "caller-consumed-embedded-contract-identity", Result: "asserted"},
			{AssertionID: "caller-consumed-embedded-profile-identity", Result: "asserted"},
			{AssertionID: "harness-expectations-not-used-as-caller-attestation", Result: "asserted"},
		},
		ObservationIDs: observations,
	}
	if protocol.ContractRevision != "22ba6987ea5fbc37d53942720133c0acad199edd" || protocol.ContractTree != "c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38" ||
		protocol.ProfileID != "sandbox-runtime-external-caller-coding-shell-v1" || protocol.ProfileVersion != "1.0.0" ||
		protocol.ProfileDigest != "sha256:ec113d31612dbb7cc0e9461925170f74f33722bb2efb237dbc68aa89f2d60231" || protocol.ValidateScenarioResultData("initial", result) != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}
	if store.BindCapabilities(discoveryA.document.ProviderRevisionID, discoveryA.raw, policyDigest, policyDecisionAt(now())) != nil || store.ValidateUnchanged() != nil {
		return protocol.ScenarioResultData{}, provider.ProviderCapabilities{}, ErrCapabilityScenario
	}
	return result, discoveryA.document, nil
}

type capabilityClient interface {
	DiscoverCapabilitiesDocument(context.Context) (provider.ProviderCapabilities, []byte, error)
}

func discoverAdmittedCapabilities(ctx context.Context, client capabilityClient) (capabilityDiscovery, error) {
	return discoverCapabilities(ctx, client, false)
}

func discoverUnadmittedCapabilities(ctx context.Context, client capabilityClient) (capabilityDiscovery, error) {
	return discoverCapabilities(ctx, client, true)
}

func discoverCapabilities(ctx context.Context, client capabilityClient, denied bool) (capabilityDiscovery, error) {
	if client == nil {
		return capabilityDiscovery{}, ErrCapabilityScenario
	}
	result := capabilityDiscovery{transients: []protocol.Outcome{}}
	for result.attempts < maxPollAttempts {
		result.attempts++
		document, raw, err := client.DiscoverCapabilitiesDocument(ctx)
		if !denied && err == nil {
			result.document, result.raw = document, raw
			result.final = protocol.Outcome{Transport: "http-response", StatusCode: statusCode(http.StatusOK)}
			return result, nil
		}
		if denied && errors.Is(err, provider.ErrTLSRejected) {
			result.final = protocol.Outcome{Transport: "tls-rejected"}
			return result, nil
		}
		var responseError *provider.HTTPError
		if denied && errors.As(err, &responseError) && responseError.StatusCode == http.StatusForbidden && !responseError.Document.Retryable {
			result.final = httpOutcome(responseError)
			return result, nil
		}
		if !errors.As(err, &responseError) || responseError.StatusCode != http.StatusServiceUnavailable || !responseError.Document.Retryable {
			return capabilityDiscovery{}, ErrCapabilityScenario
		}
		result.transients = append(result.transients, httpOutcome(responseError))
		if result.attempts == maxPollAttempts {
			return capabilityDiscovery{}, ErrCapabilityScenario
		}
		delay := pollInterval
		if responseError.RetryAfterSeconds != nil && *responseError.RetryAfterSeconds > 0 {
			delay = time.Duration(*responseError.RetryAfterSeconds) * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return capabilityDiscovery{}, context.Cause(ctx)
		}
	}
	return capabilityDiscovery{}, ErrCapabilityScenario
}

func capabilityInteraction(id, actor string, discovery capabilityDiscovery, observations []string) protocol.InteractionResult {
	return protocol.InteractionResult{
		InteractionID: id, Surface: "provider_http", Actor: actor, Method: http.MethodGet,
		RouteTemplate: "/v1/capabilities", LogicalRequestID: id, WireAttempts: discovery.attempts,
		TransientOutcomes: cloneOutcomes(discovery.transients), FinalOutcome: discovery.final,
		MutationWriteObserved: false, ObservationIDs: append([]string(nil), observations...),
	}
}

func cloneOutcomes(values []protocol.Outcome) []protocol.Outcome {
	if values == nil {
		return nil
	}
	result := make([]protocol.Outcome, len(values))
	copy(result, values)
	return result
}

func httpOutcome(response *provider.HTTPError) protocol.Outcome {
	if response == nil {
		return protocol.Outcome{}
	}
	code := response.Document.Code
	return protocol.Outcome{
		Transport: "http-response", StatusCode: statusCode(response.StatusCode), ErrorCode: &code,
		Retryable: response.Document.Retryable, RetryAfterPresent: response.RetryAfterSeconds != nil,
	}
}

func statusCode(value int) *int { return &value }

func validateLockedCapabilitySnapshot(document provider.ProviderCapabilities) error {
	if document.APIVersion != "v1" || document.ProviderRevisionID == "" || document.Limits.MaxCPUMillis < 500 || document.Limits.MaxMemoryBytes < 268435456 ||
		document.Limits.MaxEphemeralStorageBytes < 268435456 || document.Limits.MaxLeaseSeconds < 1 || document.Limits.MaxExecSeconds < 1 ||
		(len(document.Capabilities) != 2 && len(document.Capabilities) != 3) || len(document.RuntimeProfiles) != 1 {
		return ErrCapabilityScenario
	}
	expectedProfiles := map[string]string{"sandbox.exec": ExecProfileID, "sandbox.terminal": TerminalProfileID}
	if len(document.Capabilities) == 3 {
		expectedProfiles["sandbox.terminal-connect"] = TerminalConnectProfileID
	}
	seen := make(map[string]struct{}, len(document.Capabilities))
	for _, capability := range document.Capabilities {
		profile, ok := expectedProfiles[capability.ID]
		if !ok || len(capability.Versions) != 1 || capability.Versions[0] != "1.0.0" || len(capability.Profiles) != 1 || capability.Profiles[0] != profile {
			return ErrCapabilityScenario
		}
		if _, duplicate := seen[capability.ID]; duplicate {
			return ErrCapabilityScenario
		}
		seen[capability.ID] = struct{}{}
	}
	if len(seen) != len(expectedProfiles) {
		return ErrCapabilityScenario
	}
	profile := document.RuntimeProfiles[0]
	if profile.ID != RuntimeProfileID || len(profile.CapabilityProfileIDs) != len(expectedProfiles) {
		return ErrCapabilityScenario
	}
	for _, required := range expectedProfiles {
		if !contains(profile.CapabilityProfileIDs, required) {
			return ErrCapabilityScenario
		}
	}
	return nil
}
