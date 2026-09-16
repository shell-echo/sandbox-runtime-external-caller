package callerprovider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerterminal"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

func runExecTerminal(ctx context.Context, store *callerstate.Store, controller *access, capabilities provider.ProviderCapabilities, lease string, now func() time.Time) (*callerterminal.Authority, error) {
	state := store.Snapshot()
	request, err := execRequest(ctx, state, capabilities.Limits.MaxExecSeconds, lease, now())
	if err != nil {
		return nil, err
	}
	descriptor := plannedDescriptor(state, state.Plan.Exec, execFencingToken)
	admission, err := mutationAdmission(controller, state, descriptor, "exec", request.RequestDigest, request.DeadlineAt, provider.ExecRequestContractID, "/v1/sandboxes/"+state.Plan.SandboxID+"/exec", now())
	if err != nil {
		return nil, err
	}
	operation, err := controller.client.CreateExec(ctx, state.Plan.SandboxID, request, admission)
	if err != nil || operation.Status != "accepted" || !operationMatches(operation, descriptor, "exec") {
		return nil, preserveContext(ctx, ErrLifecycle)
	}
	if err := waitOperation(ctx, controller, state, descriptor, "exec", now); err != nil {
		return nil, err
	}
	descriptor.Operation = "read_result"
	result, err := readRetained(ctx, controller, state, descriptor, now, controller.client.GetExecResult)
	if err != nil {
		return nil, err
	}
	started, startErr := time.Parse(time.RFC3339Nano, result.StartedAt)
	completed, completeErr := time.Parse(time.RFC3339Nano, result.CompletedAt)
	retained, retainErr := time.Parse(time.RFC3339Nano, result.RetainedUntil)
	if !correlates(descriptor, result.SandboxID, result.OperationID, result.AttemptID, result.FencingToken) || result.Status != "completed" || result.ExitCode == nil || *result.ExitCode != 0 || result.Error != nil || result.Signal != "" || startErr != nil || completeErr != nil || retainErr != nil || completed.Before(started) || completed.After(now()) || !retained.After(now()) || !retained.After(completed) {
		return nil, ErrLifecycle
	}
	descriptor.Operation = "read_usage_evidence"
	usage, err := readRetained(ctx, controller, state, descriptor, now, controller.client.GetUsageEvidence)
	if err != nil {
		return nil, err
	}
	if !retained.After(now()) || !execUsageMatches(usage, descriptor, now()) {
		return nil, ErrLifecycle
	}
	resultDigest, err := jcs.Digest(result)
	if err != nil {
		return nil, ErrLifecycle
	}
	// These are caller-computed digests of the actual decoded documents. The
	// Provider's opaque evidence_digest is retained inside the usage preimage;
	// this caller does not invent a Provider evidence-digest algorithm.
	usageDigest, err := jcs.Digest(usage)
	if err != nil {
		return nil, ErrLifecycle
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	if err := store.BindExec(execFencingToken, resultDigest, usageDigest); err != nil {
		return nil, ErrLifecycle
	}

	state = store.Snapshot()
	session, err := runtimeSessionRequest(ctx, state, lease, now())
	if err != nil {
		return nil, err
	}
	descriptor = plannedDescriptor(state, state.Plan.Terminal, terminalFencingToken)
	admission, err = mutationAdmission(controller, state, descriptor, "open_runtime_session", session.RequestDigest, session.DeadlineAt, provider.RuntimeSessionRequestContractID, "/v1/sandboxes/"+state.Plan.SandboxID+"/runtime-sessions", now())
	if err != nil {
		return nil, err
	}
	operation, err = controller.client.OpenRuntimeSession(ctx, state.Plan.SandboxID, session, admission)
	if err != nil || operation.Status != "accepted" || !operationMatches(operation, descriptor, "open_runtime_session") {
		return nil, preserveContext(ctx, ErrLifecycle)
	}
	if err := waitOperation(ctx, controller, state, descriptor, "open_runtime_session", now); err != nil {
		return nil, err
	}
	descriptor.Operation = "read_runtime_session"
	handoff, err := readRetained(ctx, controller, state, descriptor, now, controller.client.GetRuntimeSessionHandoff)
	if err != nil {
		return nil, err
	}
	expiry, expiryErr := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
	requestedExpiry, _ := time.Parse(time.RFC3339Nano, session.ExpiresAt)
	if !correlates(descriptor, handoff.SandboxID, handoff.OperationID, handoff.AttemptID, handoff.FencingToken) || handoff.RuntimeSessionID != session.RuntimeSessionID || handoff.RuntimeType != session.RuntimeType || handoff.CapabilityProfileID != session.CapabilityProfileID || handoff.Protocol != "websocket" || expiryErr != nil || !expiry.After(now()) || expiry.After(requestedExpiry) {
		return nil, ErrLifecycle
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	if err := store.BindTerminal(terminalFencingToken, handoff.RuntimeSessionID, handoff.InternalEndpointReference); err != nil {
		return nil, ErrLifecycle
	}
	authority := &callerterminal.Authority{
		ProviderRevisionID: state.Provider.ProviderRevisionID, SandboxID: handoff.SandboxID,
		OperationID: handoff.OperationID, AttemptID: handoff.AttemptID, FencingToken: handoff.FencingToken,
		RuntimeSessionID: handoff.RuntimeSessionID, HandoffReference: handoff.InternalEndpointReference,
		ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: expiry,
	}
	connectState := store.Snapshot()
	if err := authority.BindBackend(func(connectContext context.Context, reference string) (io.ReadWriteCloser, error) {
		if reference != handoff.InternalEndpointReference || connectContext == nil || connectContext.Err() != nil || !expiry.After(now()) {
			return nil, ErrLifecycle
		}
		deadline := expiry
		if value, ok := connectContext.Deadline(); ok && value.Before(deadline) {
			deadline = value
		}
		digest, err := provider.DigestRuntimeSessionConnectDescriptor(handoff)
		if err != nil || !deadline.After(now()) {
			return nil, ErrLifecycle
		}
		admission, err := buildAdmission(controller, connectState, provider.AdmissionBinding{
			Operation: "connect_runtime_session", SandboxID: handoff.SandboxID, OperationID: handoff.OperationID,
			AttemptID: handoff.AttemptID, FencingToken: handoff.FencingToken, DeadlineAt: deadline.UTC().Format(time.RFC3339Nano),
			RequestContractID: provider.RuntimeSessionConnectDescriptorContractID, RequestDigestProfile: provider.DescriptorDigestProfile, RequestDigest: digest,
			HTTPTarget: provider.AdmissionTarget{Method: http.MethodGet, Path: "/v1/runtime-sessions:connect", NormalizedQuery: []provider.QueryParameter{}},
		}, now())
		if err != nil {
			return nil, err
		}
		return controller.client.ConnectRuntimeSession(connectContext, handoff, admission)
	}, func() { closeAccess(controller) }); err != nil {
		return nil, ErrLifecycle
	}
	return authority, nil
}

func execRequest(ctx context.Context, state callerstate.State, maxExecSeconds int64, lease string, now time.Time) (provider.ExecRequest, error) {
	deadline, err := boundedDeadline(ctx, now, lease, maxExecSeconds)
	if err != nil {
		return provider.ExecRequest{}, err
	}
	return provider.BindExecRequest(provider.ExecRequest{
		OperationID: state.Plan.Exec.OperationID, AttemptID: state.Plan.Exec.AttemptID,
		FencingToken: execFencingToken, IdempotencyKey: state.Plan.Exec.IdempotencyKey,
		DeadlineAt: deadline.Format(time.RFC3339Nano), ExpectedGeneration: 1,
		Command: []string{"sh", "-c", "printf external-caller; printf external-caller-artifact > /outputs/external-caller.txt"}, WorkingDirectory: "/workspace",
		ResultRetentionSeconds: 3600, Capture: &provider.ExecCapture{Stdout: true, Stderr: true, MaxBytes: 4096},
	})
}

func runtimeSessionRequest(ctx context.Context, state callerstate.State, lease string, now time.Time) (provider.RuntimeSessionOpenRequest, error) {
	deadline, err := boundedDeadline(ctx, now, lease, 60)
	if err != nil {
		return provider.RuntimeSessionOpenRequest{}, err
	}
	return provider.BindRuntimeSessionOpenRequest(provider.RuntimeSessionOpenRequest{
		OperationID: state.Plan.Terminal.OperationID, AttemptID: state.Plan.Terminal.AttemptID,
		FencingToken: terminalFencingToken, IdempotencyKey: state.Plan.Terminal.IdempotencyKey,
		DeadlineAt: deadline.Format(time.RFC3339Nano), ExpectedGeneration: 1,
		RuntimeSessionID: "runtime-session-" + state.Plan.RunID, RuntimeType: "terminal",
		CapabilityProfileID: TerminalProfileID, ExpiresAt: deadline.Format(time.RFC3339Nano),
	})
}

func boundedDeadline(ctx context.Context, now time.Time, lease string, limitSeconds int64) (time.Time, error) {
	deadline, ok := ctx.Deadline()
	leaseExpiry, err := time.Parse(time.RFC3339Nano, lease)
	if !ok || err != nil || limitSeconds < 1 {
		return time.Time{}, ErrLifecycle
	}
	// Clamp before converting the externally supplied integer to a duration.
	if limitSeconds > 60 {
		limitSeconds = 60
	}
	for _, limit := range []time.Time{leaseExpiry, now.Add(time.Duration(limitSeconds) * time.Second)} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	if ctx.Err() != nil || !deadline.After(now.Add(100*time.Millisecond)) {
		return time.Time{}, preserveContext(ctx, ErrLifecycle)
	}
	return deadline.UTC(), nil
}

func plannedDescriptor(state callerstate.State, plan callerstate.PlannedOperation, fence int64) provider.ReadDescriptor {
	return provider.ReadDescriptor{Operation: "read_operation", SandboxID: state.Plan.SandboxID, OperationID: plan.OperationID, AttemptID: plan.AttemptID, FencingToken: fence}
}

func mutationAdmission(value *access, state callerstate.State, descriptor provider.ReadDescriptor, operation, digest, deadline, contractID, path string, now time.Time) (provider.Admission, error) {
	return buildAdmission(value, state, provider.AdmissionBinding{
		Operation: operation, SandboxID: descriptor.SandboxID, OperationID: descriptor.OperationID,
		AttemptID: descriptor.AttemptID, FencingToken: descriptor.FencingToken, DeadlineAt: deadline,
		RequestContractID: contractID, RequestDigestProfile: provider.MutationDigestProfile, RequestDigest: digest,
		HTTPTarget: provider.AdmissionTarget{Method: http.MethodPost, Path: path, NormalizedQuery: []provider.QueryParameter{}},
	}, now)
}

func correlates(descriptor provider.ReadDescriptor, sandbox, operation, attempt string, fence int64) bool {
	return sandbox == descriptor.SandboxID && operation == descriptor.OperationID && attempt == descriptor.AttemptID && fence == descriptor.FencingToken
}

func operationMatches(operation provider.ProviderOperation, descriptor provider.ReadDescriptor, expectedType string) bool {
	return correlates(descriptor, operation.SandboxID, operation.OperationID, operation.AttemptID, operation.FencingToken) && operation.Type == expectedType && operation.Error == nil
}

func execUsageMatches(usage provider.UsageEvidence, descriptor provider.ReadDescriptor, now time.Time) bool {
	observed, err := time.Parse(time.RFC3339Nano, usage.ObservedAt)
	retained, retainErr := time.Parse(time.RFC3339Nano, usage.RetainedUntil)
	if !correlates(descriptor, usage.SandboxID, usage.OperationID, usage.AttemptID, usage.FencingToken) || (usage.ReconciliationStatus != "complete" && usage.ReconciliationStatus != "partial") || err != nil || retainErr != nil || observed.After(now) || !retained.After(now) {
		return false
	}
	countEntries := 0
	for _, entry := range usage.Entries {
		occurred, err := time.Parse(time.RFC3339Nano, entry.OccurredAt)
		if err != nil || occurred.After(observed) || entry.SandboxID != descriptor.SandboxID || entry.OperationID != "" && entry.OperationID != descriptor.OperationID {
			return false
		}
		if entry.Meter == "sandbox.exec_count" {
			if entry.OperationID != descriptor.OperationID || entry.Unit != "count" || entry.Quantity != 1 || (entry.MeterSource != "runtime_metered" && entry.MeterSource != "reconciled") {
				return false
			}
			countEntries++
		}
	}
	return countEntries == 1
}

// Retry only an explicit temporary response to a read, with fresh admission
// each time. Mutations are never silently repeated after an unknown outcome.
func readRetained[T any](ctx context.Context, value *access, state callerstate.State, descriptor provider.ReadDescriptor, now func() time.Time, read func(context.Context, provider.ReadDescriptor, provider.Admission) (T, error)) (T, error) {
	var zero T
	for attempt := 0; attempt < maxPollAttempts; attempt++ {
		if ctx.Err() != nil {
			return zero, context.Cause(ctx)
		}
		admission, err := readAdmission(ctx, value, state, descriptor, now())
		if err != nil {
			return zero, err
		}
		result, err := read(ctx, descriptor, admission)
		if err == nil {
			return result, nil
		}
		var rejection *provider.HTTPError
		if !errors.As(err, &rejection) || rejection.StatusCode != http.StatusServiceUnavailable || !rejection.Document.Retryable || rejection.RetryAfterSeconds == nil || *rejection.RetryAfterSeconds < 1 || attempt == maxPollAttempts-1 {
			return zero, preserveContext(ctx, ErrLifecycle)
		}
		deadline, _ := ctx.Deadline()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return zero, preserveContext(ctx, ErrLifecycle)
		}
		if int64(*rejection.RetryAfterSeconds) > int64(remaining/time.Second) {
			return zero, ErrLifecycle
		}
		timer := time.NewTimer(time.Duration(*rejection.RetryAfterSeconds) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, context.Cause(ctx)
		case <-timer.C:
		}
	}
	return zero, ErrLifecycle
}
