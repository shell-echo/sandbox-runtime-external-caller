// Package callerphase composes one external-caller phase around private state,
// Provider lifecycle work and a separately supervised Gateway service.
// Provider scenario execution is intentionally outside this checkpoint.
package callerphase

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callercontrol"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerstate"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerterminal"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/credentials"
)

const MaxPreparationLifetime = 5 * time.Minute

var (
	ErrPhaseDeadline    = errors.New("caller phase deadline is invalid")
	ErrPhaseState       = errors.New("caller phase state is invalid")
	ErrGatewayLifecycle = errors.New("caller Gateway lifecycle failed")
)

// GatewayService owns policy and transient grants. Stop must include terminal
// reply, EOF, clean exit and reap.
type GatewayService interface {
	callerterminal.Gateway
	InstallPolicy(context.Context, string, string) error
	Stop(context.Context) error
	Wait() error
}

type StartGateway func(context.Context, string, string, *credentials.Bundle) (GatewayService, error)

type RunProvider func(context.Context, string, string, *credentials.Bundle, *callerstate.Store) (*callerterminal.Authority, error)

// Coordinate validates the phase deadline before touching caller state. The
// initial phase creates one planned state in an empty root and advances it to
// terminal_bound through the injected Provider runner. Reconstruction accepts
// only an already complete initial state and must not mutate it. Both paths
// start the live Gateway, install the caller-owned tenant policy, stop and reap
// it, and prove the resulting state remains unchanged after Provider work.
// Initial also issues and revokes a grant from fresh terminal authority before
// stopping. A failed grant lifecycle cancels and reaps the service.
func Coordinate(parent context.Context, request callercontrol.Request, bundle *credentials.Bundle, start StartGateway, runProvider RunProvider) error {
	if parent == nil || bundle == nil || start == nil || runProvider == nil {
		return ErrGatewayLifecycle
	}
	now := time.Now()
	if request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.Sub(now) > MaxPreparationLifetime {
		return ErrPhaseDeadline
	}
	deadline := request.Deadline
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	if parent.Err() != nil {
		return context.Cause(parent)
	}
	if !deadline.After(now) {
		return ErrPhaseDeadline
	}
	phaseContext, cancel := context.WithDeadline(parent, deadline)
	defer cancel()

	var (
		store *callerstate.Store
		err   error
	)
	switch request.Phase {
	case "initial":
		store, err = callerstate.CreateInitial(request.CallerStateRoot)
	case "reconstruction":
		store, err = callerstate.OpenReconstruction(request.CallerStateRoot)
	default:
		return ErrPhaseState
	}
	if err != nil {
		return ErrPhaseState
	}
	storeClosed := false
	defer func() {
		if !storeClosed {
			_ = store.Close()
		}
	}()
	state := store.Snapshot()

	service, err := start(phaseContext, request.Phase, request.GatewayProbeEndpoint, bundle)
	if err != nil || service == nil {
		if service != nil {
			cancel()
			_ = service.Wait()
		}
		return preserveContextError(phaseContext, err)
	}
	cleanStop := false
	defer func() {
		if !cleanStop {
			cancel()
			_ = service.Wait()
		}
	}()
	if err := service.InstallPolicy(phaseContext, state.Plan.TenantAID, state.Plan.TenantBID); err != nil {
		return preserveContextError(phaseContext, err)
	}
	terminal, err := runProvider(phaseContext, request.Phase, request.ProviderOrigin, bundle, store)
	if err != nil {
		return preserveContextError(phaseContext, err)
	}
	if terminal != nil {
		defer terminal.Close()
	}
	if request.Phase == "initial" {
		current := store.Snapshot()
		if current.Stage != callerstate.StageTerminalBound || current.Provider == nil || current.Lifecycle == nil || current.Exec == nil || current.Terminal == nil || !reflect.DeepEqual(current.Plan, state.Plan) || store.ValidateUnchanged() != nil {
			return ErrPhaseState
		}
		if err := callerterminal.GrantAndRevoke(phaseContext, current, terminal, service); err != nil {
			return preserveContextError(phaseContext, err)
		}
	} else if terminal != nil {
		// Reconstruction has no freshly validated terminal authority yet.
		return ErrPhaseState
	}
	if err := service.Stop(phaseContext); err != nil {
		return preserveContextError(phaseContext, err)
	}
	cleanStop = true
	finalState := store.Snapshot()
	switch request.Phase {
	case "initial":
		if finalState.Stage != callerstate.StageTerminalBound || finalState.Provider == nil || finalState.Lifecycle == nil || finalState.Exec == nil || finalState.Terminal == nil || !reflect.DeepEqual(finalState.Plan, state.Plan) {
			return ErrPhaseState
		}
	case "reconstruction":
		if !reflect.DeepEqual(finalState, state) {
			return ErrPhaseState
		}
	}
	if err := store.ValidateUnchanged(); err != nil {
		return ErrPhaseState
	}
	if err := store.Close(); err != nil {
		return ErrPhaseState
	}
	storeClosed = true
	return nil
}

func preserveContextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrGatewayLifecycle
}
