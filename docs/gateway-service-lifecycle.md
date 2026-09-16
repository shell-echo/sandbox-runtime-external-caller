# Gateway service lifecycle and continuity v1

Status: e1.5e.4, checkpoint 4/13, complete as local process-supervision
evidence. This extends the caller-private
[`gateway-service-control.md`](gateway-service-control.md); it does not change
the Provider Contract or public qualification adapter protocol.

## Ownership and bounds

`gatewayprocess.ServiceRunner` starts the fixed sibling `caller-gateway` with
empty argv/environment and a fresh process group. The caller must supply one
context with an absolute future phase deadline no more than five minutes away.
The same deadline enters the closed private bootstrap; neither command line,
environment, endpoint query nor a hidden timer can extend it.

Startup has an additional five-second maximum. It includes process creation,
stdin bootstrap EOF, the two server/trust credential pipe writes, independent
child validation, exact endpoint bind and receipt of the sequence-zero
`listening_policy_unset` reply. Startup I/O carries deadlines and parent
cancellation closes every still-open writer. No readiness means no usable
service handle.

Each authorization operation is serialized, preserves its own context
cancellation/deadline and cannot outlive the phase. Canceling an in-flight
operation terminates the service because request/reply sequence completion is
then ambiguous; the caller cannot skip or replay that sequence safely.

Graceful stop is accepted only after the exact `stopped` reply, stdout EOF,
clean process exit, empty stderr and successful reap. Shutdown has a two-second
maximum. Cancellation first closes the caller's control/output ends so the
child can clean itself up; a separate-process-group kill is the bounded
fallback, followed by reap. Parent and child pipe ownership is explicit, and
the runner uses caller-owned stdout/stderr pipes instead of racing `Cmd.Wait`
against `StdoutPipe` reads.

## Parent-death and live-resource closure

The private service-control pipe is also the parent-liveness signal. Its writer
is held only by the Caller. Normal inheritance is close-on-exec except for the
child's explicitly remapped read end. If the Caller exits without running Go
defers or calling `Service.Stop`, the operating system closes that writer. EOF
is a terminal control error in the Gateway and triggers the same sequence:
cancel the service context, close the listener, cancel permits, close hijacked
tunnel endpoints, wait for handlers, destroy the parsed TLS identity and exit.

This is portable across the supported Darwin/Linux process boundary and does
not depend on Linux-only `PDEATHSIG`. The Gateway remains in its own group so a
Caller can kill/reap it without killing itself. If the Caller itself is gone,
the Gateway becomes an orphan only until it handles EOF and exits; the OS parent
then reaps it. A later independent qualification supervisor must observe the
full adapter/Caller/Gateway process tree and residual state; this local test is
not that evidence.

The Gateway's own absolute deadline independently closes the service even if
the liveness signal remains open. Both deadline and graceful-stop tests hold an
authorized CONNECT tunnel open, first prove a binary round trip, then require a
non-timeout close, an unreachable static listener and a gone/reaped child.

## Restart continuity

After the first successful readiness, one `ServiceRunner` retains only an
in-memory SHA-256 binding over a domain separator, canonical endpoint string,
exact server credential document bytes and exact server-trust bytes. This value
is never returned, logged, persisted or emitted as evidence. Restart uses fresh
pipes and a fresh child PID but is rejected before launch if any bound byte or
the endpoint changes. A failed pre-readiness start does not pin the binding,
and concurrent service instances from one runner are rejected.

Tests stop and restart an actual Gateway on the same endpoint, independently
hash the TLS leaf presented on both connections and require equality plus a
fresh PID. Changed endpoint and newly issued server/trust inputs are rejected
without launching a third child. This is a phase-local runtime invariant. A new
Caller process cannot inherit the in-memory binding; exact cross-phase custody
and reconstruction inputs remain an operator/supervisor obligation for the
independently observed run. No secret-derived digest is added to caller state or
public evidence.

## Local test boundary

Tests use mise Go, ephemeral loopback certificates and candidate test-only
executables. One adversarial helper announces syntactically valid readiness and
then ignores control to prove canceled operation and hard-kill/reap bounds. A
second Caller helper starts and authorizes the real service path, reports its
test-only PID/token, then deliberately uses `os.Exit` after the test opens a
tunnel. The resulting control-pipe EOF must close the tunnel, listener and
Gateway process. Neither helper is linked into the production commands.

e1.6a integrates this runner with caller phase state and immutable tenant
policy; e1.6b adds Provider capability/create reconciliation. e1.6c upgrades
the operational runner to private service v2 with a one-connection backend
socket. Provider credentials remain in the Caller; cancellation, revocation,
expiry, terminal EOF and stop close the bridged stream and process resources.
Candidate-owned loopback mTLS/WebSocket tests do not establish independent
runtime interoperability, external source/build provenance, independent
process observation, a 15+5 scenario result or qualification disposition.
