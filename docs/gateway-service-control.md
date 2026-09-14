# Private Gateway serving boundary v1

Status: e1.5e.3 service interface plus e1.5e.4 bounded lifecycle supervision.
This is a caller-private service interface,
not Provider wire API, harness invocation input, or qualification evidence.

`caller-gateway` still rejects arguments. It selects **only by an explicit
private protocol ID** between the existing v2 finite identity-validation
bootstrap and `sandbox-runtime-external-caller-private-gateway-service-v1`.
There is no credential sniffing, optional server secret, or listener fallback.
The adapter/caller's operational path still uses the finite bootstrap. The
long-lived runner is now implemented, but caller composition remains
checkpoints 5-7.

## Bootstrap, identities, and readiness

The serving request is one closed strict JSON object through stdin EOF, bounded
to 20 KiB, with exactly:

- `protocol_id`: the private serving ID above;
- `bootstrap`: the existing closed v2 Gateway request (phase, frozen HTTPS
  endpoint, and exactly the two server/trust credential descriptors);
- `control_descriptor`: a separately declared readable caller-owned pipe FD
  between 3 and 1024, distinct from both credential descriptors; and
- `deadline`: the caller's absolute RFC 3339 deadline, not a correlation value.

No tenant, runtime-session, handoff, bearer, or private key may occur in this
bootstrap. Public startup remains exactly eight credential channels; the child
receives only its remapped server and trust channels, not client private keys.
The separately declared service-control pipe is private caller IPC, not a ninth
harness credential channel. It is never forwarded from the harness.

The child independently validates its server identity and destroys the source
bundle. It retains the parsed TLS key until serving work stops. A service start
requires a future deadline at most five minutes away, clamped to the loaded
server/trust expiry. It binds exactly the frozen endpoint host/port (HTTPS's
default 443 when omitted), with no random-port retry, host rewrite, alternative
SAN, implicit certificate generation, or proxy. Supported paths are limited to
512 bytes, matching the Gateway handler.

Only after TLS configuration, bind and entry into the HTTP serving accept loop
does stdout emit a single-LF reply with sequence 0 and status
`listening_policy_unset`. This means **listening, not authorized, connected,
Provider-ready, or qualified**. It carries only the protocol ID, sequence,
phase, PID and status. Parent supervision must cross-check PID/phase and message
ordering. The current executable tests do so; the old finite runner must not be
used to consume serving replies.

TLS requires verified client chains, TLS 1.2 or newer and HTTP/1.1 ALPN. Until
caller policy is installed, every tunnel is denied. After installation, the
request must target the exact endpoint authority/path, with no query, and
satisfy the existing CONNECT/grant rules. HTTP header/idle timeouts are 2/5
seconds and the server configures a 16 KiB header limit. TLS/HTTP diagnostics are
discarded rather than written to stderr. Missing or untrusted client certificates
fail the TLS handshake; authenticated authorization failures return empty 403.

## Caller-owned authorization stream

The separate pipe contains single-LF, strict UTF-8 JSON command objects. Each
is at most 16 KiB, requires contiguous `sequence` from 1 through at most 256,
and includes `action`. Exactly these additional fields are allowed:

| Action | Required additional fields | Successful status |
| --- | --- | --- |
| `install_policy` | `tenant_a`, `tenant_b` | `policy_installed` |
| `issue_grant` | `actor`, `tenant_id`, `runtime_session_id`, `handoff_reference`, `expires_at` | `grant_issued` |
| `revoke` | `actor`, `token` | `revoked` |
| `stop` | none | `stopped` |

Actor values are exactly `controller_a` or `controller_b`; subjects come only
from the validated server credential pins. Policy installation succeeds once,
using two distinct valid caller-owned tenants. Failed installation leaves the
service policy-unset. Grants require installed policy, the matching tenant,
valid session/handoff and a future expiry no later than the service bound.
Existing one-use, five-minute and 64-entry grant limits still apply.

Replies are closed, at most 4 KiB including one LF, and carry `protocol_id`,
`sequence`, `phase`, `process_id`, `status`. Only `grant_issued` carries the
required `token`, a canonical 256-bit bearer. Semantic authorization rejection
returns `rejected` without changing the existing policy; malformed, unknown,
duplicate, missing, null, oversized, truncated or out-of-sequence control fails
the service. Exhausting the command bound without `stop` fails closed. `stop`
is terminal: buffered later commands are not executed, and the pipe is closed.

These commands come from caller business state, not the credential custodian,
adapter input, command line, environment, endpoint query or state-root seed.
Raw handoffs, bindings and returned bearer tokens remain private IPC: **do not
archive this stdout as evidence or forward it to public adapter output**. Fixed
status/error codes never echo input or include raw crypto/network diagnostics.
Managed-memory clearing does not prove erasure of JSON strings or TLS internals.

## Backend and lifetime boundaries

Authorization consumes a matching grant **before** calling `gateway.Resolver`.
The production executable currently uses `UnavailableResolver`: an otherwise
authorized request returns empty 502, never an echo, local shell or invented
Provider backend. A test-only subprocess injects a synthetic resolver through
the Go application composition boundary. There is no wire-selected backend,
backend URL, client key or test mode in the production command.

The service propagates cancellation to HTTP and tunnels, clamps live requests
to the verified client chain expiry, and closes listener/work before the
terminal `stopped` reply and parsed-key destruction. The command/output pipes
are explicitly made pollable on Darwin/Linux; blocked control reads can be
closed and output writes carry the absolute deadline. Unsupported platforms
fail closed. [`gateway-service-lifecycle.md`](gateway-service-lifecycle.md)
specifies and tests the e1.5e.4 parent-liveness pipe, bounded startup/shutdown/
reap, deadline and live-tunnel closure, exact endpoint/input continuity and
restart behavior. The new runner is not yet composed into the operational
external-caller.

## Local acceptance evidence

The actual built `caller-gateway` runs with empty argv/environment and exactly
two credential pipes plus declared control. Tests verify readiness, default
deny, authorized unavailable-backend 502, stop/EOF/clean exit, and no readiness
or stderr on invalid identity, endpoint collision or invalid lifetime.

A separate **test binary**, using the same application/service path and a
test-only injected resolver, verifies absent/untrusted certificates, unknown
same-CA subject, cross-controller, cross-tenant grant issuance, cross-controller
revocation, wrong method/path/query, unknown/replayed token, one successful
opaque binary round trip and revocation. A test-only observation pipe records
exactly one resolver invocation across all negative and positive probes. The
production binary has no such pipe or synthetic resolver.

Closed codec tests and malformed/oversized/out-of-sequence child-control tests
cover the private boundary. This is local process/component evidence only:
no real Provider backend, Docker runtime, independently supervised observation,
15+5 qualification scenario or qualification disposition is established.
