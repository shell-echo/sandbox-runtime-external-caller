# Candidate process artifacts

This checkpoint establishes three separately buildable candidate-owned command
artifacts and one bounded local bootstrap composition:

| Command | Current behavior |
| --- | --- |
| `cmd/qualification-adapter` | Operational protocol skeleton: emits startup first, validates one invocation, drains the exact harness credential pipes, starts the sibling external caller, then reports every phase case `not_executed` and finishes `stopped`. |
| `cmd/external-caller` | Accepts private v4 control and eight credential pipes, validates identities, opens strict phase state, performs protected Provider capability/create reconciliation, supervises a live sibling Gateway through policy install and clean stop/reap, then returns one bounded no-scenario-result completion. |
| `cmd/caller-gateway` | Accepts either the existing private v2 finite validation bootstrap or the separately identified live-service bootstrap, both with only two server/trust credential pipes. The live path binds mTLS CONNECT and processes private caller authorization; its production backend remains fail-closed. |

The e1.5e.3 serving protocol, separate control FD, readiness, private bearer
handling and process-test evidence are defined in
[`gateway-service-control.md`](gateway-service-control.md). The e1.5e.4
[`ServiceRunner`](gateway-service-lifecycle.md) provides bounded long-lived
supervision, parent-liveness EOF and restart continuity; e1.6a now composes it
with caller-owned phase state.

All three commands reject non-empty argument lists. The adapter's empty argv is
a locked protocol rule. Applying the same restriction to the caller and
Gateway prevents correlation or secret material from becoming an accidental
command-line convention.

## Adapter startup boundary

The adapter creates a phase-unbound state machine and writes the complete
`startup_identity` record before its first read from standard input. It does not
learn the phase from argv, environment, or working directory. Only the strict
invocation subsequently binds the machine to `initial` or `reconstruction`.

After `invocation_accepted`, the adapter opens only the eight descriptors that
exactly match its startup requirements and reads each pipe through EOF under
the locked limits. It then starts the fixed sibling `external-caller` artifact,
forwards each credential through a new dedicated inherited pipe, and destroys
its own bundle after the child returns or fails. Each locked case still receives
an empty `not_executed` result with `prerequisite_not_satisfied`; the terminal
completion is `stopped`. This is an honest protocol result, not a passing
scenario or qualification outcome.

An executable-level test builds and starts the actual adapter with empty argv,
an empty environment, and an empty working directory. It withholds invocation
and credential bytes until it has received and validated startup, then verifies
the terminal record and clean process exit. This is local process behavior; an
independent process supervisor must repeat and record the boundary during a
qualification run.

## Private adapter-to-caller control

The candidate-private protocol `sandbox-runtime-external-caller-private-control-v4`
uses one strict JSON request through standard-input EOF and one strict JSON-line
result through stdout EOF. Both directions reject unknown and duplicate members,
invalid JSON, trailing documents, and oversized input. The request contains
only:

- the phase;
- the Provider origin and static Gateway probe endpoint;
- the caller state root; and
- the adapter-side Caller supervisor's absolute deadline; and
- descriptors for the eight newly inherited credential pipes.

It omits invocation/profile identity, every sandbox/operation/attempt/
idempotency/fencing/runtime-session/handoff correlation, and all credential
payloads. Secrets are copied only from the adapter-owned bundle into the new
anonymous pipes and are destroyed independently in both processes.

The caller result states
`provider_lifecycle_and_gateway_coordination_complete_no_scenario_results` and
includes its own PID. It is emitted only after strict state opening, Provider
capability/create reconciliation, live Gateway readiness and policy
installation, graceful Gateway stop, stdout EOF, clean exit, unchanged-state
validation and reap. The adapter-side runner cross-checks that PID with the
process it actually started, but neither value is forwarded to the public
adapter protocol or treated as qualification evidence.

The runner resolves `external-caller` by fixed sibling name from the adapter's
resolved executable directory. It supplies zero arguments and an empty
environment, inherits the supervisor-owned working directory, assigns a new
process group, concurrently drains bounded stdout/stderr, and enforces a
ten-second maximum with group kill and bounded reap. That exact absolute bound
is copied into private control and becomes the Gateway phase deadline; it is
not a public protocol timestamp or qualification deadline claim. Non-empty
stderr, malformed results, PID/phase mismatch, timeout, or nonzero exit fails
the caller boundary.

## Private caller-to-Gateway bootstrap

The second candidate-private protocol
`sandbox-runtime-external-caller-private-gateway-control-v2` uses the same
strict one-request/one-result framing. Its request contains only the phase,
static Gateway probe endpoint, and descriptors for newly remapped
`gateway-server` and `gateway-trust` pipes, in that order. It
omits Provider location and caller state, invocation/profile identity, all seven
forbidden correlation classes, and credential payloads.

The caller resolves `caller-gateway` by fixed sibling name from its own resolved
executable directory. Caller validation first checks server/client identities
and key separation. It forwards only the two server/trust payloads from its live
bundle through new anonymous pipes. The Gateway independently validates
control, drains the exact pipe set, validates the server key/certificates, clears
its parsed key and bundle, and returns a
PID/phase-bound result. Its supervisor applies the same empty argv/environment,
bounded stdout/stderr, five-second lifetime, process-group kill, and bounded
reap rules as the adapter-to-caller boundary.

The result status is `server_identity_validated_no_listener`. This bootstrap
validates credentials without binding a socket. Old v1 control identities,
three-client-channel Gateway input and false `listening`/`passed` results are
rejected. Actual command tests exercise both valid credentials and malformed
server credentials, with failure mapped to the existing public
`caller_start_failed` code before any scenario result. Tests use ephemeral
local certificates and assert that secret markers are absent from output.

## Development identities and builds

The adapter currently embeds `release-id: local-development` for both caller
and adapter source identities. These are immutable bytes within that binary but
remain self-asserted development labels. They are not source hosting,
third-party build, or release provenance. Release builds may replace the
package variables with validated immutable values at link time, but the future
artifact pipeline must record the exact command and resulting raw executable
digests independently.

Local binaries can be built without Docker:

```bash
mise exec -- go build -trimpath -buildvcs=false -o ./bin/qualification-adapter ./cmd/qualification-adapter
mise exec -- go build -trimpath -buildvcs=false -o ./bin/external-caller ./cmd/external-caller
mise exec -- go build -trimpath -buildvcs=false -o ./bin/caller-gateway ./cmd/caller-gateway
```

The repository does not retain local build outputs. Merely compiling these
commands does not establish their artifact identities in qualification
evidence.

## Defined serving boundary and next implementation

[`gateway-server-identity.md`](gateway-server-identity.md) defines the explicit
eighth credential channel, custody, server/client identity separation, private
delivery and reconstruction policy. The earlier "locked seven-channel public
startup contract" wording was incorrect; the public maximum is eight and the
candidate now explicitly declares eight.

e1.5e.2 activates the declaration and loader and replaces the former client-key
Gateway input with the versioned two-channel server-identity/trust bootstrap.
e1.5e.3 implements the separately selected listener/service boundary,
e1.5e.4 establishes its long-lived supervision and restart behavior, e1.6a
composes it with empty-initial/complete-reconstruction caller state, and e1.6b
adds Provider capability/create reconciliation and durable lifecycle binding.
The private protocol remains separate from Provider wire API. The real exec and
terminal backend remains e1.6c.
