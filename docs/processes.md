# Candidate process artifacts

This checkpoint establishes three separately buildable candidate-owned command
artifacts and one bounded local bootstrap composition:

| Command | Current behavior |
| --- | --- |
| `cmd/qualification-adapter` | Emits startup first, validates one invocation, drains the exact harness credential pipes, executes all 15 initial cases or all 5 reconstruction cases, and forwards each validated result. Both local paths finish `completed`. The no-Caller component path remains all-`not_executed`. |
| `cmd/external-caller` | Accepts private v20 control and eight credential pipes, validates identities, executes all 15 locked initial cases or all 5 reconstruction cases, and opens initial state only from an empty root or reconstruction only from complete retained state. It requires private EOF and cleanly stops any retained reconstruction Gateway before exit. |
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
the locked limits. For the first initial case, it emits the public
`scenario_started` before starting the fixed sibling `external-caller`
artifact and authorizing capability discovery. After validating and publishing
that result, it emits the second `scenario_started` before sending the
protected-create command to the same child, then does the same for replay
semantics, lifecycle completion/status, exec result/usage evidence,
stale-fencing rejection, exec cancellation, terminal session/opaque handoff,
the authorized Gateway byte round-trip, wrong-caller/cross-tenant Gateway
rejection, live grant expiry, active revocation, artifact staging/evidence, and
Provider cross-tenant artifact rejection, and mTLS/JWS caller-binding rejection.
All 15 results are `completed`; terminal completion is therefore `completed`.
For reconstruction, the adapter starts the fresh Caller for locked capability
discovery, validates that completed result, then authorizes durable lifecycle
reconciliation, retained exec/usage/artifact evidence reads, retained terminal
handoff validation and the bounded Gateway reconnect on the same Caller and
Gateway. It validates all five completed results; the nil-Caller
component path still reports every case `not_executed`. A completed adapter
record is candidate progress, not a passing qualification scenario.

An executable-level test builds and starts the actual adapter with empty argv,
an empty environment, and an empty working directory. It withholds invocation
and credential bytes until it has received and validated startup, then verifies
the terminal record and clean process exit. This is local process behavior; an
independent process supervisor must repeat and record the boundary during a
qualification run.

## Private adapter-to-caller control

The current command uses the candidate-private protocol
`sandbox-runtime-external-caller-private-scenario-v20@20.0.0`. It accepts either
the reconstruction capability request followed by durable-lifecycle,
retained-evidence, durable-handoff and same-shell-reconnect commands or exactly the initial capability
request followed by protected-create, replay-semantics,
lifecycle-completion, exec-result/usage, stale-fencing, exec-cancellation,
terminal-session, Gateway-round-trip, Gateway-authority-rejection, and
Gateway-grant-expiry, Gateway-revocation, artifact-staging/evidence, and
Provider cross-tenant artifact-rejection and mTLS caller-binding-rejection commands,
with one strict LF-framed
record per authorization and result. Both directions reject
unknown and duplicate members, invalid JSON, extra cases, incorrect order and
oversized input. The first request contains only:

- invocation, phase and authorized case identity;
- the Provider origin and static Gateway probe endpoint;
- the caller state root;
- the first case's absolute 120-second deadline; and
- descriptors for the eight newly inherited credential pipes.

The request does not carry expected Contract revision, profile digest, scenario
assertions or observation IDs; those are embedded candidate authority and
cannot be injected by the harness. It also omits every Provider correlation and
all credential payloads. Secrets are copied only into new anonymous pipes and
destroyed independently in both processes.

Each later command carries only the original invocation/phase identity, one
allowlisted case ID and its own clipped 120-second deadline. It contains no
credentials, request body, Admission material or Provider correlation. Each
result contains public result data plus the child PID and
exact request binding. The adapter-side runner cross-checks invocation, phase,
case and PID, deep-copies each result, and revalidates its public shape.

The runner resolves `external-caller` by fixed sibling name from the adapter's
resolved executable directory. It supplies zero arguments and an empty
environment, inherits the supervisor-owned working directory, assigns a new
process group, concurrently drains bounded stderr and bounded per-result stdout,
and gives the fifteen-case process at most 1800 seconds while clipping each command
to its locked 120-second limit. After the fifteenth result, the runner closes
private stdin and requires stdout EOF,
empty stderr, clean exit and reap.
The reconstruction sequence is the first request plus durable-lifecycle,
retained-evidence, durable-handoff and same-shell-reconnect continuations. After the fifth result the runner closes private stdin and
requires Gateway shutdown, stdout EOF, empty stderr, clean exit and reap within
the bounded process budget.
Malformed results, extra output, invocation/phase/case/PID mismatch, timeout,
or nonzero exit fails the caller boundary.

Completion and abort now drain bounded stdout concurrently with process wait,
so a descendant that inherits the output pipe cannot block supervision before
the reap timer starts. Graceful completion permits two seconds for natural exit;
both paths enforce a five-second total reap bound, terminate the entire private
process group after the group leader exits, and classify an unconfirmed reap as
cleanup uncertainty. A successfully forced and confirmed abort is clean local
cleanup, while an unconfirmed cleanup maps to public `internal_failure` and a
nonzero adapter exit. Caller start and ordinary scenario errors map only to
`caller_start_failed` and `scenario_execution_failed`; private paths, PIDs,
stderr and error text are never copied into public records.

Local transcript tests require the exact 15-case initial and five-case
reconstruction record sequences, one terminal record last, final LF, the
locked per-record and aggregate byte limits, and absence of retained run,
tenant, operation, attempt, idempotency, sandbox, session and handoff values.
The qualification supervisor remains the authority that observes terminal,
then stdout EOF, then a clean reaped exit and constructs the closed sanitized
transcript projection. Candidate tests do not substitute for that observation.

Candidate shutdown covers the adapter-owned Caller and Caller-owned Gateway
processes and live local connections. It deliberately preserves the single
private caller-state file needed by reconstruction and does not issue Provider
resource teardown. The locked operator owns disposable run-namespace teardown,
the pre-run baseline, and three stable zero-resource inventory samples; missing
or failed evidence there remains `incomplete` or `unknown`.

The older private v4 whole-phase coordinator remains exercised as historical
e1.6c composition code, but it is not the current command path and does not
emit public scenario results.

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
`scenario_execution_failed` code after the first public scenario start and
before any scenario result. Tests use ephemeral
local certificates and assert that secret markers are absent from output.

## Development and candidate release identities

Ordinary development builds embed `release-id: local-development` for both
Caller and Adapter source identities. These immutable bytes remain
self-asserted development labels and are not source hosting, third-party build
or release provenance.

The e1.8a release builder instead creates a deterministic `source.tar`, derives
one 64-hex `source-revision` from its raw SHA-256, and embeds it into the Caller,
Adapter and Gateway release variables with an empty Go build ID. It extracts
the archive twice, builds all three command artifacts in distinct roots, and
publishes only byte-identical results. The canonical manifest records the
archive, toolchain, exact command/environment arrays and raw executable
digests. See [`release-artifacts.md`](release-artifacts.md).

Local binaries can be built without Docker:

```bash
mise exec -- go build -trimpath -buildvcs=false -o ./bin/qualification-adapter ./cmd/qualification-adapter
mise exec -- go build -trimpath -buildvcs=false -o ./bin/external-caller ./cmd/external-caller
mise exec -- go build -trimpath -buildvcs=false -o ./bin/caller-gateway ./cmd/caller-gateway
```

The repository ignores local outputs under `dist/`. A verified local bundle is
candidate reproducibility evidence only. Its manifest explicitly records that
independent source hosting, build attestation and qualification process
observation are absent; merely producing matching local bytes does not satisfy
the locked artifact-observation or external-ownership prerequisites.

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
e1.6c adds the exec/result/usage/session/handoff flow and the credential-owning
Caller-to-Gateway terminal byte bridge. The private protocol remains separate
from Provider wire API. e1.7a executes all 15 locked initial cases. e1.7b now
executes all five reconstruction cases, including retained handoff validation
and the bounded reconstructed-Gateway byte connection. This remains local
candidate composition; independent observer proof is still pending.
