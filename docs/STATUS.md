# Status

Current checkpoint: **e1.6b Provider lifecycle composition complete**. The
operational external caller now combines strict phase state, protected Provider
capability/create reconciliation and the live Gateway lifecycle. Of the 13
checkpoints in [`PLAN.md`](PLAN.md), 6 are complete and **7 remain**; e1.6c is next. Sections
below record evidence at each checkpoint, not simultaneous current claims.

## e1.1 external-caller candidate foundation

Status: **local candidate only**.

The repository is a separate, uncommitted Git working tree. Its authority lock
pins the current Provider Contract, qualification profile, adapter protocol,
transcript projection, report schema, and validator semantics. The verifier
checks the exact lock and all named upstream public-file bytes. Tests reject a
direct import of any `github.com/shell-echo/sandbox-runtime` package.

Not established: an external owner, independent source hosting, a hosted build
or attestation, caller/adapter/Gateway artifacts, behavior, interoperability,
15+5 execution, teardown, evidence archive, or qualification outcome.

The next foundation slice is recorded below.

## e1.2 startup identity and invocation codec

Status: **complete as a local clean-room component**.

`internal/protocol` constructs and validates the exact startup identity,
including the locked Contract, profile, and adapter-protocol authorities. It
writes one bounded JSON record with a single LF. Its one-shot invocation decoder
reads all bytes through required EOF, applies the locked 32 KiB limit and error
precedence, rejects invalid UTF-8, invalid surrogate escapes, duplicate JSON
members, multiple documents, unknown or missing fields, wrong message
direction, and schema mismatches. It also validates canonical HTTPS/WSS
locations, absolute clean POSIX paths, source identities, channel limits,
unique channel/file-descriptor identities, total credential bounds, and exact
ordered requirement/descriptor matching.

Race/shuffle tests, vet, authority verification, dependency-boundary checks,
and Darwin runtime plus Linux/Windows cross-compilation pass with mise Go
1.26.5. No process was launched and no credential, Provider/Gateway request,
Docker daemon, release artifact, provenance claim, or qualification result was
produced.

Next bounded slice: implement the remaining adapter-to-harness output codecs
and the single-phase protocol state machine. Process launch, credentials, and
Provider/Gateway behavior remain later slices.

## e1.3 adapter output codec and single-phase state machine

Status: **complete as a local clean-room component**.

`internal/protocol` now models every locked adapter-to-harness output record
and writes only complete, schema-valid JSON records with one LF. The invocation
decoder recognizes a wrong-direction message only after the claimed output
record satisfies its complete closed shape, including nested interactions,
outcomes, and assertions.

The phase machine emits startup before consuming invocation input, derives the
locked 15-case initial and 5-case reconstruction order from locally pinned
authority, binds every post-acceptance record to the accepted invocation and
phase, enforces contiguous sequences and the completed/not-executed branches,
and derives `invocation_finished.completion`. A normal completion requires one
terminal record, stdout EOF, then a clean process exit; early EOF,
post-terminal bytes, non-clean exit, invalid order, or output failure moves the
machine to its absorbing failed state. The maximum all-completed initial path
is exactly 33 records and ends at sequence 32.

This is producer/state-machine component evidence only. It does not prove that
a process was supervised, credentials were isolated, Provider or Gateway
behavior occurred, observations are true, or any scenario or qualification
passed.

Next bounded slice: implement the Provider HTTP caller foundation, request
signing, and lifecycle request/response handling. Gateway execution and the
full qualification scenarios remain later slices.

## e1.4 Provider HTTP, protected admission, and lifecycle foundation

Status: **complete as locally simulated component evidence**.

`internal/jcs` canonicalizes strict JSON according to RFC 8785, including
UTF-16 object-key ordering, ECMAScript number serialization, and the required
string escaping. It rejects duplicate members, invalid Unicode, multiple JSON
values, and non-finite numbers. Tests bind it to the locked public Admission
Context and protected-read descriptor digest vectors.

`internal/provider` now owns local Provider wire DTOs, validates create
requests, calculates the mutation digest with `request_digest` excluded,
calculates full-document read-descriptor digests, constructs and encodes the
closed Admission Context, and signs closed compact JWS headers and claims with
Ed25519/EdDSA. Cross-binding covers caller subject, Provider revision and
audience, tenant/work order, operation/attempt/sandbox/fencing identities,
policy and deadlines, request Contract/digest profile/digest, and the exact
HTTP method/path. Token lifetime is bounded to 300 seconds.

The redirect-free HTTP client requires an explicitly injected transport and
implements capability discovery, sandbox creation, sandbox-status reads, and
operation reads. It enforces canonical HTTPS origins, operation-specific
success/error statuses, bounded bodies, JSON media types, strict closed
responses, Retry-After integers, admission expiry, and response correlation.
Tests use only in-memory RoundTrippers and verify the compact JWS signature;
no socket or Provider request is made.

The transport injection point does not prove mTLS configuration or caller
identity. There is still no credential-channel reader, runnable adapter/caller,
durable state, Gateway, external release/provenance evidence, scenario run, or
qualification outcome.

The former e1.5 description combined several independently reviewable security
boundaries. It is split into e1.5a through e1.5d so each checkpoint can be
validated and approved separately.

## e1.5a inherited credential channels and Provider mTLS

Status: **complete as a local component checkpoint**.

`internal/credentials` declares the candidate's seven ordered Provider/Gateway
credential requirements. Its one-shot reader first requires an exact startup
requirement/descriptor match, accepts only pipe file descriptors, reads each
payload through EOF with the locked per-channel and total limits, closes each
descriptor, and clears bundle-owned bytes on failure or destruction. Actor
selection has no fallback across credential channels.

The candidate-private Provider credential format is closed and contains no
qualification correlation fields. The loader binds the declared controller
subject to a currently valid, non-CA client certificate with exactly one
absolute URI SAN and client-auth usage. Admitted actors require an unpadded
Ed25519 Admission key; the same-CA unadmitted actor must not have one. Provider
trust accepts certificate PEM blocks only. The resulting no-proxy TLS
1.2-or-newer transport is injected into the e1.4 Provider client and uses the
origin hostname for server verification.

Race/shuffle tests, vet, authority verification, dependency-boundary checks,
and cross-compilation are required before this checkpoint is accepted. Unit
tests use OS pipes and locally generated certificates only; they do not connect
to a Provider, Gateway, Docker daemon, or remote service.

The reader can verify a pipe file type but cannot prove that the supervisor
created an anonymous pipe or delivered bytes only after startup. The future
process-supervisor run must supply that evidence. Managed-runtime memory zeroing
is best effort, and process exit remains the hard secret-lifetime boundary.

Next bounded checkpoint: e1.5b private durable correlation state, including
empty-initial-root enforcement, atomic private persistence, and reconstruction
reload without harness-supplied correlations.

## e1.5b caller-owned durable correlation state

Status: **complete as a local filesystem/state-machine checkpoint**.

`internal/callerstate` accepts only an absolute, clean, non-root path whose
components are not symbolic links and whose final object remains the same
exactly `0700` directory across open. Initial creation requires an empty root.
The caller accepts no correlation input: it generates distinct persisted plan
identities with `crypto/rand`, then writes the locked Contract/profile identity
and plan as revision one.

The state advances only through `planned`, `capabilities_bound`,
`lifecycle_bound`, `exec_bound`, `terminal_bound`, and `initial_complete`.
Every retained operation must use the caller-generated operation, attempt, and
idempotency plan. Fencing values and retained evidence digests are bounded, and
the handoff-reference digest is calculated from the stored opaque reference.
Out-of-order and concurrent duplicate transitions fail closed.

Each revision is bounded canonical RFC 8785 JSON in the sole
`correlation-state-v1.json` file. A new `0600` file is synced, atomically
renamed, and followed by a directory sync. Updates first reread the old revision
and reject external changes. Reconstruction accepts only a complete state with
stable regular-file identity, exact permissions and fields, and no additional
root entry.

Race/shuffle tests cover successful restart, deep-copy isolation, concurrent
writers, partial state, non-private roots/files, root and path-component
symlinks, non-empty initial roots, extra reconstruction files, state symlinks,
noncanonical bytes, unknown correlation members, and out-of-band changes. The
tests use temporary local directories only and require no Docker daemon.

This proves local fail-closed behavior, not harness non-observation, same-root
continuity across supervised processes, external provenance, or qualification.
The state file is permission-isolated but not encrypted, and the raw opaque
handoff is deliberately private caller state rather than evidence.

Next bounded checkpoint: e1.5c implement the caller-owned terminal Gateway,
including mTLS actor binding, tenant-scoped grants, byte forwarding, expiry,
revocation, and restart reconstruction from caller state.

## e1.5c caller-owned terminal Gateway

Status: **complete as a local mTLS loopback component checkpoint**.

`internal/credentials` now parses a separate closed Gateway credential document
for exactly `controller_a` or `controller_b`, binds its declared subject to one
valid client-auth URI SAN, accepts certificate-only trust, and constructs an
HTTPS/TLS-1.2-or-newer configuration for the exact endpoint hostname and
HTTP/1.1 ALPN. It rejects unknown or duplicate fields, actor fallback, query
correlation, and the unimplemented WSS option.

`internal/gateway` owns an immutable two-controller/two-tenant policy. It issues
bounded, one-connection, five-minute-or-shorter bearer grants bound to the exact
controller, tenant, runtime session, and opaque handoff reference, retaining
only a SHA-256 token key. Its private HTTP/1.1 CONNECT handler authenticates
mTLS and authorizes the grant before invoking the backend resolver, then
forwards opaque bytes in both directions. Expiry closes both transports;
authorized revocation waits for permit closure, while the other controller
cannot revoke or connect with the grant.

Race/shuffle tests use locally generated certificates and a loopback TLS server
to verify authorized byte round trips, missing-credential and cross-tenant
rejection before backend resolution, expiry, revocation, and construction of a
new Gateway from a reopened complete caller-state store. A stateful synthetic
resolver confirms that the reloaded opaque reference selects the same retained
terminal state.

This does not establish an actual Provider terminal, a separately supervised
Gateway process, harness state-root continuity, a real observer challenge or
byte count, external provenance, or any profile scenario/result. The private
Gateway protocol is not part of the Provider Contract.

Next bounded checkpoint: e1.5d add the three runnable artifacts and process
composition so startup ordering, inherited credential delivery, caller-state
continuity, secret lifetime, and separate caller/adapter/Gateway process
boundaries can be tested without claiming qualification.

## e1.5d.1 executable entrypoints and startup boundary

Status: **complete as a local fail-closed process skeleton**.

The repository now builds three distinct command artifacts. The qualification
adapter is phase-unbound at startup, so it emits its locked startup identity
before reading standard input and learns `initial` or `reconstruction` only from
the validated invocation. It accepts the invocation, drains and destroys the
exact seven inherited credential pipes, reports every case `not_executed` with
`prerequisite_not_satisfied`, emits `stopped`, and exits cleanly. It never emits
`scenario_started` or claims a completed interaction.

An executable-level test builds and launches the actual adapter with empty
argv, empty environment, and an empty working directory. The test withholds all
invocation and credential bytes until startup has been received and validated.
The standalone external-caller and caller-Gateway paths are intentionally
non-operational: with empty argv they perform no stream I/O and exit `69`; any
argument causes exit `64`. This keeps correlation and secrets out of an
unreviewed bootstrap convention.

The embedded `local-development` release IDs are self-asserted labels only.
Local executable bytes and their temporary SHA-256 values are not retained as
qualification artifacts or provenance. No Provider/Gateway request, external
caller behavior, scenario execution, process-supervisor evidence, or
qualification result is claimed.

Next bounded checkpoint: e1.5d.2 define the closed private adapter-to-caller
control channel, make the external-caller command operational behind it, and
verify process separation and bounded shutdown without yet composing the
Gateway server process.

## e1.5d.2 external-caller private process boundary

Status: **complete as a local two-process bootstrap checkpoint**.

`internal/callercontrol` defines one closed, bounded private request and result.
The request carries only phase, locked-shape locations, and remapped credential
descriptors. It excludes the invocation ID and profile path, all seven forbidden
correlation classes, and credential bytes. The result carries only readiness,
phase, and a child-reported PID; the adapter runner binds the latter to the
actual process it started and does not expose it through public adapter output.

`internal/callerprocess` locates a fixed sibling external-caller executable,
rejects a symlink or non-executable target, supplies empty argv/environment,
creates seven new inherited credential pipes, concurrently drains bounded
stdout and stderr, and places the child in a new process group. Its ten-second
outer limit leaves room for the nested Gateway's five-second limit, then closes
parent I/O, kills the group, and bounds reap. Tests verify a PID distinct from
the test process, successful clean reap, symlink rejection, and timeout
kill/reap.

The external-caller command independently validates the private control request,
reads the exact pipe set through EOF, destroys its own credential bundle, emits
one readiness result, and exits. The real adapter executable test now builds the
caller beside it, withholds invocation and credential delivery until startup,
and then exercises both processes. Public output remains the honest
all-`not_executed`/`stopped` path because no Provider scenario runs.

These are local process mechanics, not proof of external ownership, executable
provenance, harness behavior, Provider/Gateway interoperability, or a scenario
or qualification result. The caller currently consumes but does not parse or
use credentials, open caller state, or perform Provider requests.

## e1.5d.3 caller-Gateway private bootstrap boundary

Status: **complete as a local no-listener three-process checkpoint**.

`internal/gatewaycontrol` defines one closed, bounded private request and result.
The request contains only phase, the static Gateway endpoint, and three remapped
Gateway credential descriptors. It excludes Provider and caller-state
locations, invocation/profile identity, all seven forbidden correlation
classes, and credential bytes. The result carries phase, PID, and the explicit
status `control_and_credentials_consumed_no_listener`.

`internal/gatewayprocess` resolves the fixed sibling `caller-gateway`, supplies
empty argv/environment, forwards only the two Gateway controller credentials
and Gateway trust through new inherited pipes, bounds both output streams, and
enforces process-group termination and bounded reap. The external caller waits
for this child and emits no caller readiness if Gateway bootstrap fails. The
adapter executable test builds all three artifacts and exercises their nested
process boundaries before emitting the unchanged all-`not_executed`/`stopped`
public transcript.

This checkpoint intentionally does not start a network listener. Its seven
candidate channels contain client credentials and trust but no Gateway
server certificate/private key. An undeclared channel, key material on control
JSON/argv/environment, or reuse of a client-auth identity is unacceptable.
e1.5e.1 below corrects the earlier assumption that the public protocol itself
limits this candidate to seven channels. There is
still no Provider request, caller-state lifecycle execution, actual terminal,
scenario result, release/provenance evidence, or qualification outcome.

## e1.5e.1 Gateway server identity supply standard

Status: **complete as a definition and declaration/control test checkpoint**.

The locked public schema permits `gateway_credentials` with a null actor and
up to eight channels. [`gateway-server-identity.md`](gateway-server-identity.md)
therefore selects a declared `gateway-server` eighth channel, with a closed
candidate-private secret document specified for implementation in e1.5e.2.
The existing public authority lock and active seven-channel declaration are
unchanged. Seven was an implementation choice, not a public protocol limit.

The standard assigns caller-owned identity policy and operator credential
custody, preserves static preflight-before-acquisition and startup-before-input
ordering, specifies server/client certificate and key separation, and limits
the future Gateway child to its own server identity plus public server trust.
Reconstruction reuses privately retained credential bytes through fresh pipes.
Hot rotation and disk-cache recovery are excluded from v1. The standard also
records the separate long-lived parent-death/connection/reap obligations that
the existing short bootstrap tests do not establish.

New tests demonstrate that the proposed declaration encodes and binds for both
phases under the existing public codec. They reject a ninth channel, invented
role/actor, duplicate channel/FD, changed descriptor projection, and secrets or
forbidden correlation fields inserted into current control documents. Existing
seven-channel caller and three-channel Gateway bootstrap validators still
reject the proposed extra channel before any descriptor is opened. A client
credential test rejects a nested server-identity payload. All marker data are
synthetic; this slice implements no server secret decoder or certificate
loader and makes no key-erasure or live-listener claim.

Validation passed locally with mise Go 1.26.5 on Darwin/arm64: the focused
declaration/control tests, full `go test -race -shuffle=on -count=1 ./...`,
`go vet ./...`, authority-file verification and whitespace checks on all edited
files (including untracked files). Certificate, serving-process, restart and
qualification obligations are identified separately in the standard's
acceptance matrix.

Next: **e1.5e.2**, checkpoint 2/13, implement the declared server credential
codec, certificate validation and isolated pipe forwarding. **12 remain**.

## e1.5e.2 Gateway server credentials and isolated forwarding

Status: **complete as a local identity-validation/process checkpoint**.

The active startup declaration has eight channels, with the reviewed
`gateway-server` requirement last. Provider and public adapter protocol
authorities remain unchanged. Both private control protocols advance to v2;
the Gateway accepts only server credentials and public server trust through two
new pipes, rejecting the former controller-key channel set and old v1 identity.

`internal/credentials/gateway_server.go` implements bounded closed JSON,
strict PEM framing with bounded distinct certificate lists, PKCS#8 Ed25519
server keys, exact DNS/IP SAN and server-only EKU, explicit CA trust/chain
verification and validity checks. Caller validation binds the two Gateway
controller subjects and chains to supplied client roots and rejects Gateway
key reuse with one another, Provider TLS keys or Admission signing keys. No
Provider client is constructed or request signed by this identity check.

The Gateway child independently validates server identity, clears its parsed
key and credential bundle, and emits only
`server_identity_validated_no_listener`. The caller's bounded result is
`gateway_credentials_validated_no_listener`. Invalid server material fails
before scenarios and maps to the existing public `caller_start_failed` code.
All errors are fixed messages; raw parsing/crypto details and secret material
remain out of output. Memory clearing is best effort, not a secure-erasure claim.

Tests generate ephemeral local identities for valid three-process startup and
malformed-identity rejection. Negative tests cover closed/oversized/truncated
JSON, PEM skipping/duplicates/junk, wrong/extra SANs, ambiguous EKUs, key and
trust substitution, expired identities, subject substitution and key reuse.
An actual Gateway child succeeds using only its two server/trust channels even
when all client material in its parent's bundle is invalid; a blocked large
server-secret write is bounded by timeout, kill and reap. Test-helper imports
are forbidden in runtime source.

The loader exports the server/trust expiry bound for future serving code; it
does not enforce a live tunnel lifetime. This step establishes no listener,
Provider interoperability, cross-phase secret-custody evidence, external
provenance or qualification result. Those stay in their named checkpoints.

Validation passed with mise Go 1.26.5 on Darwin/arm64: focused identity/control
and executable-process tests, full `go test -race -shuffle=on -count=1 ./...`,
`go vet ./...`, the authority verifier and whitespace checks including all
edited untracked files. Linux/amd64 and Windows/amd64 `go build ./...` passed;
these are compilation checks, not runtime tests on those platforms. Command
dependency inspection confirms that no credential fixture generator is linked
into any of the three executables.

Next: **e1.5e.3**, checkpoint 3/13, bind the actual mTLS CONNECT listener and
validate process-level authorization and byte forwarding. **11 remain**.

## e1.5e.3 live Gateway service boundary

Status: **complete as local executable/component evidence**, checkpoint 3/13.

`caller-gateway` now exposes the separately identified serving bootstrap in
[`gateway-service-control.md`](gateway-service-control.md). It independently
loads the same isolated server/trust inputs, binds the frozen HTTPS endpoint,
starts the HTTP/1.1 mTLS serving loop and reports `listening_policy_unset` with
PID/phase binding. A separately declared caller-private command pipe supports
one immutable tenant-policy installation, grant issuance, revocation and stop.
Control frames are closed, bounded, contiguous and fail closed on malformed
input. Only the private grant reply contains a bearer; this stream is not
public adapter output or evidence and must not be archived as such.

The actual command's backend is explicitly unavailable: authorized CONNECT
returns 502. There is no production echo fallback or wire-selected backend.
Actual artifact tests cover readiness, policy-unset rejection, authorization,
unavailable-backend behavior, stop/EOF/clean exit, invalid server identity,
endpoint collision and invalid lifetime, with no raw stderr output. A separate
test binary injects only a synthetic backend into the same application/service
path. Its extra test-only observer counts exactly one resolver call across
certificate/subject/controller/policy/grant/path/method/ALPN rejection probes,
one opaque binary round trip, replay rejection and successful revocation.

Initial process testing caught that Go's inherited blocking stdio was not
deadline-capable. The service now adopts declared command pipes in nonblocking
mode and duplicates output ownership before wrapping it for the runtime poller.
Regression tests prove read cancellation, output deadlines/backpressure and
rejection of regular-file output. This does not establish full parent-death or
phase supervision.

Validation passed locally with mise Go 1.26.5 on Darwin/arm64: full
`go test -race -shuffle=on -count=1 ./...`, `go vet ./...`, the pinned-authority
verifier and whitespace checks including untracked files. Linux/amd64 and
Windows/amd64 `go build ./...` passed as compile-only checks. No Docker daemon,
real Provider endpoint, external observer, commit, push or qualification run
was used.

The adapter/caller's existing finite runner deliberately remains on v2
identity validation. Service lifetime supervision, identity/endpoint continuity
and restart are checkpoint 4; caller and real Provider backend composition are
checkpoints 5-7. Byte transfer in the test child is not Provider interoperability
or independent qualification evidence.

Next: **e1.5e.4**, checkpoint 4/13, implement and verify same-identity/static-
endpoint restart, parent-death propagation, bounded startup/deadline/shutdown
and live-connection cleanup. **10 checkpoints remain** in the fixed plan.

## e1.5e.4 Gateway lifecycle supervision and continuity

Status: **complete as local executable/process evidence**, checkpoint 4/13.

`gatewayprocess.ServiceRunner` now supervises the separately identified live
Gateway path described in
[`gateway-service-lifecycle.md`](gateway-service-lifecycle.md). It requires one
absolute phase deadline of at most five minutes, applies a five-second startup
bound and two-second shutdown/reap bound, serializes context-bounded private
commands, and accepts stop only after terminal reply, stdout EOF, clean exit,
empty stderr and reap. Canceled ambiguous command/reply exchange terminates the
service rather than skipping a private sequence.

The caller-owned control pipe also provides parent liveness. A process test
starts a Caller helper and Gateway in separate groups, opens an authorized live
tunnel, then makes the Caller exit through `os.Exit` without cleanup. Control
EOF closes the Gateway tunnel and listener and the orphan Gateway exits. Other
tests hold live tunnels through graceful stop and absolute deadline, requiring
actual close rather than treating a read timeout as closure evidence.

One runner pins a private in-memory digest over the canonical endpoint and
exact server/trust input bytes only after readiness. It restarts the actual
Gateway with a fresh PID at that exact endpoint and tests equal presented TLS
leaf bytes. Changed endpoint or newly issued identity/trust is rejected before
launch; concurrent start is rejected; a failed pre-readiness bind does not pin
continuity. This private digest is not persisted, reported or evidence and does
not prove cross-phase operator custody.

Regression tests also cover startup timeout plus group kill/reap and a child
that announces readiness but ignores control, proving operation cancellation
unblocks the Caller and terminates/reaps the process. Runtime helpers remain
under testdata and are absent from production command dependencies.

Validation passed locally with mise Go on Darwin/arm64: focused lifecycle tests
under the race detector and shuffle, full repository race/shuffle tests,
`go vet ./...`, pinned-authority verification, whitespace checks including
untracked files and Linux/Windows compile-only builds. No Docker daemon, real
Provider endpoint, external observer, commit, push or qualification run was
used.

At this checkpoint, the operational external-caller still deliberately selected
the finite identity-only bootstrap. Wiring phase state and the live runner was
deferred to e1.6a. Local supervision was not external qualification evidence.

Next: **e1.6a**, checkpoint 5/13, implement the Caller phase coordinator with
empty initial state, complete-only reconstruction and live Gateway lifecycle
composition. **9 checkpoints remain** in the fixed plan.

## e1.6a Caller phase coordinator

Status: **complete as local executable/process composition evidence**,
checkpoint 5/13.

The operational `external-caller` now uses the long-lived Gateway
`ServiceRunner`, not the earlier finite identity-only bootstrap. A new narrow
coordinator validates the phase deadline before touching state. Initial accepts
only an empty exact-`0700` root and creates the caller-generated `planned`
revision; reconstruction accepts only a closed `initial_complete` revision.
Both paths install live Gateway policy from the retained tenant pair, require
graceful stop, stdout EOF, clean child exit and reap, and verify that the state
bytes and private root remain unchanged before emitting completion.

This checkpoint used adapter-to-caller private protocol v3. It added the exact absolute
deadline already enforced by the adapter-side ten-second process supervisor;
the caller bounds the Gateway by the earlier of that value and its own parent
context. This is internal cancellation propagation, not a reported public
timestamp and not an independent qualification deadline observation. The
private completion status is
`state_and_gateway_lifecycle_validated_no_provider_execution`, so it does not
claim Provider traffic, scenario completion, or qualification.

Local tests exercised both initial and reconstruction through real separately
built caller/Gateway commands on loopback mTLS. Reconstruction uses a synthetic
complete state assembled through the public candidate store transitions; the
operational initial path at this checkpoint intentionally left `planned` state because
Provider capabilities, lifecycle, exec, terminal and artifact actions are not
implemented yet. Tests also reject expired deadlines before state creation and
partial reconstruction before Gateway start, retain partial state after
failure, destroy credential bytes, and require cleanup of a failed service.

This checkpoint does not establish a real Provider request, runtime backend,
15+5 scenario result, cross-phase supervisor custody, external provenance or
qualification. An initial failure is deliberately non-retriable in the same
root: no automatic rollback or deletion is performed.

Next: **e1.6b**, checkpoint 6/13, compose Provider credentials, capability
discovery, protected lifecycle creation/reconciliation and the corresponding
durable state bindings. **8 checkpoints remain** in the fixed plan.

## e1.6b Provider lifecycle composition

Status: **complete as local executable/process composition evidence**,
checkpoint 6/13.

The initial caller independently builds controller A and B Provider access from
the inherited credential bundle. Both controllers discover capabilities over
mTLS; the caller requires byte-identical bounded response documents, the same
Provider revision, the locked coding-shell runtime profile, exec and terminal
capability profiles, and sufficient resource limits before changing state. It
then persists the exact raw snapshot digest, Provider revision, and a stable
caller-owned policy digest and decision timestamp.

Controller A constructs the create request only from the caller-generated plan
and the selected capability authority. Each protected create/read uses a fresh
JTI and binds the retained policy, Provider revision, operation identities,
request digest, HTTP target and phase deadline. Admission expiry cannot exceed
that deadline. The caller accepts one create, reconciles its operation to
`succeeded`, requires a generation-one `ready` sandbox with the retained
workspace, slot, profile and Provider revision, then writes
`lifecycle_bound` with fencing token one. A failed lifecycle deliberately
retains only the prior durable stage; it is not rolled back or silently retried.

Reconstruction requires an already complete state, rediscovers byte-identical
capability authority through controller A, reads the retained create operation
and sandbox, and leaves the canonical state bytes unchanged. The private
adapter-to-caller protocol is now v4; its completion status says
`provider_lifecycle_and_gateway_coordination_complete_no_scenario_results`.
The public adapter still truthfully emits every locked case as `not_executed`.

Race/shuffle tests cover selection and cross-controller mismatches, partial
failure retention, reconstruction continuity, credential cleanup, and actual
separately built adapter/caller/Gateway processes against a candidate test-only
local mTLS Provider surface. The fixed `registry.invalid` development image is
only a Contract-valid placeholder accepted by that synthetic surface. No live
runtime image was pulled and no Docker daemon was used.

This establishes neither Provider implementation interoperability nor exec,
terminal, handoff, the 15+5 scenario outcomes, independent observation,
release provenance or qualification. The test Provider is owned by this
candidate repository and is not independent evidence.

Next: **e1.6c**, checkpoint 7/13, compose protected exec, terminal and handoff
operations with Gateway grant/revocation and real Provider-terminal byte
forwarding. **7 checkpoints remain** in the fixed plan.
