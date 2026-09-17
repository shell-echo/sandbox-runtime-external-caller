# Status

Current checkpoint: **e1.8b prerequisite in progress; e1.8a complete**. The
deterministic bundle, public source, GitHub-hosted Linux/amd64 rebuild,
five-subject Sigstore/Rekor attestation, downloaded-byte verification and
independent subject verification all pass. The caller now selects the published
coding/shell image by immutable index digest; refreshed candidate provenance and
the live supervised run remain open. Of the 13 checkpoints in
[`PLAN.md`](PLAN.md), 11 are complete and **2 remain**.
Sections below record evidence at each checkpoint, not simultaneous current
claims.

Current pinned authority: Provider Contract revision
`22ba6987ea5fbc37d53942720133c0acad199edd`, tree
`c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38`, 53-case local Suite
`sha256:b40c932643f4a1e5fd6681e3abf9b64a607609866a6254456970f8b8034cf2a8`,
profile `sha256:4effea27fd3d7668b88eeb95c69e19b51556914b7949b1a39ce522b2aec46c14`,
report schema `sha256:cd51ccf0aea0bc31b11ff4f288751fc7df0f0dd081860efc305182ea61f842e4`,
validator semantics `sha256:c724eaa9f3b52e1a5ba4aa5aaeb5e8b61a744818b2f56fd8ff52dfa5e1e584df`,
adapter schema `sha256:d12b477cd540e02c6a7e2f8eb77b0405b717c15e98a0f144b2d63f705ff95969`,
and adapter semantics
`sha256:10cd42017aee60b620dbbb7394a20c2a387983468a865a8d12a572f861d07662`.
The public authority snapshot containing those qualification authorities is
`96ee9933fe2a3bcfaef291b486cd6b8f7095539a`.
The raw authority-lock digest is
`sha256:e39a5f9bd3e237a94c70cef0801dd2a4f32e3b188e46bc408938c1e34f38a595`.
The authority verifier passes against that committed snapshot. This establishes
the input boundary, not a qualification result.

## e1.1 external-caller candidate foundation

Status: **local candidate only**.

The repository is separate from the Provider repository. Its current authority
refresh is uncommitted. The lock pins the Provider Contract, qualification
profile, adapter protocol, transcript projection, report schema, and validator
semantics. The verifier checks the exact lock and all named upstream public-file
bytes. Tests reject a direct import of any
`github.com/shell-echo/sandbox-runtime` package.

Not established: an external owner, independent source hosting, a hosted build
or attestation, immutable release artifacts, independent runtime behavior or
interoperability, independently supervised 15+5 qualification execution,
teardown, evidence archive, or qualification outcome.

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

## e1.6c Exec, usage, terminal and Gateway data-plane composition

Status: **complete as local synthetic/process composition**,
checkpoint 7/13.

The initial caller requires the exec/terminal client dependency and advances
from `lifecycle_bound` to `exec_bound` only after a succeeded exec operation,
a retained completed result with exit code zero, and a separately read usage
document. Usage must be correlated to the same operation/attempt/fence/sandbox
and include exactly one runtime-metered or reconciled execution count of one.
`partial` reconciliation is accepted as partial evidence; `unknown` does not
justify the binding. `result_digest` and `usage_evidence_digest` are caller
RFC 8785/SHA-256 digests of the complete decoded documents. The opaque Provider
`evidence_digest` remains a field in that usage document; the caller does not
derive usage from the exec result or invent its digest semantics.

The caller then submits a terminal-session request, reconciles its operation
and reads the handoff before writing `terminal_bound` at store revision five.
Operation, attempt, fencing, sandbox, session and selected profile must match;
the opaque reference must satisfy the closed Contract shape and the handoff
must remain unexpired without extending requested authority. Request deadlines
are clipped to the phase budget, observed/requested sandbox lease and caller
limit; exec also respects the advertised execution limit.

Each mutation and read uses its exact Contract identity, HTTP target and fresh
Admission token. Only explicit retryable 503 reads with positive Retry-After
within the remaining budget are retried. Mutations are submitted once; a failed,
expired, inconsistent or cancelled result leaves the prior durable stage and
does not silently resume an initial run. Reconstruction still requires a fully
complete state and checks capability/lifecycle continuity only; this sub-slice
does not add artifact staging or exec/terminal reconstruction acceptance.

The selected runtime must additionally advertise
`sandbox.terminal-connect@1.0.0` with `terminal-connect-v1` on the same coding
shell profile. The Caller retains controller mTLS and Admission signing
material, constructs a fresh `connect_runtime_session` admission over the full
retained handoff descriptor, and performs the fixed protected WebSocket upgrade
with `sandbox-runtime-terminal.v1`, compression disabled, binary messages and a
65,536-byte message bound. Redirects, raw endpoints, query/Origin correlation,
wrong subprotocol, descriptor mismatch and expired authority fail closed.

The Gateway child receives no Provider credential or origin. Private serving
protocol v2 adds a separately declared one-connection socket inherited from the
Caller. After Gateway authorization consumes a grant, the child sends only the
opaque reference; the Caller cross-checks it against fresh authority, opens the
Provider stream and relays bytes. Cancellation, revocation, expiry, terminal
EOF and service stop close both directions. The bridge cannot be rebound or
reused for a second Provider attach.

Validation on 2026-09-15 uses mise Go and candidate-owned synthetic evidence:
strict DTO/request/admission tests, stage-retention and cancellation tests,
fresh-token pending-read retries, a live loopback mTLS/WebSocket Provider
surface that checks actual HTTP/body/descriptor bindings, and separately built
adapter/caller/Gateway processes. The initial process tests require three
operation reads, one exec result, one independent usage read and one handoff,
plus the exact terminal state. A built production Gateway test proves opaque
binary round-trip, Provider EOF propagation, cross-actor denial, replay denial,
expiry, revocation, cancellation and bounded child reap. The current public
adapter behavior is recorded separately below. No Docker/runtime backend,
independent observer, release provenance or qualification result is
established by e1.6c.

The full `go test -race -shuffle=on -count=1 ./...` and `go vet ./...`
checks passed with mise Go 1.26.5 on Darwin/arm64. The external authority
verifier, adjacent Provider Contract lock verifier and whitespace checks
(including new untracked files) passed. All changes remain uncommitted.

## e1.7a-1 Locked capability-discovery scenario

Status: **complete as local candidate composition; superseded operationally by
the two-case composition below**.

The adapter now emits the first public `scenario_started` before any scenario
request, launches one separately supervised Caller with a closed private
single-scenario request, and accepts only an invocation/phase/case/PID-bound,
schema-valid completed result. The private request carries no expected Contract
or profile values, assertions, observations, Provider correlations, or secret
bytes. All nested returned slices and pointers are defensively copied before
the public phase machine emits them.

The Caller creates fresh strict state and performs exactly three ordered
Provider interactions: controller A capability discovery, controller B
capability discovery, and a same-CA but unadmitted identity denial. It requires
byte-identical admitted documents, the exact embedded Contract/profile
authority, one atomic coding-shell runtime profile, exact capability versions,
and either TLS rejection or a closed non-retryable 403 for the unadmitted peer.
Only explicit retryable 503 responses can be retried, within the absolute
120-second case deadline. The result is validated before state advances once to
`capabilities_bound`; no sandbox mutation or Gateway process occurs.

Local race tests cover strict private framing and alias isolation, malformed
requests/results, TLS-alert versus generic transport classification, capability
shape negatives, explicit 503 retry, cancellation, real mTLS actors, public
start-before-request ordering, separate process PID/reap, exact Provider counts,
and exact ordering of the 14 remaining `not_executed` cases. This remains
candidate-owned synthetic/component evidence. It does not establish independent
observations, external provenance, runtime interoperability, a passed scenario,
or qualification.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Windows/Linux compile checks for the changed process boundaries, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. All changes remain uncommitted.

## e1.7a-2 Protected lifecycle create

Status: **complete as local candidate composition; checkpoint e1.7a is 2/15**.

The private scenario protocol is now v2 and streams two bounded commands and
results through one supervised Caller process. The adapter publishes each
locked `scenario_started` before the corresponding private authorization. The
Caller keeps the credential bundle, state handle and scenario executor alive
between cases; invocation, phase, case and PID are cross-checked on both
results. After the second result it requires private stdin EOF, bounded stdout
and stderr, clean exit and reap.

The protected-create case constructs the request exclusively from the durable
Caller plan and previously bound capability authority. Controller A supplies
the exact mTLS identity, Admission Context and compact JWS. The accepted
operation must bind the planned sandbox, operation, attempt and fencing token.
Only one explicit retryable 429/503 with positive `Retry-After` may precede the
final 202, and the identical request and JWS are reused for that wire retry.
The original request, Admission and operation remain only in Caller memory for
the following replay case. Durable state correctly stays
`capabilities_bound`; no operation poll, runtime dispatch conclusion or Gateway
action is pulled forward from later cases.

Local tests cover v2 multi-record framing, second-command allowlisting,
start-before-command ordering, second-case failure cleanup, one PID across both
cases, exact retained replay authority, a retryable 503 followed by a real mTLS
and Admission-protected 202, unchanged durable state, child EOF/exit/reap, and
the remaining 13 cases in locked `not_executed` order. These observations are
candidate-owned component evidence, not independent qualification evidence.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Windows/Linux compile checks for the changed process boundaries, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. One earlier full-suite run hit the unchanged
five-second historical Gateway-bootstrap limit under parallel race load; that
exact test then passed ten consecutive runs and the unmodified full suite
passed. No production deadline was widened. All changes remain uncommitted.

The following bounded slice, e1.7a-3, uses the retained exact JWS for replay
rejection and a fresh JTI with the identical request for idempotency replay.

## e1.7a-3 Replay semantics

Status: **complete as local candidate composition; checkpoint e1.7a is 3/15**.

Private scenario control is now v3 and keeps one supervised Caller alive for
the first three locked cases. The adapter emits the replay
`scenario_started` record before sending its third allowlisted command. The
Caller rejects missing, reordered or additional cases, cross-checks the same
invocation/phase/PID on every result, and requires EOF, empty stderr, clean exit
and reap only after the third result.

The replay case first submits the byte-identical create request with the exact
retained Admission Context and compact JWS. It requires a closed
non-retryable 409 with no `Retry-After`; that rejection is not treated as an
idempotency success. The Caller then signs the unchanged create request and
Admission Context with a fresh JTI and requires the same accepted logical
operation. The candidate-owned test Provider separately counts exact-JTI
rejection, fresh-JTI idempotency replay and runtime dispatch, proving its local
fixture dispatched only the original create. Durable state remains
`capabilities_bound` at revision two.

Local tests cover strict three-record framing, ordered public authorization,
third-case cleanup, one PID across all cases, exact request/JWS reuse, a fresh
JTI with an unchanged context/body/operation/fence, real mTLS 409/202 traffic,
one synthetic runtime dispatch, and the remaining 12 cases in locked
`not_executed` order. These are candidate-owned component observations, not
independent qualification evidence.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Windows/Linux compile checks for the changed process boundaries, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. All changes remain uncommitted.

Next bounded slice: e1.7a-4,
`initial.lifecycle-completion-and-status`, reconciling the retained create
operation and generation-one ready sandbox before binding lifecycle state.
**Six large checkpoints remain in the fixed plan.**

## e1.7a-4 Lifecycle completion and status

Status: **complete as local candidate composition; checkpoint e1.7a is 4/15**.

Private scenario control is now v4 and keeps one supervised Caller alive for
the first four locked initial cases. The adapter emits the lifecycle-completion
`scenario_started` record before sending the fourth allowlisted command, gives
the process a bounded 480-second aggregate lifetime, and requires EOF, empty
stderr, clean exit and reap only after the fourth result.

The fourth case reconciles the exact create operation retained by the preceding
create/replay cases and then reads sandbox status. Each wire attempt signs a
fresh read Admission bound to the locked descriptor and route. Only an explicit
retryable 503 with a positive `Retry-After` is retried, within both the 64-attempt
wire maximum and the case deadline. The result is emitted only after the create
operation is `succeeded` and the exact tenant/work-order/sandbox is generation
one `ready` under the selected runtime profile and a live lease. Only then does
the Caller commit `lifecycle_bound` revision three. Rejected, inconsistent,
expired or failed observations preserve `capabilities_bound` revision two.

Local tests cover ordered four-record control, public start-before-command
authorization, fourth-case cleanup, one PID across all four cases, bounded 503
read retry with fresh JTIs, accepted/running/succeeded operation polling,
provisioning/ready status polling, failure-state preservation, real mTLS and
Admission-protected 200 reads, exact lifecycle binding, and the remaining 11
cases in locked `not_executed` order. These are candidate-owned component
observations, not independent qualification evidence.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for the changed process boundaries, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. One first full-suite run hit the unchanged
five-second historical Gateway-process I/O limit under parallel race load;
that exact test passed ten consecutive reruns and the unchanged full suite then
passed. No production deadline was widened. All changes remain uncommitted.

Next bounded slice: e1.7a-5,
`initial.exec-result-and-usage-evidence`, submitting and reconciling the locked
exec, reading its retained result and separate usage evidence, and binding only
their validated decoded documents. **Six large checkpoints remain in the fixed
plan.**

## e1.7a-5 Exec result and usage evidence

Status: **complete as local candidate composition; checkpoint e1.7a is 5/15**.

Private scenario control is now v5 and keeps one supervised Caller alive for
the first five locked initial cases. The adapter emits the exec-evidence
`scenario_started` record before sending the fifth allowlisted command, gives
the process a bounded 600-second aggregate lifetime, and requires EOF, empty
stderr, clean exit and reap only after the fifth result.

The fifth case constructs the planned bounded exec under the observed live
sandbox lease and selected Provider limit. A mutation is repeated at most once
only after an explicit retryable 429 or 503 with positive `Retry-After`, using
the byte-identical request and Admission. It then polls the exact exec operation
with fresh read Admissions and independently reads the retained exec result and
usage evidence. Only explicit retryable 503 reads with positive `Retry-After`
are retried within the 64-attempt and case-deadline bounds.

The Caller requires a correlated completed result with zero exit, no signal or
error, coherent live retention, and a nonempty Contract-valid opaque stdout
reference. It separately requires correlated, live `complete` or `partial`
usage evidence with exactly one runtime-metered or reconciled
`sandbox.exec_count=1` entry. It computes canonical digests over both full
decoded documents and commits `exec_bound` revision four only after validating
the complete public result shape. Public scenario evidence contains neither
command output nor the private opaque reference. Any missing, expired,
inconsistent or cancelled evidence preserves `lifecycle_bound` revision three.

Local tests cover ordered five-record control, old-v4 rejection, public
start-before-command authorization, fifth-case cleanup, one PID across all five
cases, exact mutation retry bytes, fresh read JTIs, operation polling, a
retryable usage read, missing-output-reference rejection, real mTLS and
Admission-protected 202/200 traffic, exact result/usage digest binding, and the
remaining 10 cases in locked `not_executed` order. These are candidate-owned
component observations, not independent qualification evidence.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for the changed process boundaries, the external
authority verifier, and the adjacent Provider Contract verifier. Tracked and
untracked whitespace checks also passed. All changes remain uncommitted.

Next bounded slice: e1.7a-6, `initial.stale-fencing-rejection`, submitting an
exec with a lower fencing token, requiring a closed non-retryable 409 before
dispatch, and preserving the accepted exec binding. **Six large checkpoints
remain in the fixed plan.**

## e1.7a-6 Stale-fencing rejection

Status: **complete as local candidate composition; checkpoint e1.7a is 6/15**.

Private scenario control is now v6 and keeps the supervised Caller alive for
the first six locked initial cases under a bounded 720-second aggregate
lifetime. The adapter emits the stale-fencing `scenario_started` record before
authorizing its private command and reports the remaining 9 initial cases in
locked `not_executed` order only after the sixth result.

The sixth case requires the retained accepted exec and `exec_bound` revision
four. It constructs a distinct caller-owned operation, attempt and idempotency
identity, binds a fresh Admission to the exact request digest, and submits fence
one below the retained accepted fence two. Only an explicit retryable 429 or
503 with positive `Retry-After` can cause one byte-identical request and
Admission replay. A final 409 must carry exactly `SANDBOX_CONFLICT` or
`SANDBOX_STALE_FENCING_TOKEN`, be non-retryable and omit `Retry-After`; the
Caller then stops without another attempt. Any accepted, malformed, retryable
or differently coded response fails closed.

The candidate-owned Provider observer records stale rejections separately
from exec dispatch. Local unit, live mTLS and separately built process tests
require exactly one accepted exec dispatch plus one stale rejection, prove the
non-retryable conflict was not retried, and compare the complete durable state
before and after the case. The stage remains `exec_bound`, store revision four,
with the accepted operation/result/usage binding unchanged. These observations
are local candidate evidence and do not establish independent qualification.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for the changed process boundaries, the external
authority verifier, and the adjacent Provider Contract verifier. Tracked and
untracked whitespace checks also passed. All changes remain uncommitted.

Next bounded slice: e1.7a-7, `initial.exec-cancellation`, proving cancellation
authority, terminal operation state and caller-state preservation under the
locked case. **Six large checkpoints remain in the fixed plan.**

## e1.7a-7 Exec cancellation

Status: **complete as local candidate composition; checkpoint e1.7a is 7/15**.

Private scenario control is now v7 and keeps one supervised Caller alive for
the first seven locked initial cases under an 840-second aggregate bound. The
adapter emits the cancellation `scenario_started` record before its private
command, forwards the validated five-interaction result, and reports the
remaining 8 cases `not_executed` only after the seventh result.

The seventh case constructs a distinct fence-three exec whose deadline is
clipped by the case, selected Provider exec limit, and observed live lease. It
submits a separately digested fence-four `caller_requested` cancellation bound
to the exact target operation and attempt. The exec mutation permits at most
one byte-identical replay after an explicit retryable 429 or 503 with positive
`Retry-After`; cancellation permits the same only for an explicit retryable
503. Acceptance of either mutation is not considered final cancellation.

Fresh read Admissions reconcile the `cancel_exec` operation to `succeeded`,
then the exact target `exec` operation to `cancelled`, and finally read a live,
correlated retained result whose status is `cancelled`. Unknown operation type,
identity drift, a different terminal status, malformed or expired result,
unapproved retry, deadline/cancellation, or premature 202-only completion fails
closed. The separate cancellation correlations are not reconstruction state;
the complete accepted `exec_bound` revision four remains unchanged.

Local unit tests cover exact cancellation DTO/digest/Admission/HTTP binding,
invalid target/reason/generation/digest rejection, bounded exact-authority
mutation retry, missing cancelled target failure, and durable-state
preservation. Candidate-owned live mTLS, one-PID process, and actual adapter
tests require the exact 202/202/200/200/200 interaction order and observe two
admitted execs, one stale rejection, one cancellation intent, both operation
reads, and two retained-result reads. This remains local candidate evidence,
not independent qualification.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for changed process packages, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. All changes remain uncommitted.

Next bounded slice: e1.7a-8,
`initial.terminal-session-and-opaque-handoff`, opening and reconciling the
locked terminal session and validating its opaque handoff without yet claiming
Gateway byte round-trip. **Six large checkpoints remain in the fixed plan.**

## e1.7a-8 Terminal session and opaque handoff

Status: **complete as local candidate composition; checkpoint e1.7a is 8/15**.

Private scenario control is now v8 and keeps one supervised Caller alive for
the first eight locked initial cases under a 960-second aggregate bound. The
adapter emits the terminal-session `scenario_started` record before its private
command, forwards the validated three-interaction result, and reports the
remaining 7 cases `not_executed` only after the eighth result.

The eighth case starts from the accepted `exec_bound` revision four and the
observed generation-one ready sandbox. It opens the planned terminal session
with fence five, a request deadline and expiry clipped by the case deadline and
observed sandbox lease, and Admission bound to the exact digest and Provider
route. Only one byte-identical retry is permitted after an explicit retryable
429 or 503 with positive `Retry-After`; acceptance is not treated as completion.

Fresh read Admissions reconcile the exact `open_runtime_session` operation to
`succeeded` and read the correlated runtime-session handoff. The Caller requires
terminal type, the selected `terminal-v1` capability profile, WebSocket
protocol, a Contract-valid opaque reference, positive connection generation,
and a live expiry no later than requested. It then commits `terminal_bound`
revision five. The full request, accepted authority, reconciled operation and
handoff remain only in live Caller memory for the next case; the public result
contains observation identifiers but not the raw handoff reference.

Local unit tests cover exact result shape, fence progression, durable binding,
private-authority retention, public redaction, bounded exact-authority mutation
retry, and malformed, non-WebSocket, expired, extended or zero-generation
handoff rejection without state transition. Candidate-owned live mTLS,
one-PID process and actual adapter tests require the exact 202/200/200 sequence
and observe one session dispatch, one operation read and one handoff read. This
is local candidate evidence, not independent qualification or terminal byte
interoperability.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for changed process packages, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. All changes remain uncommitted.

Next bounded slice: e1.7a-9,
`initial.gateway-terminal-byte-round-trip`, using the retained caller-owned
handoff to issue one Gateway grant and prove the locked authorized byte path.
**Six large checkpoints remain in the fixed plan.**

## e1.7a-9 Gateway terminal byte round-trip

Status: **complete as local candidate composition; checkpoint e1.7a is 9/15**.

Private scenario control is now v9 and keeps one supervised Caller alive for
the first nine locked initial cases under a 1080-second aggregate bound. The
adapter emits the Gateway-round-trip `scenario_started` record before its
private command, forwards the validated one-interaction result, and reports the
remaining 6 cases `not_executed` only after the ninth result.

The ninth case consumes the full terminal request, reconciled operation and
handoff retained by the same Caller process. It starts the actual sibling
Gateway, installs caller-owned tenant-A/tenant-B policy, binds an opener that
creates a fresh exact-descriptor Admission for the protected Provider
WebSocket, and issues one controller-A/tenant-A grant whose expiry is clipped
to both the handoff and case deadlines. The caller performs exactly one mTLS
CONNECT attempt and exchanges one cryptographically random 32-byte challenge,
requiring an exact 32-byte response under the case deadline. It then stops and
reaps the Gateway and proves the durable `terminal_bound` revision-five state
is unchanged.

Unit tests cover exact public result shape, private authority binding and
redaction, Provider connect Admission correlation, deadline-bounded I/O,
failure cleanup, unchanged state and no scenario advancement on failure.
Candidate-owned process tests build all three sibling commands and traverse the
actual adapter, external Caller, mTLS Gateway, private byte bridge and synthetic
Provider WebSocket echo, observing exactly one terminal connect.

These observations remain candidate-owned local evidence. In particular, the
locked continuity challenge and digest must ultimately be generated and held
by the independent `gateway_observer`; this result does not establish
independent provenance, live runtime interoperability, same-shell
reconstruction continuity, or qualification.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for changed process packages, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. All changes remain uncommitted.

Next bounded slice: e1.7a-10,
`initial.gateway-wrong-caller-and-cross-tenant-rejection`, proving both
caller-owned negative authorization paths without changing terminal state.
**Six large checkpoints remain in the fixed plan.**

## e1.7a-10 Gateway wrong-caller and cross-tenant rejection

Status: **complete as local candidate composition; checkpoint e1.7a is 10/15**.

Private scenario control is now v10 and keeps one supervised Caller alive for
the first ten locked initial cases under a 1200-second aggregate bound. The
adapter emits the rejection-case `scenario_started` record before its private
command, forwards the validated two-interaction result, and reports the
remaining 5 cases `not_executed` only after the tenth result.

The tenth case requires the two caller-owned tenants and two Gateway controller
subjects to be distinct. It restarts the exact endpoint/identity Gateway,
installs the same caller policy, binds the retained Provider terminal opener,
and issues one controller-A/tenant-A grant. A certificate-free CONNECT is
rejected during TLS or before HTTP upgrade. A separate controller-B mTLS
CONNECT with that same tenant-A grant is rejected at the subject binding. Each
probe has exactly one wire attempt; neither consumes terminal bytes or opens a
second Provider WebSocket. The Gateway is stopped and reaped and the complete
`terminal_bound` revision-five state remains unchanged.

Unit tests cover exact result and observation shape, certificate removal,
distinct actor/subject selection, one-attempt failures, private handoff
redaction, zero additional Provider connects, cleanup and unchanged state.
Candidate-owned executable tests build all three sibling commands and observe
both live rejection paths while the synthetic Provider terminal-connect count
remains the one successful connection from the preceding round-trip case.

These remain local candidate observations. The independent `gateway_observer`
must still establish the locked no-runtime-connection and no-byte-forwarding
facts during qualification; this slice does not establish independent
provenance, live runtime interoperability or a qualification result.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for changed process packages, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. All changes remain uncommitted.

Next bounded slice: e1.7a-11, `initial.gateway-grant-expiry`, proving an active
Gateway tunnel closes at its caller-owned grant deadline without changing
terminal state. **Six large checkpoints remain in the fixed plan.**

## e1.7a-11 Gateway grant expiry

Status: **complete as local candidate composition; checkpoint e1.7a is 11/15**.

Private scenario control is now v11 and keeps one supervised Caller alive for
the first eleven locked initial cases under a 1320-second aggregate bound. The
adapter emits the expiry-case `scenario_started` record before its private
command, forwards the validated one-interaction result, and reports the
remaining 4 cases `not_executed` only after the eleventh result.

The eleventh case restarts the exact endpoint/identity Gateway, installs the
same caller-owned tenant policy, and binds the retained Provider terminal
opener. It issues one deliberately short-lived controller-A/tenant-A grant,
clipped to the retained handoff and case cleanup bounds, and performs exactly
one mTLS CONNECT. A fresh random 32-byte challenge must round trip before the
grant deadline. The same connection must then close with a non-timeout error at
or after that deadline; a post-expiry probe must receive no bytes. The Gateway
is stopped and reaped and the complete `terminal_bound` revision-five state
remains byte-for-byte unchanged.

Unit tests cover the exact result/observation shape, initial byte authorization,
deadline closure, no post-expiry response, private token/handoff redaction,
cleanup, unchanged state, and no advancement on an invalid closure. The
candidate-owned executable tests build all three sibling commands and observe
the live expiry path; the synthetic Provider receives exactly one new terminal
connection for this case.

These remain local candidate observations. TCP can accept a locally buffered
write after peer closure, so the implementation does not misclassify the first
post-close write result as forwarding evidence. The independent
`gateway_observer` must still establish initial authorization, close timing,
and absence of post-expiry backend bytes during qualification. This slice does
not establish independent provenance, live runtime interoperability, or a
qualification result.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for changed process packages, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. All changes remain uncommitted.

Next bounded slice: e1.7a-12, `initial.gateway-revocation`, proving an active
Gateway tunnel closes only after caller-authorized revocation is acknowledged,
without changing terminal state. **Six large checkpoints remain in the fixed
plan.**

## e1.7a-12 Gateway revocation

Status: **complete as local candidate composition; checkpoint e1.7a is 12/15**.

Private scenario control is now v12 and keeps one supervised Caller alive for
the first twelve locked initial cases under a 1440-second aggregate bound. The
adapter emits the revocation-case `scenario_started` record before its private
command, forwards the validated two-interaction result, and reports the
remaining 3 cases `not_executed` only after the twelfth result.

The twelfth case restarts the exact endpoint/identity Gateway, installs the
same caller-owned tenant policy, binds the retained Provider terminal opener,
and issues one controller-A/tenant-A grant bounded by the live handoff and case
cleanup deadline. Its only CONNECT completes a fresh random 32-byte round trip
before the caller sends exactly one controller-A revocation control write.
`revocation-acknowledged` is reported only after that control operation returns;
the production Gateway returns only after all active permits finish. The same
connection must then show a non-timeout close, and a post-revocation probe must
receive no bytes. Gateway stop/reap succeeds and the complete
`terminal_bound` revision-five state remains byte-for-byte unchanged.

Unit tests cover exact interaction and observation shape, mutation-write
accounting, initial byte authorization, acknowledgement ordering, connection
closure, no post-revocation response, token/handoff redaction, cleanup, and
failure without result or advancement. Candidate-owned executable tests build
all three sibling commands and observe the live path; the synthetic Provider
receives exactly one new terminal connection for this case.

These are still local candidate observations. The wrong-controller revocation
path remains covered at the Gateway component boundary but is not added to this
locked two-interaction case. The independent `gateway_observer` must establish
the close and no-forwarding facts during qualification. This slice does not
establish independent provenance, live runtime interoperability, or a
qualification result.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for changed process packages, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. All changes remain uncommitted.

Next bounded slice: e1.7a-13, `initial.artifact-staging-and-evidence`, adding
the locked artifact mutation, operation reconciliation, evidence read, and
durable artifact binding. **Six large checkpoints remain in the fixed plan.**

## e1.7a-13 Artifact staging and evidence

Status: **complete as local candidate composition; checkpoint e1.7a is 13/15**.

Private scenario control is now v13 and keeps one supervised Caller alive for
the first thirteen locked initial cases under a 1560-second aggregate bound.
The adapter emits the artifact-case `scenario_started` record before its private
command, forwards the validated three-interaction result, and reports the
remaining 2 cases `not_executed` only after the thirteenth result.

The earlier output exec now creates one Caller-defined 24-byte file under the
stable `/outputs` mount while retaining its required stdout. The thirteenth case
constructs the artifact reference, source path, expected SHA-256, media type,
exact size bound, expiry, operation/attempt/idempotency identities, and fence
six (strictly above the terminal mutation fence) without accepting Provider
metadata as platform truth. It submits the
protected `stage_artifact` mutation, separately reconciles the correlated
`artifact_stage` operation to `succeeded`, and reads evidence with a fresh
descriptor Admission. The Caller requires `staged`, an opaque staging
reference, exact digest/media/size, three passed checks, coherent timestamps,
and unexpired evidence before committing `initial_complete` revision six.
The durable binding uses the Caller-computed RFC 8785 digest of the full decoded
evidence document; the Provider-supplied evidence digest is only one opaque
field in that preimage.

Provider client tests cover request-digest/admission/path/body binding, strict
response shape, closed paths/media types, staged-check requirements, and
operation/evidence correlation; the client also enforces the locked 64 KiB
mutation limit. Scenario tests cover
the exact public interaction shape, private-reference redaction, state
transition, and rejection of mismatched digest, size, artifact reference,
check result, or expiry. Candidate executable tests build all three sibling
commands and traverse the mTLS/JWS Provider path. The Provider is synthetic and
does not prove that an independent runtime produced or scanned the file.

Final validation on 2026-09-15 passed the full race/shuffle suite, `go vet`,
Linux/Windows compile checks for changed process packages, the external
authority verifier, the adjacent Provider Contract verifier, and tracked plus
untracked whitespace checks. All changes remain uncommitted.

Next bounded slice: e1.7a-14,
`initial.provider-cross-tenant-artifact-rejection`, proving controller B cannot
stage or read controller A's artifact operation and no artifact dispatch occurs.
**Six large checkpoints and 22 fixed small steps remain.**

## e1.7a-14 Provider cross-tenant artifact rejection

Status: **complete as local candidate composition; checkpoint e1.7a is 14/15**.

Private scenario control is now v14 and keeps one supervised Caller alive for
the first fourteen locked initial cases under a 1680-second aggregate bound.
The adapter emits the cross-tenant case's `scenario_started` record before its
private command, forwards the validated two-interaction result, and reports
only the final initial case `not_executed` after the fourteenth result.

The Caller opens a distinct controller-B Provider access from its retained
credential bundle and signs a fresh Admission bound to tenant B and work order
B. It reuses the exact successful artifact request body, operation, attempt,
fence and request digest against tenant A's sandbox. The Provider requires the
controller-B mTLS/JWS identity and complete HTTP/body binding, then returns the
locked closed `403/SANDBOX_FORBIDDEN` before incrementing the artifact-dispatch
count or replacing retained artifact authority. A separate fresh read
Admission targets the retained artifact operation and receives the locked
concealing `404/SANDBOX_NOT_FOUND`; the successful operation-read count does
not advance and no operation document or backend reference is returned.

Scenario tests cover exact public result shape, tenant-B Admission binding,
reuse of the retained logical request, private-authority redaction, unchanged
`initial_complete` revision-six state, non-retryable outcome enforcement, exact
mutation-authority reuse on a permitted 503 retry, and fresh JTI issuance for a
permitted read retry. Candidate process tests build the sibling commands and
verify both mTLS/JWS rejection paths plus unchanged successful Provider counts.
The Provider and observer are candidate-owned synthetic test components; this
does not establish independent multi-tenant isolation, live runtime behavior,
or qualification evidence.

Validation on 2026-09-16 covers the full race/shuffle suite, `go vet`,
Linux/Windows compile checks, the external authority verifier, the adjacent
Provider Contract verifier, and tracked plus untracked whitespace checks. All
changes remain uncommitted.

Next bounded slice: e1.7a-15,
`initial.provider-mtls-caller-binding-rejection`, proving a valid Admission
presented over controller B's mTLS identity cannot read controller A's sandbox.
**Six large checkpoints and 21 fixed small steps remain.**

## e1.7a-15 Provider mTLS caller-binding rejection

Status: **complete as local candidate composition; checkpoint e1.7a is 15/15
and complete locally**.

Private scenario control is now v15 and keeps one supervised Caller alive for
all 15 locked initial cases under an 1800-second aggregate bound. The adapter
emits the final case's `scenario_started` before its private command, forwards
the validated result, then completes the initial invocation as `completed`.

For the final case the Caller deliberately uses controller B's Provider client
and admitted mTLS certificate while constructing a fresh read Admission with
controller A's signer, subject, tenant-A work order and retained policy digest.
The candidate-owned synthetic Provider first authenticates controller B's
certificate, then validates the otherwise-correct controller-A JWS and request
binding, requires the peer/JWS caller identities to agree, and returns the
locked non-retryable `403/SANDBOX_FORBIDDEN`. The normal sandbox-status read
counter does not advance, proving the synthetic route rejected the mismatch
before its state-read branch. No Provider document is returned and durable
`initial_complete` revision-six state remains byte-for-byte unchanged.

Scenario tests cover exact public result shape, controller-B transport with a
controller-A-signed subject, fresh-JTI retry after an allowed 503, rejection of
success, wrong-code and concealing-404 outcomes, unchanged state, the complete
15-record private sequence, adapter ordering, and separately built process
execution. This is candidate-owned local/synthetic evidence; it does not prove
independent Provider runtime interoperability, observer independence,
provenance, or qualification.

Validation on 2026-09-16 covers the full race/shuffle suite, `go vet`,
Linux/Windows compile checks, the external authority verifier, the adjacent
Provider Contract verifier, and tracked plus untracked whitespace checks. All
changes remain uncommitted.

Next bounded slice: e1.7b-1,
`reconstruction.locked-capability-discovery`, starting reconstruction from the
retained complete caller state without harness correlation reinjection.
**Five large checkpoints and 20 fixed small steps remain.**

## e1.7b-1 Reconstruction locked capability discovery

Status: **complete as local candidate composition; checkpoint e1.7b is 1/5**.

Private scenario control is now v16. It accepts either the complete 15-case
initial sequence or the single currently authorized reconstruction capability
request. The reconstruction request retains the same closed fields as initial
startup and contains no sandbox, operation, attempt, idempotency, fencing,
runtime-session or handoff binding. The Caller opens the state root only through
`OpenReconstruction`, which accepts exactly one canonical `0600`
`initial_complete` state document at revision six.

The first reconstruction case starts fresh adapter, Caller and Gateway command
processes. The Caller installs policy from its own retained tenant IDs, loads a
new controller-A Provider access from the credential bundle, and discovers
capabilities against a fresh candidate-owned synthetic Provider server
instance. It accepts the result only when the locked capability selection,
Provider revision and SHA-256 digest of the exact raw capability document equal
the retained caller-owned binding. The complete state file is byte-identical
before and after the new invocation. Gateway shutdown, private stdout EOF,
empty stderr, clean Caller exit and reap are required before the adapter accepts
the scenario result.

The adapter emits `scenario_started` before private authorization, publishes
the validated completed result, then truthfully reports the remaining four
reconstruction cases `not_executed` and finishes `stopped`. Unit and process
tests cover exact public result shape, 503 retry without invented Retry-After,
capability-byte mismatch rejection and cleanup, forbidden-field absence,
fresh Caller PID, fresh synthetic Provider instance, new Gateway process,
byte-identical state and actual separately built adapter/Caller/Gateway
commands.

The Provider server and process assertions remain candidate-owned local test
evidence. They do not establish an independently supervised new Provider
process, external source/build provenance, live runtime continuity, independent
observer facts, or qualification.

Validation on 2026-09-16 covers the full race/shuffle suite, `go vet`,
Linux/Windows compile checks, the external authority verifier, the adjacent
Provider Contract verifier, and tracked plus untracked whitespace checks. All
changes remain uncommitted.

Next bounded slice: e1.7b-2, `reconstruction.durable-lifecycle`, recovering the
retained create operation and sandbox from caller-owned state and reconciling
them without harness correlation reinjection.
**Five large checkpoints and 19 fixed small steps remain.**

## e1.7b-2 Reconstruction durable lifecycle

Status: **complete as local candidate composition; checkpoint e1.7b is 2/5**.

Private scenario control is now v17. After the completed reconstruction
capability result, the adapter emits `scenario_started` for
`reconstruction.durable-lifecycle` and authorizes that exact continuation on
the same fresh Caller process. The Caller retains the controller-A access and
the newly started reconstruction Gateway from the first case; neither the
harness request nor the continuation command carries any sandbox, operation,
attempt, fencing or tenant correlation.

The second case reads the create operation and sandbox descriptors from the
complete Caller-owned revision-six state. It signs a new Admission for every
wire attempt, retries only explicit retryable `503` responses with a positive
`Retry-After` under the case deadline and 64-attempt profile bound, and requires
the exact retained create operation to be `succeeded`. It then requires the
same retained sandbox, tenant, work order, workspace, Provider revision and
slot key to report desired/observed `ready`, generation and observed generation
one, the locked runtime profile, and a non-expired lease. No state transition is
performed; the complete state document remains byte-for-byte identical.

The adapter publishes both completed reconstruction results, truthfully marks
the remaining three reconstruction cases `not_executed`, and finishes
`stopped`. Only after the second result does private stdin close; successful
Gateway stop, private stdout EOF, empty stderr, clean Caller exit and reap are
required. Unit and separately built process tests cover exact public result
shape, retained descriptor binding, fresh-JTI 503 retry, mismatched operation
rejection, same Caller/Gateway lifetime, fresh synthetic Provider seeding,
unchanged state bytes and Provider request counts of one capability, one
operation and one sandbox read.

This remains candidate-owned local/synthetic evidence. It does not establish
an independently supervised new Provider process, live runtime continuity,
external source/build provenance, independent observer facts or qualification.

Validation on 2026-09-16 covers the full race/shuffle suite, `go vet`,
Linux/Windows compile checks, the external authority verifier, the adjacent
Provider Contract verifier, and tracked plus untracked whitespace checks. All
changes remain uncommitted.

Next bounded slice: e1.7b-3,
`reconstruction.retained-exec-usage-and-artifact-evidence`, reading and
cross-checking the retained exec result, usage evidence and artifact evidence
without state mutation or harness correlation reinjection.
**Five large checkpoints and 18 fixed small steps remain.**

## e1.7b-3 Reconstruction retained exec, usage and artifact evidence

Status: **complete as local candidate composition; checkpoint e1.7b is 3/5**.

Private scenario control is now v18. The adapter authorizes
`reconstruction.retained-exec-usage-and-artifact-evidence` only after the first
two reconstruction results, on the same fresh Caller and Gateway processes.
The continuation carries only invocation, phase, case and deadline fields; it
does not carry Provider operation, attempt, fencing, sandbox, evidence or digest
values.

The Caller constructs all three read descriptors from its complete revision-six
state and signs a fresh Admission for every attempt. It accepts only explicit
retryable `503` responses with a positive `Retry-After` under the case deadline
and 64-attempt profile bound. The retained exec result must remain completed
with zero exit, an opaque stdout reference, coherent timestamps and live
retention. Usage must remain correlated, retained, complete or partial, and
contain exactly one reconciled/runtime-metered exec-count entry of one. Artifact
evidence must remain staged, correlated, unexpired, within its original
retention, match the Caller-owned reference/content metadata, and retain all
three passed checks.

For each decoded document, the Caller independently recomputes its RFC 8785
SHA-256 digest and requires equality with `exec.result_digest`,
`exec.usage_evidence_digest` or `artifact.evidence_digest` in its durable state.
The Provider's own opaque `evidence_digest` fields are not substituted for
these Caller digests. A mismatch fails before publishing a scenario result and
does not change the state.

The local synthetic Provider now retains the exact documents read during the
initial phase and imports those same bytes-as-values into a fresh service
instance only after verifying all three Caller digests. This models Provider
durability for the process tests and prevents regenerated timestamps from
falsely satisfying continuity. It remains candidate-owned test setup, not an
independent Provider persistence observation.

The adapter publishes the first three reconstruction results, marks the final
two `not_executed`, and finishes `stopped` only after Gateway shutdown, private
EOF, empty stderr, clean Caller exit and reap. Tests cover exact public result
shape, fresh-JTI 503 retry, digest mismatch rejection, stable state bytes,
three-process execution and one reconstructed read of each evidence document.

Validation on 2026-09-16 covers the full race/shuffle suite, `go vet`,
Linux/Windows compile checks, the external authority verifier, the adjacent
Provider Contract verifier, and tracked plus untracked whitespace checks. All
changes remain uncommitted.

Next bounded slice: e1.7b-4, `reconstruction.durable-opaque-handoff`, reading
and validating the retained terminal handoff without state mutation or harness
correlation reinjection.
**Five large checkpoints and 17 fixed small steps remain.**

## e1.7b-4/5 Reconstruction retained handoff and Gateway reconnect

Status: **complete as local candidate composition; checkpoint e1.7b is 5/5
and complete locally**.

Private scenario control is now v20. The fourth reconstruction command is
accepted only after capability, lifecycle and retained-evidence completion in
the same fresh Caller/Gateway lifetime. The Caller constructs the handoff read
descriptor exclusively from its revision-six durable state, signs a fresh
Admission for every attempt, and accepts retries only for an explicit retryable
`503` with positive `Retry-After` under the case deadline. The returned full
handoff must bind the retained operation, attempt, fence, sandbox, runtime
session, terminal profile, WebSocket protocol, positive connection generation,
live expiry, exact opaque reference and Caller-retained raw-reference digest.
The raw reference is absent from public evidence.

The fifth command uses that newly read full handoff as transient connection
authority; it does not reconstruct authority from the opaque reference alone
and receives no handoff injection from the harness. The Caller installs one
backend opener into the already-running reconstructed Gateway, issues a
caller-owned one-use grant clipped to both the command and handoff expiry, and
completes one bounded 32-byte round trip through Gateway to the fresh synthetic
Provider process. The grant, handoff and challenge bytes are absent from public
output. The Caller state file remains byte-for-byte unchanged across all five
reconstruction cases.

The synthetic Provider retains the exact initial handoff and imports it into
the fresh test service only after checking every durable state binding. Unit
tests cover fresh-JTI read retry, mismatch rejection without authority or state
advance, exact public result shapes, private-value redaction and bounded
cleanup. Separately built process tests cover the fresh adapter, Caller,
Gateway and synthetic Provider chain, one retained-handoff read, one terminal
connect, clean process reap and unchanged state bytes.

This is candidate-owned local/synthetic composition. The echoed bytes do not
independently prove same-shell continuity; the locked qualification still
requires the independent `gateway_observer` challenge and independently
supervised process/runtime evidence.

Validation on 2026-09-16 covers the full race/shuffle suite, `go vet`,
Linux/Windows compile checks, the external authority verifier, the adjacent
Provider Contract verifier, and tracked plus untracked whitespace checks. All
changes remain uncommitted.

## e1.7c candidate process closure and transcript limits

Completed on 2026-09-16. Adapter failures now preserve the locked public error
surface: executable/start failures become `caller_start_failed`, ordinary case
failures become `scenario_execution_failed`, and unconfirmed cleanup becomes a
sanitized `internal_failure` plus nonzero adapter exit. A failure to close the
Caller can no longer be discarded or mislabeled as successful cleanup.

Caller process supervision now drains stdout concurrently with `Wait`, permits
two seconds for a normal exit and enforces a five-second total reap bound for
both normal completion and abort. It terminates the private process group after
the leader exits, closing the inherited-pipe hole in which a descendant could
otherwise keep stdout open indefinitely. Tests build a parent/straggler fixture
and prove bounded normal and forced cleanup plus disappearance of the complete
process group.

Adapter tests now validate the exact 15-case initial and five-case
reconstruction transcript sequences, monotonic sequence/phase binding, single
last terminal, final LF, locked per-record and aggregate byte limits, and no
post-terminal records. Executable tests additionally reject any public output
containing retained caller run, tenant, work-order, workspace, branch,
resolution, sandbox, operation, attempt, idempotency, runtime-session or raw
handoff values.

This is candidate-owned process evidence only. The `0600` caller state remains
intentionally durable for reconstruction. The candidate does not perform or
claim Provider/runtime namespace teardown, the pre-run baseline, the three
stable zero-resource samples, the supervisor-owned closed transcript
projection, or an independent qualification disposition. Those remain under
the locked operator/observer boundary in e1.8b/e1.8c.

Validation on 2026-09-16 covers the full race/shuffle suite, `go vet`,
Linux/Windows compile checks, the external authority verifier, the adjacent
Provider Contract verifier, and tracked plus untracked whitespace checks. All
changes remain uncommitted.

Next checkpoint: e1.8a, reproducible artifacts, immutable release/source
identity, exact build commands/digests and provenance. **Three large
checkpoints and eight merged execution steps remain.**

## e1.8a local reproducible bundle and provenance boundary

Local implementation completed on 2026-09-16. `cmd/release-artifacts` creates
one deterministic Git-visible source archive, derives the immutable 64-hex
`source-revision` from its raw SHA-256, and embeds that identity into all three
candidate command builds. It records and fixes the exact Go version and raw Go
binary digest, target/architecture baseline, environment, `-mod=readonly`,
`-trimpath`, `-buildvcs=false`, empty build ID and linker identity arguments.

The builder extracts the same archive into two independent temporary roots and
requires byte-identical qualification-adapter, external-caller and
caller-gateway outputs before atomically publishing the bundle. Its canonical
RFC 8785 manifest binds the authority lock, source archive and Git baseline,
toolchain, exact command arrays, executable raw-byte digests/sizes and shared
source identity. `-verify` strictly rechecks the canonical/self-digesting
manifest, deterministic archive shape and every retained executable. Tests also
launch the built adapter and require its two startup identities to equal the
archive-derived identity, then prove executable tampering is rejected.

The candidate manifest deliberately says
`candidate-local-reproducibility-only`, `qualification_eligible: false`, and
records no independent source-hosting/build attestation or process-supervisor
observation because candidate-controlled bytes cannot self-certify those facts.
The preliminary private source revision
`32bfb5fd786228769742cd90db9cb18f127edf6f` was pushed and hosted run
`35067554697` completed the full serialized race/shuffle suite, vet, deterministic
Linux/amd64 build, strict bundle verification, public authority checkout and
digest verification, and artifact upload. The downloaded artifact passed the
local strict verifier with manifest digest
`sha256:5e11550fe9f69f4770386237a98a438c459390549211d776e2de8ee0cbd34b06`.

Artifact `10435176113` has archive digest
`sha256:a9026a602ac2f1d18cf8ddd832d75f269d5bcf9455bcdd11154661d7df75aab0`
and expires on 2026-10-16. Its source archive/source identity is
`sha256:0100134da1680da8c101d9a7b8944d8c1a1b51317d255037452b6305f6bf283d`;
the qualification-adapter, external-caller and caller-gateway raw digests are
respectively `sha256:92726c7d534df6f7a5079d68473becc6a2254ef28b12b9e31ee1c742252b7c96`,
`sha256:82249d2f1d0162756bf6fda76231eb95d2d0972e8f3e929453a8cbf9cb157caf`,
and `sha256:fb19d045119c8971cd3696496df41d65b8213a4b3889b81f103fe6edd84ad5fd`.

The final attestation step failed closed with GitHub's explicit
`Feature not available for user-owned private repositories` response. No
attestation was created for that preliminary revision, and it is retained only
as historical failure evidence.

After explicit authorization, the repository was made public. Hosted run
`35068957048` then passed every workflow step against source commit
`58a211f0c167af3ec117c8cb8247bfe268bbae40`: full serialized race/shuffle tests,
vet, deterministic Linux/amd64 build, strict bundle verification, public
authority checkout and verification, artifact upload, attestation and immutable
summary publication. Artifact `10435915145` has archive digest
`sha256:d01ea02563a229c42b9a53dbfcd628f82e659f22dc3e2955d8d6cfa0197a259d`
and expires on 2026-10-16.

The downloaded public bundle passed the strict verifier with manifest digest
`sha256:468b0f7bfd7e835ba5464033994739c28cec3b9985fbd24fb3ae375b8e7fb33b`.
Its source archive/source identity is
`sha256:94d7eb744c0e70d9058a6d19888bba0d4852908e8be407f86ab31864e1e82eac`;
the qualification-adapter, external-caller and caller-gateway raw digests are
respectively `sha256:90f8dfe5aa6ee3cd99edbaffede885646a5082f3460b63c4f07357c10101ca8f`,
`sha256:82249d2f1d0162756bf6fda76231eb95d2d0972e8f3e929453a8cbf9cb157caf`,
and `sha256:fb19d045119c8971cd3696496df41d65b8213a4b3889b81f103fe6edd84ad5fd`.
GitHub attestation `47846951` covers exactly those five retained subjects, is
signed through the Public Good Sigstore instance, is recorded in Rekor, and all
five local `gh attestation verify --repo
shell-echo/sandbox-runtime-external-caller` checks exited successfully.

Next checkpoint: e1.8b, the independently supervised initial/reconstruction run
against a live runtime with operator-owned observers and teardown. **Two large
checkpoints and five merged execution steps remain; e1.8a is complete.**

## e1.8b published runtime-image prerequisite

The current worktree replaces the synthetic
`registry.invalid/sandbox/base@sha256:dddd...` create policy with exact image
`ghcr.io/shell-echo/sandbox-runtime-coding-shell@sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1`.
The Provider repository records that exact linux/amd64 plus linux/arm64/v8 OCI
index in merge `ea3c06cf655a70ac595d1833949408233962e285`, from source
`cf1830e9bbfcd08d6f171e60f67d949d839e1069`, publication run `35171475925`
and attestation `48073123`. The create-request test requires the production
repository and digest separately, preventing a mutable tag from replacing the
digest authority.

The public Contract and qualification authorities are byte-identical, so the
authority lock deliberately remains at snapshot `96ee9933...`; changing that
identity would manufacture an authority refresh with no authority-byte change.
The provenance workflow instead checks those locked public bytes from Provider
merge `ea3c06c`, which also contains the accepted image publication record.

This removes the known synthetic-image blocker only. It is not evidence that
the image was pulled or executed by this candidate, that the 15+5 cases passed,
or that cleanup and independent observations exist. A new commit, hosted
candidate build/attestation, independently supervised live initial plus
reconstruction run, and final report remain separate gates.
