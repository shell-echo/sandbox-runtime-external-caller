# sandbox-runtime external caller candidate

This is a clean-room candidate consumer of the repository-owned
`sandbox-runtime` Provider Contract. It is a separate Git repository and may
use generated code from the locked public Contract, but it must not import or
copy Provider implementation packages or either repository's reference E2E
caller.

The remaining work is tracked in [`docs/PLAN.md`](docs/PLAN.md): 10 of 13
checkpoints are complete; 3 remain. Checkpoint e1.8a is in progress: local
reproducibility and a private hosted build are established, while independent
attestation remains blocked by repository visibility/account capability.

The current authority lock pins Provider Contract revision
`22ba6987ea5fbc37d53942720133c0acad199edd`, tree
`c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38`, the 53-case local Suite, and the
refreshed P2.7 profile/report/protocol authorities from public authority
snapshot `96ee9933fe2a3bcfaef291b486cd6b8f7095539a`. The raw
`authority.lock.json` digest is
`sha256:e39a5f9bd3e237a94c70cef0801dd2a4f32e3b188e46bc408938c1e34f38a595`.
These committed authorities are inputs to release provenance, not a
qualification result.

## Current scope

The completed e1.1 foundation establishes:

- the exact Provider Contract revision, tree, document identities, and Suite
  identities;
- the exact external-caller qualification profile and adapter protocol
  authorities;
- raw-byte digests for every public upstream file consumed by the candidate;
- a fail-closed verifier for those inputs; and
- a source-level import boundary check.

The completed e1.2 codec slice additionally provides a clean-room
`internal/protocol` implementation of:

- the locked startup identity and its single-LF output framing;
- one-shot, bounded invocation input through required EOF;
- strict UTF-8 JSON with duplicate-member, invalid-surrogate, multiple-value,
  unknown-field, and missing-field rejection;
- the locked secure-origin, Gateway endpoint, absolute POSIX path, source
  identity, and credential-channel shapes; and
- ordered startup requirement to invocation descriptor matching.

The completed e1.3 protocol slice adds:

- closed adapter-to-harness output DTOs and a fail-closed single-LF producer;
- schema-before-direction rejection for every adapter output message presented
  on the invocation input;
- the exact locked initial and reconstruction case order;
- one single-phase state machine with contiguous sequence, invocation/phase
  binding, completed-versus-not-executed branching, and derived terminal
  completion; and
- terminal-message, EOF, clean-exit, record-count, and byte-count enforcement.

The completed e1.4 Provider caller foundation adds:

- RFC 8785 canonical JSON with fixed public Contract digest vectors;
- create-request, read-descriptor, Admission Context, and compact JWS binding;
- deterministic Ed25519/EdDSA signing with closed headers and claims;
- local Provider DTOs and strict bounded response decoding; and
- redirect-free capability discovery, sandbox creation, sandbox-status reads,
  and operation reconciliation over an explicitly injected HTTP transport.

The completed e1.5a credential and mTLS checkpoint adds:

- a fixed seven-channel startup declaration covering the exact Provider and
  Gateway actors needed by the locked 15+5 profile;
- one-shot, EOF-framed, ordered inherited-pipe reads with per-channel and total
  bounds, rejection of non-pipe descriptors, and best-effort byte clearing;
- a closed candidate-private Provider credential document with no correlation
  fields and exact actor-to-channel selection;
- client certificate/private-key parsing with exact URI SAN, client-auth,
  validity, and actor-subject binding; and
- a no-proxy TLS 1.2-or-newer Provider transport plus Ed25519 admission signer,
  injected into the existing clean-room Provider client.

The completed e1.5b durable-state checkpoint adds:

- a no-symlink, exactly `0700`, initially empty caller state root;
- caller-internal cryptographic generation of the persisted run, tenant,
  work-order, sandbox, operation, attempt, and idempotency plan;
- a closed six-stage state machine that cross-binds retained lifecycle, exec,
  terminal, handoff, and artifact correlations to that plan;
- canonical, bounded, exactly `0600` state revisions using file sync, atomic
  rename, and directory sync; and
- complete-only reconstruction with strict identity, permission, file-stability,
  unknown-field, and out-of-band-change rejection.

The completed e1.5c terminal-Gateway checkpoint adds:

- closed Gateway client credentials with exact actor, URI-SAN, trust, and
  HTTPS transport binding;
- an immutable two-controller/two-tenant policy and bounded one-use 256-bit
  terminal grants;
- direct mTLS HTTP/1.1 CONNECT with authorization before opaque backend
  resolution and bidirectional byte forwarding;
- live connection closure on grant expiry and caller-authorized revocation; and
- local reconstruction from the caller-owned complete state into a new Gateway
  instance while preserving synthetic terminal continuity.

The completed e1.5d.1 process-entrypoint checkpoint adds:

- three separately buildable `qualification-adapter`, `external-caller`, and
  `caller-gateway` command artifacts;
- a phase-unbound adapter machine that emits locked startup before learning the
  harness phase or reading invocation and credential bytes;
- exact inherited-pipe draining and secret-bundle destruction after invocation
  acceptance; and
- an honest all-`not_executed`/`stopped` adapter path while, at that checkpoint,
  the external caller and Gateway commands were explicit exit-69 fail-closed
  placeholders.

The completed e1.5d.2 external-caller process checkpoint adds:

- a closed, bounded, credential-free private adapter-to-caller control codec;
- a fixed sibling external-caller launch with empty argv/environment, separate
  anonymous credential pipes, bounded output, process-group termination, and
  bounded reap;
- an operational external-caller bootstrap that independently drains and
  destroys its credential bundle; and
- PID/phase cross-binding between the private child result and the process the
  adapter actually started, without leaking either into public adapter output.

The completed e1.5d.3 Gateway bootstrap checkpoint adds:

- a closed, bounded, credential-free private caller-to-Gateway control codec;
- an operational `caller-gateway` bootstrap that consumes only the remapped
  three-channel Gateway credential subset in its own process;
- fixed-sibling launch with empty argv/environment, PID/phase cross-binding,
  bounded output, process-group termination, and bounded reap; and
- one local adapter-to-caller-to-Gateway executable composition.

The completed e1.5e.1 definition checkpoint adds the
[Gateway server identity supply standard](docs/gateway-server-identity.md), a
machine-readable proposed server-channel declaration, and declaration/control
negative tests. It corrects a previous premise: seven channels are this
candidate's current choice; the public adapter protocol permits up to eight.
The standard selects an explicitly declared eighth `gateway_credentials`
channel with `actor: null`, without changing public protocol authority.

The completed e1.5e.2 implementation activates that eighth channel and adds:

- a bounded closed server secret decoder, strict PEM/PKCS#8 Ed25519 key loading,
  exact endpoint SAN/server-auth binding and injected-root chain verification;
- client subject/chain checks and Gateway key separation from other Gateway,
  Provider TLS and Admission signing identities before child launch;
- versioned private caller/Gateway control, with only the server credential and
  server trust forwarded to the Gateway; and
- independent server-identity validation in the Gateway child, explicit parsed
  key cleanup, and real three-process valid/invalid-identity tests.

The completed e1.5e.3 adds a separately identified
[private serving boundary](docs/gateway-service-control.md) to `caller-gateway`:
real fixed-endpoint mTLS CONNECT listening, truthful policy-unset readiness,
caller-owned immutable policy, grant/revocation control and strict bounded IPC.
The actual command fails closed with 502 for an authorized unavailable backend;
a test-only child resolver verifies opaque bytes and rejection before resolution.

The completed e1.5e.4 adds the
[long-lived service supervisor](docs/gateway-service-lifecycle.md): bounded
startup/operations/shutdown/reap, parent-liveness EOF, live tunnel/listener
cleanup, and phase-local exact endpoint/server-input continuity across fresh
Gateway processes.

The completed e1.6a adds a Caller phase coordinator that receives the existing
adapter-side ten-second deadline over closed private v3 control, creates an
initial plan only in an empty private root, accepts reconstruction only from a
complete retained state, starts the live Gateway, installs policy from the
caller-generated tenant IDs, and requires graceful stop, EOF, clean exit and
reap before its bounded private completion. It revalidates unchanged state
before success. That historical slice deliberately left `planned` state.

The completed e1.6b advances the operational initial path through Provider
capability and create-lifecycle composition. Controller A and B independently
load their exact mTLS and Admission credentials, require identical raw
capability bytes and the locked coding-shell selection, and persist the raw
snapshot digest, Provider revision and caller-owned policy authority. Controller
A then submits one protected create, reconciles its operation to `succeeded`
and the sandbox to generation-one `ready`, and durably binds fencing token one.
Reconstruction rediscovers the same capability authority and reads the retained
operation and sandbox without mutating the complete state. Private caller
control is v4 so its completion reports lifecycle/Gateway coordination while
explicitly disclaiming scenario results.

The e1.6c coordinator sub-slice advances the operational initial path to
`terminal_bound`. After lifecycle readiness, the caller submits one bounded
exec, reconciles its operation, reads its retained result and separate usage
evidence, and binds digests of those actual decoded documents. It then opens a
terminal session, reconciles the operation and reads the exact opaque handoff.
Session/profile/operation identities and expiry must match the caller's request
before binding. Exec and terminal dependencies are required; a lifecycle-only
client cannot silently complete this path.

Reads use the correct Contract descriptor, route and fresh Admission binding.
Only explicit retryable 503 reads with a usable Retry-After are retried within
the phase deadline. Failures preserve the last durable stage; mutations are
not automatically repeated. Local mTLS and separately built process tests use
the candidate-owned synthetic Provider. Gateway grant/expiry/revocation and
Provider-terminal byte forwarding are composed through the initial phase.
The Caller retains Provider credentials and Admission signing authority; a
one-connection private socket carries only the connected byte stream to the
Gateway child. The protected WebSocket requires the exact terminal-connect
capability, full retained descriptor digest, fresh Admission, mTLS, binary
subprotocol, message bound and handoff deadline.

The fifteen e1.7a slices execute
`initial.locked-capability-discovery` and
`initial.protected-lifecycle-create`, then `initial.replay-semantics` in one
separately supervised Caller process, followed by
`initial.lifecycle-completion-and-status`. The adapter emits each
`scenario_started` before authorizing its private command. The replay case
requires the original compact JWS/JTI to receive a closed non-retryable 409,
then signs the byte-identical logical request with a fresh JTI and requires the
same accepted operation without another runtime dispatch. The fourth case
polls the retained create operation and sandbox with fresh read Admissions,
requires `succeeded` plus generation-one `ready`, and only then commits
`lifecycle_bound` revision three. The fifth case submits the bounded output
exec, reconciles its operation, reads the retained zero-exit result and separate
usage evidence, requires an opaque stdout reference and exactly one exec-count
entry, and binds caller-computed digests of both full decoded documents at
`exec_bound` revision four. The sixth case submits a distinct exec request with
a fencing token below the accepted exec fence, requires a closed non-retryable
409 before dispatch, and leaves the complete `exec_bound` state byte-for-byte
unchanged. The seventh case starts a higher-fence cancellable exec, submits a
separate cancellation intent, and does not treat either 202 as final: it
requires the cancel operation to succeed, the target exec operation and
retained result to become `cancelled`, and the durable state to remain
unchanged. The eighth opens the planned terminal session at fence five,
reconciles the operation, validates the live bounded WebSocket handoff and
positive connection generation, and commits `terminal_bound` revision five.
The ninth starts the actual sibling Gateway, installs caller-owned tenant
policy, binds the retained Provider WebSocket backend, issues one controller-A
grant bounded by the handoff and scenario deadlines, and proves an exact
32-byte random challenge round-trip over mTLS CONNECT. It does not mutate the
`terminal_bound` revision-five state. The tenth restarts the exact sibling Gateway, issues one
controller-A/tenant-A grant, then proves both a missing-client-certificate
CONNECT and controller B's attempted use of that grant are rejected before the
Provider terminal backend opens. It also leaves `terminal_bound` revision five
unchanged.

The eleventh restarts the same sibling Gateway, issues a deliberately
short-lived controller-A grant bounded by the retained Provider handoff, and
uses one CONNECT attempt. It first completes a fresh random 32-byte echo while
the grant is live, then requires a non-timeout connection close at the grant
deadline and observes no response bytes after a post-expiry probe. The durable
`terminal_bound` revision-five state is unchanged.

The twelfth again opens one controller-A tunnel and proves a fresh random
32-byte round trip before sending one caller-owned revocation control write.
The acknowledgement is accepted only after the Gateway has closed the active
connection; a post-revocation probe receives no bytes. It leaves
`terminal_bound` revision five unchanged.

The thirteenth stages the exact 24-byte file created by the earlier output exec.
The Caller owns its artifact reference, source path, media type, expected digest
and exact size bound; it accepts neither the `202` nor the later operation read
as final evidence. Only a correlated `artifact_stage` success followed by a
non-expired `staged` evidence document with all three checks passed and exact
content metadata advances durable state to `initial_complete` revision six.
The retained evidence binding is the Caller-computed RFC 8785 digest of the full
decoded evidence document; the Provider's own `evidence_digest` remains an
opaque field in that preimage.

The fourteenth case reuses that exact logical artifact request under a fresh
controller-B Admission bound to tenant B. The Provider must reject the tenant-A
sandbox mutation with closed `403/SANDBOX_FORBIDDEN` before artifact dispatch,
then conceal the retained artifact operation behind
`404/SANDBOX_NOT_FOUND`. Neither rejection changes the durable
`initial_complete` revision-six state or exposes backend references.

The fifteenth case deliberately sends a fresh controller-A-signed Admission
over controller B's admitted mTLS connection. The Provider requires the two
caller identities to agree and returns the locked closed
`403/SANDBOX_FORBIDDEN` before a sandbox state read. The adapter now reports all
15 initial cases `completed` and finishes the local initial invocation
`completed`; durable state remains `initial_complete` revision six.

The first reconstruction case starts fresh adapter, Caller and Gateway command
processes, opens only the retained complete caller-state file, and rediscovers
capabilities through controller A against a fresh synthetic Provider instance.
It requires the raw capability snapshot digest and Provider revision to match
the caller-owned state exactly, leaves that state byte-identical, and carries no
sandbox, operation, attempt, idempotency, fencing, session or handoff binding in
private control. The second case keeps that same new Caller and Gateway alive,
loads the retained create-operation and sandbox correlations only from the
Caller store, and uses fresh controller-A Admissions to require a succeeded
create operation plus the same generation-one ready sandbox. The retained state
remains byte-identical. The third case reads the retained exec result, usage
evidence and artifact evidence with fresh Admissions, revalidates their stable
semantics and expiration bounds, and requires Caller-computed digests of all
three full decoded documents to match revision six exactly. The local synthetic
Provider carries those same retained documents into its fresh service instance
instead of regenerating timestamps. The fourth case reads the exact retained
terminal handoff under a fresh Admission, binds it to the Caller-owned session
and raw-reference digest, and keeps the opaque reference out of public output.
The fifth case grants that authority through the same reconstructed Gateway and
performs one bounded 32-byte connection round trip. All five local
reconstruction results are now `completed`, and the retained state file remains
byte-identical. This local echo composes the connection path; only the later
independent `gateway_observer` challenge can prove same-shell continuity for
qualification.

These local Gateway results are candidate-owned composition evidence, not the
independent `gateway_observer` evidence required by qualification. There is no
release artifact, source hosting attestation,
build-system attestation, independently supervised 15+5 qualification
execution, or qualification result. The local three-process tests are not
independent process-supervisor observations. The Gateway component tests use
local certificates, loopback sockets, and a synthetic terminal backend; they
do not prove Provider-runtime interoperability or independent observations.
Local filesystem checks do not
prove that the harness preserved and never inspected the state root. The pipe
file type alone does not prove supervisor-created anonymity or
startup-before-delivery. A local repository created by the qualification
operator is not by itself third-party provenance.

The completed e1.7c process-closure checkpoint bounds both normal and failure
cleanup of the candidate-owned Caller process group to five seconds, including
descendants that retain stdout after the group leader exits. Cleanup uncertainty
is reported only as sanitized `internal_failure` with a nonzero adapter exit;
caller-start and scenario failures use their locked public codes. Local tests
also enforce the exact initial/reconstruction output order, one final terminal,
final LF, record/aggregate size limits and absence of caller-private
correlations. The retained caller-state file is intentional. Provider/runtime
namespace teardown and the three stable zero-resource samples remain
operator-owned qualification evidence and are not claimed here.

The local portion of e1.8a adds a content-addressed candidate release bundle.
It archives the exact Git-visible source with deterministic metadata, embeds
the archive SHA-256 as the immutable Caller/Adapter/Gateway `source-revision`,
rebuilds the three executable artifacts from two separate archive extractions,
and requires byte-identical outputs. A canonical self-digesting manifest binds
the authority lock, source archive, exact Go toolchain and build commands, and
all raw executable digests; a strict verifier detects retained-byte changes.
See [`docs/release-artifacts.md`](docs/release-artifacts.md).

That manifest is intentionally marked qualification-ineligible. Private hosted
run `35067554697` built and uploaded the exact `32bfb5fd...` Linux/amd64 bundle,
which was downloaded and passed the strict verifier. GitHub then rejected the
attestation because user-owned private repositories do not support that
feature. The final e1.8a provenance gate therefore remains open until the
repository is explicitly made public (or an equivalent independent attestor is
provided). Qualification supervisor observation remains a later external gate.

## Verify the locked inputs

The repository uses Go from mise and has no dependency on the Provider module:

```bash
mise exec -- go test -race -shuffle=on -count=1 ./...
mise exec -- go vet ./...
mise exec -- go run ./cmd/verify-authority \
  -provider-source-root ../sandbox-runtime
```

The last command reads only the public files named in `authority.lock.json`.
Against the adjacent Provider source, it currently passes with mise Go 1.26.5
and explicitly claims no external artifact or qualification result.
The command-level tests launch the local adapter/Caller capability case against
a test-only local mTLS Provider surface, as well as the historical actual Gateway
serving entry point. Provider/Gateway component and test-child byte tests use
loopback TLS and synthetic behavior. None establishes live runtime Provider
interoperability or an
external-caller qualification result.
