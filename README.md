# sandbox-runtime external caller candidate

This is a clean-room candidate consumer of the repository-owned
`sandbox-runtime` Provider Contract. It is a separate Git repository and may
use generated code from the locked public Contract, but it must not import or
copy Provider implementation packages or either repository's reference E2E
caller.

The remaining work is tracked in [`docs/PLAN.md`](docs/PLAN.md): 6 of 13
checkpoints are complete; 7 remain. The next checkpoint is e1.6c.

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

There is still no Provider exec, terminal or handoff scenario execution, release
artifact, source hosting attestation, build-system attestation, 15+5 execution,
or qualification result. The local three-process tests are not independent
process-supervisor observations. The Gateway component tests use local certificates, loopback
sockets, and a synthetic terminal backend; they do not prove Provider-runtime
interoperability or independent observations. Local filesystem checks do not
prove that the harness preserved and never inspected the state root. The pipe
file type alone does not prove supervisor-created anonymity or
startup-before-delivery. A local repository created by the qualification
operator is not by itself third-party provenance.

## Verify the locked inputs

The repository uses Go from mise and has no dependency on the Provider module:

```bash
mise exec -- go test -race -shuffle=on -count=1 ./...
mise exec -- go vet ./...
mise exec -- go run ./cmd/verify-authority \
  -provider-source-root ../sandbox-runtime
```

The last command reads only the public files named in `authority.lock.json`.
The command-level tests launch the local all-not-executed three-process
bootstrap, a test-only local mTLS Provider surface, and the actual Gateway
serving entry point. Provider/Gateway component and test-child byte tests use
loopback TLS and synthetic behavior. None establishes live runtime Provider
interoperability or an
external-caller qualification result.
