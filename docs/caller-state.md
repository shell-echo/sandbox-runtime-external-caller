# Caller-owned durable correlation state

This state belongs only to the external caller. It is not a Provider wire DTO,
an adapter-protocol message, or qualification evidence.

## Root and file boundary

The initial caller opens the invocation's `caller_state_root` only when all of
the following hold:

- the path is absolute, clean, non-root, and every existing component is not a
  symbolic link;
- the final object is the same directory before and after opening;
- the directory mode is exactly `0700`; and
- the directory is empty.

The caller then creates exactly one file,
`correlation-state-v1.json`. Each revision is encoded as canonical RFC 8785
JSON with a 64 KiB limit and written to a new `0600` file. The caller syncs the
file, atomically renames it over the prior revision, and syncs the directory.
Before every update it rereads the current file and rejects external changes.

Reconstruction requires the same root checks, exactly that one `0600` regular
file, a complete initial-stage record, stable file identity while reading, the
locked Contract/profile identity, canonical bytes, exact members, and valid
cross-bindings. A partial or ambiguous store fails closed.

## Caller-generated plan

`CreateInitial` accepts only the state-root path. It does not accept a sandbox,
operation, attempt, idempotency, tenant, work-order, session, handoff, or other
correlation value. It generates a 128-bit random suffix inside the caller for
each persisted plan identity, including distinct tenant/work-order identities
and the retained lifecycle, exec, terminal, and artifact operations.

The closed state advances exactly once through:

1. `planned`;
2. `capabilities_bound`;
3. `lifecycle_bound`;
4. `exec_bound`;
5. `terminal_bound`; and
6. `initial_complete`.

Each transition increments `store_revision` and binds only the planned
operation identity. The store retains the raw capability snapshot digest,
Provider revision, caller-owned policy digest/decision timestamp,
operation/attempt/idempotency/fencing correlations, retained
exec and usage digests, terminal runtime-session identity and opaque handoff,
and artifact evidence digest required by reconstruction. The handoff digest is
derived by the store from the raw reference rather than accepted separately.

The raw handoff remains private state because the reconstructed Gateway needs
it. It must not be copied into adapter output, logs, or evidence.

## Phase-coordinator use

e1.6a wires this store into the operational external-caller process. Before
touching the root, the coordinator requires the absolute deadline propagated
by its adapter-side process supervisor. `initial` calls only `CreateInitial`;
`reconstruction` calls only `OpenReconstruction`. The resulting caller-owned
tenant IDs install the immutable policy of a live, separately supervised
Gateway service. The coordinator then requires graceful Gateway stop, stdout
EOF, clean exit and reap and calls `ValidateUnchanged` before reporting private
phase preparation complete.

e1.6b adds the Provider phase runner. Initial discovers identical capabilities
through both controllers, binds the Provider/policy authority, creates and
reconciles the sandbox, and finishes at `lifecycle_bound`. Reconstruction
rediscovers the exact capability bytes and reads the retained lifecycle without
changing state. A failure leaves the last committed stage (`planned` or
`capabilities_bound`) in place, emits no caller completion, and makes the same
root ineligible for another initial invocation or reconstruction. The
coordinator never deletes or rolls back durable state. e1.6c must advance the
same store through exec and terminal transitions; e1.7a must perform the actual
artifact work and final transition before an initial run can produce the
complete state accepted by a later reconstruction invocation.

## Evidence limits

The open directory handle continues to address the object actually opened if
its pathname is renamed. These local checks still do not prove that the harness
created the directory, never read or modified it, or preserved the same object
between process invocations. Those are independent process-supervisor facts.

The file is permission-isolated but not encrypted. Go-managed strings and JSON
decoding also prevent a claim of guaranteed in-memory erasure. Process exit is
the hard lifetime boundary. No local state test establishes external ownership,
process separation, Provider/Gateway interoperability, or qualification.
