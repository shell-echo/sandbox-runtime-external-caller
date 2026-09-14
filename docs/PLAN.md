# Remaining delivery checkpoints

Baseline: the 13 checkpoints agreed after e1.5d.3. A checkpoint count is a
review boundary, not an equal-size effort estimate. Complete one checkpoint,
report its evidence and the next checkpoint, then wait for user confirmation.
New findings stay in the relevant checkpoint; any required plan expansion must
be explained explicitly instead of silently resetting the count.

| Number | Checkpoint | Deliverable and acceptance | State |
| --- | --- | --- | --- |
| 1 | e1.5e.1 | Gateway server identity supply standard, threat model, declaration/control negative tests | Complete (definition only) |
| 2 | e1.5e.2 | Explicit eight-channel declaration, server secret codec/validation, least-privilege pipe forwarding and failures | Complete (no listener) |
| 3 | e1.5e.3 | Real mTLS CONNECT Gateway process, readiness, authentication/authorization and local bytes | Complete (local service boundary) |
| 4 | e1.5e.4 | Gateway identity/endpoint continuity, restart, parent death, deadline and live connection cleanup | Complete (local process supervision) |
| 5 | e1.6a | Caller phase coordinator: empty initial state and complete-only reconstruction | Complete (local composition) |
| 6 | e1.6b | Provider credential, capability, lifecycle, reconciliation and durable binding composition | Complete (local composition) |
| 7 | e1.6c | Exec, terminal, handoff, caller grant/revocation and actual backend composition | Next |
| 8 | e1.7a | All 15 locked initial cases with truthful interactions, assertions and observation references | Pending |
| 9 | e1.7b | All 5 reconstruction cases with retained caller state and no harness correlation reinjection | Pending |
| 10 | e1.7c | Teardown, residual resources, failure mapping and final transcript ordering/limits | Pending |
| 11 | e1.8a | Reproducible artifacts, immutable release/source identity, build commands/digests and provenance | Pending |
| 12 | e1.8b | Independently supervised initial/reconstruction run with live runtime and observers | Pending |
| 13 | e1.8c | Closed report, receipt, independent validation and final qualification disposition | Pending |

After checkpoint 6, **7 checkpoints remain** across three stages:
caller composition (7), scenarios (8-10), and artifacts
and qualification (11-13). Each of the 15+5 cases is a test obligation within
its checkpoint, not an additional checkpoint in this count.

Checkpoint 1 corrects an earlier premise: the public adapter protocol allows
up to eight channels; the former seven were candidate-specific. The eighth
server credential channel is explicitly declared as of checkpoint 2, with
the upstream Provider/adapter authorities unchanged. See
[`gateway-server-identity.md`](gateway-server-identity.md).

mise supplies the Go toolchain. Local component and loopback checks do not
require Docker. Live runtime interoperability needs a working supported runtime
before the relevant integration checks and checkpoint 12 can pass; changing
runtime drivers is not an implicit part of this plan. External source/build
ownership and observer/credential custody must also be available for the final
qualification gates. Commits, pushes, hosted builds, qualification runs and
evidence publication retain their separate authorization boundaries.
