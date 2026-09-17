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
| 7 | e1.6c | Exec, terminal, handoff, caller grant/revocation and actual backend composition | Complete (local synthetic/process composition) |
| 8 | e1.7a | All 15 locked initial cases with truthful interactions, assertions and observation references | Complete (local synthetic/process composition) |
| 9 | e1.7b | All 5 reconstruction cases with retained caller state and no harness correlation reinjection | Complete (local synthetic/process composition) |
| 10 | e1.7c | Teardown, residual resources, failure mapping and final transcript ordering/limits | Complete (candidate process closure; operator cleanup still external) |
| 11 | e1.8a | Reproducible artifacts, immutable release/source identity, build commands/digests and provenance | Complete (public hosted build and five-subject attestation verified) |
| 12 | e1.8b | Independently supervised initial/reconstruction run with live runtime and observers | Complete (hosted native Linux/Docker 15+5 run, exact 91-fact observation set and stable zero-resource teardown verified) |
| 13 | e1.8c | Closed report, receipt, independent validation and final qualification disposition | Pending |

After checkpoint 12, **1 checkpoint remains** in independent qualification:
e1.8c report/receipt/conclusion. Each of the 15+5 cases is a test obligation
within e1.8b, not an additional checkpoint in this count.

The first e1.8b prerequisite replaces the synthetic `registry.invalid` image
with the Provider-published coding/shell OCI index
`sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1`.
It remains caller-owned selection policy: the Provider does not adapt its API
for this candidate. Hosted run `35175318990` rebuilt and attested the exact
image-pinned candidate, and the downloaded bundle plus all five subjects passed
independent verification. Hosted native Linux/Docker run `35198049461`
subsequently closed the independently supervised execution and cleanup
checkpoint. The final closed report, receipt, archive validation and
disposition remain separate.

Checkpoint 7 includes the exec/result/usage/session/handoff coordinator,
caller Gateway grant/expiry/revocation, protected Provider WebSocket connector,
and a one-connection Caller-to-Gateway byte bridge. Its acceptance uses a
candidate-owned synthetic Provider and does not establish independent runtime
interoperability.

Checkpoint 8 executes capability discovery, protected lifecycle
create, both replay-semantics checks, lifecycle completion/status, exec
result/usage evidence, stale-fencing rejection, exec cancellation, terminal
session/opaque handoff, the authorized Gateway terminal byte round-trip, and
missing-caller/cross-tenant Gateway rejection, live grant expiry, active
revocation, artifact staging/evidence binding, and Provider cross-tenant
artifact mutation/operation concealment, and mTLS/JWS caller-identity mismatch
rejection in one Caller process. This completes all 15 initial cases as local
candidate composition and advances the fixed count to 8/13. It does not prove
independent runtime interoperability, observations, provenance, or qualification.

Checkpoint 9 executes reconstruction capability discovery, durable
lifecycle reconciliation, and retained exec/usage/artifact evidence reads from
the complete retained caller state in fresh adapter, Caller and Gateway command
processes. It requires exact raw capability continuity, reads the retained
create operation and generation-one ready sandbox, then recomputes and matches
the three full retained-document digests under fresh Admissions while leaving
the state file byte-identical; no forbidden Provider correlation is present in
private control. It then reads the retained terminal handoff with a fresh
Admission, validates the exact runtime-session and opaque-reference digest, and
uses the same reconstructed Gateway for one bounded authorized byte round trip.
All five results are locally completed while the state file remains
byte-identical. The candidate-owned synthetic Provider and Gateway establish
local composition only; they do not supply the independent observer evidence
required to prove same-shell continuity or qualification.

Checkpoint 10 closes the candidate-owned process boundary. Adapter failures
map caller start, scenario and cleanup uncertainty onto the locked public code
set without private diagnostics. Caller stdout and process waiting proceed
concurrently; both graceful completion and abort are bounded to five seconds
and kill/reap the caller's private process group, including descendants that
outlive the group leader. Exact initial and reconstruction record counts,
sequence, phase, terminal position, final LF and aggregate/per-record limits
are locally tested, as is absence of caller-private correlations from public
output. The durable `0600` caller state is intentionally retained for
reconstruction. Provider/runtime namespace teardown, the pre-run baseline and
three stable zero-resource samples remain exclusively operator-owned evidence
for checkpoints 12-13; this checkpoint does not claim them.

Checkpoint 11 has a deterministic source archive, source-archive-derived
immutable startup identity, exact toolchain/command/environment recording,
two independent archive extractions and byte-identical rebuild enforcement,
three raw executable digests, a canonical self-digesting manifest and strict
retained-byte verifier. Exact source is public. Hosted run `35068957048` passed
tests, build, authority verification and upload for revision `58a211f0...`, then
created Sigstore/Rekor attestation `47846951` over all five retained subjects.
The downloaded bundle passed the strict verifier and each subject passed
`gh attestation verify`. The candidate manifest remains self-conservatively
qualification-ineligible; external provenance is established by the hosted
observations rather than by changing candidate-controlled flags.

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
