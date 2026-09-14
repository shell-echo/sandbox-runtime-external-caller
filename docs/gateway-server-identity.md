# Gateway server identity supply v1

Status: e1.5e.1 definition, e1.5e.2 credential implementation, e1.5e.3 local
serving boundary, e1.5e.4 lifecycle supervision and e1.6a Caller composition
complete. Commands declare eight channels. The operational external caller now
selects the separately identified [live service protocol](gateway-service-control.md)
through the runner documented in
[`gateway-service-lifecycle.md`](gateway-service-lifecycle.md).

## Authority and the seven-channel correction

The public adapter protocol pinned by `authority.lock.json` permits **one to
eight** credential channels, including `gateway_credentials` with `actor:
null` and a candidate-selected media type. See the locked public
`adapter-protocol.schema.json` definitions `channelRequirement` and
`channelDescriptor`, and `adapter-protocol.semantics.json` sections `limits`,
`credential_channels`, and `invocation.location_policy`.

Seven channels were the e1.5d candidate declaration, not a public maximum.
The earlier description of a "locked seven-channel public startup contract"
was incorrect. An undeclared descriptor is forbidden; an explicitly declared
eighth credential channel fits the existing protocol. This decision changes
neither Provider wire DTOs nor upstream schema/semantic authority.

## Decision and declaration

The candidate appends the requirement in
[`protocol/gateway-server-channel-v1.json`](protocol/gateway-server-channel-v1.json)
after the original seven ordered requirements:

| Field | Required value |
| --- | --- |
| `channel_id` | `gateway-server` |
| `role` | `gateway_credentials` |
| `actor` | `null` (service identity, not a controller) |
| `media_type` | `application/vnd.shell-echo.sandbox-gateway-server-credentials-v1+json` |
| `max_bytes` | `262144` |

The resulting declared maximum is 8 * 262144 = 2097152 bytes, below the public
4194304-byte aggregate limit. The ninth channel is invalid. File descriptors
are assigned by each process parent; they are absent from startup requirements
and matched through the invocation/control descriptors. No fixed hidden FD is
an alternative delivery path.

e1.5e.2 activates the declaration, exact matching, secret loader and child
forwarding together. A historical seven-channel binary must continue
rejecting an eighth descriptor, and an eight-channel serving binary must
reject seven-channel input. There is no optional server credential, implicit
downgrade, payload sniffing, or automatic certificate generation on missing
input. The same binary identities and eight requirements apply in both phases.

## Ownership and preparation order

The external caller owner owns this private format, server identity policy,
controller-subject policy, and Gateway authorization. The qualification
operator is the trusted credential custodian for a disposable run. It may
generate credentials from caller-approved policy or acquire them from an
authorized issuer; the adapter and caller do not supply an issuer key or
receive one. Custody is an operator role, not a fourth candidate executable or
a source of caller business state.

Before generating or acquiring credential material, the operator/supervisor
freezes and commits the profile path, Provider origin, static Gateway endpoint,
caller-state root, working directory, and candidate artifact/configuration
identities under the existing preflight rules. The endpoint selects the server
certificate SAN; a certificate must never select or rewrite the endpoint.
Controller subjects are fixed credential identities, never encodings of
sandbox, operation, attempt, idempotency, fencing, runtime-session, or handoff
values. Preflight must also arrange network reachability of that fixed endpoint.

After that commitment, the custodian obtains a Gateway server leaf/key, two
distinct Gateway controller leaves/keys, a server trust bundle, and a client
trust bundle. Server and controller keys must be distinct, and Gateway keys
must not reuse Provider or Admission signing keys. CA signing keys stay with
the issuer. Only leaf keys travel through credential pipes. The custodian
retains the exact phase inputs privately in memory through reconstruction.
Loss of that custody aborts the run; v1 has no disk-cache recovery or key export
to `caller_state_root`, the working directory, or the evidence root.

The supervisor creates the declared pipes, starts the adapter with empty argv
and its existing environment policy, validates the complete startup identity,
then delivers the one invocation and EOF-framed credential payloads. No input
or credential byte is delivered before startup. The adapter forwards the exact
eight payloads to the caller through new pipes; control JSON contains only
descriptors and the existing permitted locations/phase.

## Secret document and cryptographic checks for e1.5e.2

The server credential pipe carries exactly one bounded strict UTF-8 JSON
document followed by EOF. JSON is an encoding on this **secret pipe**, not on
stdin control or stdout. Every top-level member below is required; unknown,
duplicate, missing, null, trailing, or oversized data is invalid:

| Member | Meaning |
| --- | --- |
| `format_version` | Integer `1` |
| `credential_type` | `sandbox-gateway-server-credentials-v1` |
| `certificate_chain_pem` | Server leaf first, followed by issuer certificates |
| `private_key_pem` | Exactly one header-free, unencrypted PKCS#8 `PRIVATE KEY` block, Ed25519 |
| `client_ca_certificates_pem` | Certificate-only trust anchors for Gateway client authentication |
| `controller_subjects` | Closed object with required, distinct `controller_a` and `controller_b` absolute URI strings |

`controller_subjects` must match the subjects in the two existing Gateway
client credential documents and their single URI SANs exactly. It is not a
controller-to-tenant mapping. Tenant and terminal authorization remain
caller-owned state and must not be supplied by the credential custodian.

The separate existing `gateway-trust` payload supplies **server** trust
anchors. `client_ca_certificates_pem` supplies **client** trust anchors. These
are distinct trust purposes even if an operator deliberately uses one CA for
both. A server leaf must chain to the injected server roots; both controller
leaves must chain to the injected client roots. Never silently add a supplied
leaf or intermediate to a trust-root pool, use OS default roots, or fetch
missing issuers from the network.

The server leaf must have a matching Ed25519 key, be non-CA and currently valid,
permit digital signatures, and have exactly the server-auth extended usage
(no client-auth, any-usage, or unknown usage). Its SAN must contain exactly the
static endpoint DNS hostname or IP address, with no wildcard, alternative name,
URI SAN, email SAN, or Common Name fallback. The serving candidate accepts
HTTPS only; WSS input fails closed. All chains must be usable for their selected
purpose. PEM material allows only the stated block types, no headers or
non-whitespace trailing text, and no additional private key. Each certificate
list is limited to eight distinct certificates; supplied chains must be in
leaf-to-issuer order. A leaf cannot substitute for a trust anchor.

Issuer policy must give the inputs validity covering the run's remaining
execution and cleanup budgets. The loader rechecks validity on each phase;
the serving Gateway must stop accepting and close active tunnels at the
earliest relevant expiry or phase deadline. No hot reload, trust expansion,
or in-run identity rotation is permitted. Rotation requires ending the run and
preparing a new run with newly committed configuration and startup identities.

The implemented loader checks validity at load time and returns `ExpiresAt`
covering the loaded server chain and trust anchors. Enforcing the remaining
run budget and live connection expiry belongs to the serving/coordinator
checkpoints; successful loading alone does not establish that lifetime.

## Least-privilege caller-to-Gateway delivery

The caller validates server material against `gateway-trust`, validates both
controller identities against the server document's client roots and subject
pins, and checks key separation before requesting service startup. The
Gateway independently validates its received server material and server trust.

The caller forwards only `gateway-server` and
`gateway-trust`, in that order, through two new readable anonymous pipes. The
former e1.5d.3 three-client-channel Gateway bootstrap is replaced atomically
with a new private control protocol identity in e1.5e.2. Provider credentials,
Admission signing keys, and both Gateway **client private keys** must not be
inherited by the serving Gateway. All unrelated descriptors are close-on-exec.

Private bootstrap control remains credential- and correlation-free. Later
caller-owned authorization commands may carry the caller's own tenant/session
bindings over a separately specified private control boundary; this standard
does not prohibit that necessary control path or permit harness reinjection.
An identity-valid server must deny every tunnel until that caller policy is
installed. Certificates alone cannot create tenants, issue grants, or resolve
an opaque terminal handoff.

## Restart, lifetime, destruction, and evidence

On reconstruction the supervisor starts fresh phase processes, reuses the same
static endpoint, startup declarations, and exact credential bytes, and delivers
them only through fresh pipes after startup. The caller's complete correlation
state remains separate and unread by the harness. Credential continuity is
checked privately by the custodian and caller; secret bytes or secret-derived
fingerprints must not be added to public adapter output or report fields.

The finite e1.5d bootstrap exits after consuming input. A serving Gateway must
instead stay alive for the caller's phase under the inherited absolute
deadline, with separate bounded startup and shutdown budgets. Readiness must
mean that validation, TLS configuration, fixed-endpoint bind, and serving-loop
startup succeeded; it must never reuse the current `no_listener` result as
proof of service. Authentication/grant failures do not extend any deadline.

e1.5e.4 proves locally that cancellation or death of the caller closes
the Gateway and every accepted/hijacked connection. Independently killing
only the caller's process group does not cover a Gateway in a different group;
the serving design needs parent-liveness signaling and supervisor ownership
of all child groups. Reap must stay inside the locked termination budget.
The existing bootstrap tests are not evidence for that long-lived behavior.

After each forwarding or loading operation, clear temporary secret buffers
when they are no longer needed and close the pipe ends. The TLS server needs
its parsed key for its bounded lifetime; clearing a source byte buffer does
not erase that parsed object. Teardown closes listeners and all tunnels,
cancels work, terminates and reaps the processes, and discards custodian input
copies after reconstruction or terminal abort. Go memory clearing is best
effort; v1 makes no secure-erasure, anti-debugging, swap, core-dump, or
same-UID hostile-process secrecy claim.

All errors use bounded fixed codes at the private boundary, mapped to existing
public failures when needed. No PEM, secret document, raw parse/TLS error,
endpoint, controller-subject dump, or key hash enters stdout/stderr/evidence.
The operator's allowed credential custody neither proves source independence
nor authorizes it to construct or sign the caller's Provider requests. A local
declaration test proves neither original request attribution nor qualification.

## Threats and acceptance gates

| Threat/input | Required outcome | Evidence in this slice |
| --- | --- | --- |
| Missing server channel, legacy seven-channel invocation or three-client-channel Gateway input | Reject before opening credential FDs | Exact matching and v2 control tests |
| More than eight channels, invented role/actor, repeated channel or FD | Reject | Public-codec declaration tests |
| Changed role, actor, media type, limit, or descriptor order | Reject | Exact matching tests |
| Key material or forbidden correlations inserted in invocation/private control | Reject as unknown input | Decoder negative tests with synthetic markers |
| Server identity supplied through a client credential document | Reject | Existing client decoder negative test |
| Missing server key, wrong key/SAN/EKU/chain, expired identity, forged subject pins or key reuse | Reject before readiness/bind | e1.5e.2 loader/binding tests and actual invalid-identity command test |
| Real file, repeated consumption, undeclared descriptor, short/truncated/oversized secret, blocked writer | Reject or bounded terminate/reap | Shared reader and server codec tests; actual Gateway blocked-write timeout/reap test |
| Unauthenticated or cross-tenant connection | No backend resolution | e1.5e.3 service-child probes and exact resolver-invocation count |
| Rotation, lost custody, stale phase or changed endpoint during restart | Abort; no fallback/rekey | e1.5e.4 phase-local exact-input/endpoint restart tests; cross-phase custody remains external |
| Parent death or deadline while a tunnel is live | Close tunnel/listener and terminate/reap as ownership permits | e1.5e.4 abrupt-Caller/deadline process tests |

The declaration fixture contains no credentials. New credential fixtures are
generated locally in test memory by `internal/testcredentials`; a source test
forbids importing that helper into runtime code. Three-process tests now supply
valid or intentionally malformed server identities. Those three-process bootstrap
tests do not bind a listener; separate e1.5e.3 Gateway process tests now do.
No test sends a real Provider request. Operator custody, cross-phase
credential equality, hostile-process secrecy and actual issuer provenance
remain external obligations, not claims from these tests.
