# Private terminal Gateway

The terminal Gateway is owned by this external-caller candidate. Its protocol,
credentials, grant model, and control API are consumer-private behavior. They
do not extend the repository-owned Provider Contract and must not be presented
as Provider DTOs or stable Provider routes.

Server identity supply is defined in
[`gateway-server-identity.md`](gateway-server-identity.md). The command now has a
separately identified [live service entry point](gateway-service-control.md).
Its [lifecycle runner](gateway-service-lifecycle.md) is implemented, while the
adapter/caller still selects the finite validation bootstrap until coordinator
composition in [`PLAN.md`](PLAN.md).

## Tunnel endpoint

This candidate implements direct HTTP/1.1 `CONNECT` over HTTPS. Although the
locked adapter invocation permits a canonical `https` or `wss` Gateway probe
endpoint, this implementation deliberately supports only `https`. The endpoint
has one fixed, clean path and no user information, query, or fragment. Session
or qualification correlation is never encoded in the URL.

The client sends the one-use grant in exactly one `Authorization: Bearer`
header. A successful handshake returns `200 Connection Established` with no
body and then transports opaque terminal bytes in both directions. Rejected
authentication and authorization return an empty `403`; failure to resolve an
already-authorized backend returns an empty `502`. These are private transport
details, not profile evidence status codes.

The client bypasses environment proxy settings, requires TLS 1.2 or newer,
verifies the exact endpoint hostname against an injected trust bundle, presents
exactly one selected client certificate, and requires mutually negotiated
HTTP/1.1 ALPN. The explicit unauthenticated probe retains server verification
while presenting no client certificate.

## Identity and tenant policy

The server authenticates the client certificate against caller-owned trust. A
valid leaf has exactly one absolute URI SAN; its exact string is the controller
subject. The Gateway is initialized with the two expected controller subjects,
each mapped to a distinct caller-owned tenant. Neither a bearer token nor a
handoff reference can override that immutable mapping.

The server rejects a missing identity, unknown subject, subject/token mismatch,
malformed or duplicate bearer header, wrong method, wrong path, and query input
before invoking the terminal backend resolver. Consequently an unauthorized
request cannot use the opaque handoff reference to reach a runtime connection.

## Grants and live connections

The caller issues a grant only for a policy-authorized subject/tenant pair and
binds it to one runtime-session ID and one opaque handoff reference. A grant:

- contains 256 random bits encoded as canonical unpadded base64url;
- has a maximum lifetime of five minutes;
- authorizes one connection only;
- is retained only by its SHA-256 token key, never as the raw bearer; and
- is capped by a bounded 64-entry in-memory grant table.

Authorization consumes the grant and reserves a permit before the resolver sees
the opaque reference. Expiry cancels the permit and closes both tunnel sides.
Authorized revocation does the same and is acknowledged only after the permit
has finished; its caller supplies a bounded context so an uncooperative backend
cannot cause an unlimited control-plane wait. A different controller subject
cannot revoke the grant.

## Reconstruction boundary

The local integration test closes one Gateway server, reopens an
`initial_complete` caller-state store, constructs a new Gateway from the
reloaded tenant and terminal bindings, and reconnects with a fresh grant. A
synthetic stateful resolver confirms that the same opaque reference selects the
same retained terminal state.

This is component-level reconstruction evidence. It does not prove an actual
Provider terminal session, an external process restart, a harness-preserved
state root, a harness-generated continuity challenge, bounded observer byte
counts, or an independently observed profile result. Those require the future
runnable process composition and qualification harness.
