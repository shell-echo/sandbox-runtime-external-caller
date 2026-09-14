# Private credential channels

These formats belong only to this external-caller candidate. They are not part
of the repository-owned Provider Contract, are not stable Provider wire DTOs,
and must never appear in qualification evidence.

## Fixed startup requirements

The adapter declares exactly these eight requirements, in this order:

| Channel ID | Protocol role | Actor | Media type | Maximum bytes |
| --- | --- | --- | --- | ---: |
| `provider-controller-a` | `provider_credentials` | `controller_a` | `application/vnd.shell-echo.sandbox-provider-client-credentials-v1+json` | 262144 |
| `provider-controller-b` | `provider_credentials` | `controller_b` | `application/vnd.shell-echo.sandbox-provider-client-credentials-v1+json` | 262144 |
| `provider-same-ca-unadmitted` | `provider_credentials` | `same_ca_unadmitted` | `application/vnd.shell-echo.sandbox-provider-client-credentials-v1+json` | 262144 |
| `provider-trust` | `provider_trust` | `null` | `application/pem-certificate-chain` | 262144 |
| `gateway-controller-a` | `gateway_credentials` | `controller_a` | `application/vnd.shell-echo.sandbox-gateway-client-credentials-v1+json` | 262144 |
| `gateway-controller-b` | `gateway_credentials` | `controller_b` | `application/vnd.shell-echo.sandbox-gateway-client-credentials-v1+json` | 262144 |
| `gateway-trust` | `gateway_trust` | `null` | `application/pem-certificate-chain` | 262144 |
| `gateway-server` | `gateway_credentials` | `null` | `application/vnd.shell-echo.sandbox-gateway-server-credentials-v1+json` | 262144 |

The upstream protocol allows up to eight declared channels. e1.5e.2 activates
the server requirement defined in
[`gateway-server-identity.md`](gateway-server-identity.md). Seven-channel
invocations, extra descriptors and changed ordered projections fail closed.

The ordered projection must exactly match the invocation descriptors. Each
descriptor must identify a unique inherited readable pipe. Every payload is
read through EOF once, subject to both its declared limit and the protocol's
4 MiB total limit. The process closes each descriptor after reading it.

A descriptor's file type can establish that it is a pipe, but cannot by itself
prove that the supervisor created an anonymous pipe. That provenance and the
required startup-before-delivery order remain process-supervisor evidence.

## Provider credential document

The Provider credential media type carries one closed UTF-8 JSON object:

```json
{
  "format_version": 1,
  "credential_type": "sandbox-provider-client-credentials-v1",
  "actor": "controller_a",
  "controller_subject": "spiffe://provider/controller-a",
  "certificate_chain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
  "admission": {
    "issuer": "https://caller.example.test/control",
    "provider_instance_audience": "urn:shell-echo:sandbox-runtime:provider-instance:provider-1",
    "key_id": "caller-key-1",
    "ed25519_private_key_base64url": "..."
  }
}
```

All seven top-level members, including `admission`, are required. `actor` is
exactly `controller_a`, `controller_b`, or
`same_ca_unadmitted`, and must equal the selected channel actor. The first two
actors require the complete `admission` object. The unadmitted actor requires
`admission: null`, so it cannot mint a protected-operation bearer.

The client leaf must be currently valid, non-CA, usable for digital signature
and client authentication, and contain exactly one absolute URI SAN without a
fragment. That URI must exactly equal `controller_subject`. The Admission key
is an unpadded canonical base64url Ed25519 private key. Duplicate, unknown,
missing, invalid, or trailing JSON data is rejected.

The Provider trust channel contains one or more header-free `CERTIFICATE` PEM
blocks and no other PEM block type. The caller constructs a no-proxy HTTP
transport with TLS 1.2 as its minimum, the Provider origin hostname as TLS
server name, this root pool, and exactly the selected client certificate.

## Gateway credential document

The Gateway credential media type carries a separate closed UTF-8 JSON object:

```json
{
  "format_version": 1,
  "credential_type": "sandbox-gateway-client-credentials-v1",
  "actor": "controller_a",
  "controller_subject": "spiffe://gateway/controller-a",
  "certificate_chain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
}
```

All six fields are required. `actor` is exactly `controller_a` or
`controller_b` and must equal the selected fixed channel. The same client-leaf
and trust-bundle checks described above apply. The resulting Gateway TLS config
uses the endpoint hostname for verification, TLS 1.2 or newer, exactly the
selected client certificate, and HTTP/1.1 ALPN. This candidate supports the
profile's HTTPS Gateway endpoint option; a `wss` endpoint fails closed.

The two Gateway client credential channels and their trust channel configure only
caller-private mTLS. Their contents do not define the controller-to-tenant
policy, issue a terminal grant, or carry any Provider/runtime correlation.

## Gateway server identity

The `gateway-server` secret document is defined by the six-field table in
[`gateway-server-identity.md`](gateway-server-identity.md). The loader rejects
unknown/missing/duplicate members, oversized input, malformed/trailing PEM,
multiple keys, non-Ed25519 server keys, extra/wrong SANs, non-server or ambiguous
EKUs, invalid dates, non-CA trust anchors and untrusted chains. Each certificate
list is bounded to eight certificates, with duplicates rejected. Only supplied
trust anchors are used; no default roots or issuer network lookup is enabled.

Caller validation also binds both Gateway client subjects and client chains to
the server document's subject pins/client roots and rejects shared Gateway keys
or reuse with Provider TLS/Admission keys. e1.6b now builds Provider authority
and clients from those same exact bundle entries; each access is closed after
the phase and clears owned key references on a best-effort basis.
The serving Gateway receives only the new server credential and `gateway-trust`
through two new pipes. It independently validates its server identity and
clears its parsed key before returning `server_identity_validated_no_listener`.
No client key, Provider key or Admission signer is forwarded to that process.

## Security boundary

These payloads contain credentials but no sandbox, operation, attempt,
idempotency, fencing, runtime-session, or handoff correlation fields. They are
not persisted, logged, placed in argv or environment, or written to the
evidence root. In-memory byte zeroing is best-effort only; phase process exit is
the hard lifetime boundary.

The private Gateway protocol and grant boundary are described in
[`gateway.md`](gateway.md).
