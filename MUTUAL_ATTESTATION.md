# Mutual Attestation (Single Round Trip)

The base SDK proves one direction: the client verifies that the server is a
genuine TEE running approved software. Mutual attestation proves the other
direction too, so a server can refuse to answer anything but a confidential
client.

It costs **one round trip** — the same `/_attest-connection` request the
server-only flow already makes.

---

## The exchange

```text
Client (TEE)                                        Server (TEE)
|                                                              |
| [1] Standard TLS 1.3 handshake                               |
|<============================================================>|
|                                                              |
+--[2] Refuse unless the session is TLS 1.3                    |
+--    EKM = export_keying_material("EXPORTER-Channel-Binding", 32)
+--[3] Proof_client = Sign(K_client, {SHA256(EKM), SHA256(T_client),
|                                     role=CLIENT, mode=MUTUAL, version=1})
|                                                              |
| [4] POST /_attest-connection { mode=MUTUAL, Proof_client }   |
|------------------------------------------------------------>|
|                                 +--[5] Check request & TLS 1.3 (else 400),
|                                 |      then derive the EKM independently
|                                 +--[6] Verify Proof_client, else 403
|                                 +--[7] Proof_server = Sign(K_server, {...,
|                                 |         role=SERVER, mode=MUTUAL})
|                                                              |
| [8] { Proof_server, mode=MUTUAL, mutual_attestation_complete }|
|<------------------------------------------------------------|
|                                                              |
+--[9] Verify the echoed mode, then verify Proof_server        |
|                                                              |
| [10] Verified E2E encrypted application data                 |
|=============================================================>|
```

The server verifies the client's proof **before** producing its own, so a
client that fails policy never receives a fresh server attestation.

The requests and responses use the existing `AttestConnectionRequest` and
`AttestConnectionResponse` messages. A mutual request sets `mode=MUTUAL`,
`protocol_version=1`, and `client_attestation`, and leaves `nonce` empty. A
mutual response echoes `mode` and `protocol_version` and sets
`mutual_attestation_complete`.

---

## Why there are no nonces

Both peers bind to the TLS **Exported Keying Material** (RFC 5705) using the
RFC 9266 `tls-exporter` channel binding label (`"EXPORTER-Channel-Binding"`) and
*no context*. In TLS 1.3 (RFC 8446, section 7.5),
no context and an empty context (`b""`) give the same keying material, so a peer
in another language may use either. In TLS 1.2 they differ.

The EKM is derived from the TLS handshake secret, which is derived from both
peers' handshake randoms. It is therefore already unique to this session and
unforgeable without the session keys — it *is* the freshness challenge. A
client nonce would add nothing the handshake did not already provide, and a
server nonce would force a second flight to carry it.

Removing the nonces is what collapses the exchange to one round trip. It also
removes the per-connection handshake state the server would otherwise have to
keep between flights.

### Mutual mode requires TLS 1.3

The argument above holds for TLS 1.3, where every exporter value comes from a
fresh ephemeral key exchange and both handshake randoms. A TLS 1.2 exporter is
unique to the session only when both peers use the extended master secret
(RFC 7627). Without it, an attacker in the middle can make two TLS 1.2 sessions
with the same keying material (the triple handshake attack), and then relay a
proof from one session to the other. Python's `ssl` module cannot tell whether
a TLS 1.2 session used the extended master secret.

So both peers check `version()` on the TLS socket before the mutual exchange:

* **Client:** if the session is not `TLSv1.3`, the connection raises
  `AttestationHandshakeError` before it exports the EKM or signs its proof.
  Nothing is sent.
* **Server:** if a mutual request arrives over a session that is not
  `TLSv1.3`, the server answers `400` before it verifies the client proof or
  produces its own. The client gets no server proof.

Server-only mode does not change: it binds to a fresh client nonce as the EKM
context, and it continues to accept the TLS versions that it accepted before.

### What replaces the nonces

Because both peers now sign over the *same* value, three fields inside
`SessionSignaturePayload` do the work the separate nonces used to:

| Field | Purpose |
| :--- | :--- |
| `peer_role` | `CLIENT` or `SERVER`. Stops a proof from being reflected back and accepted as the other side's proof. |
| `mode` + `protocol_version` | Pins the semantics of the binding, so a server-only proof cannot satisfy a mutual check (and vice versa). |

All three are absent from the wire for server-only proofs, so the existing
signed payload is byte-for-byte unchanged.

Because `"EXPORTER-Channel-Binding"` is a shared RFC 9266 label, any other
`tls-exporter` protocol sharing the same TLS session derives the same bytes.
Cross-protocol separation therefore depends on signing `SessionSignaturePayload`
with dedicated keys: `KeyManager` keys must sign only SDK attestation payloads
and must not be reused to sign other application data.

---

## No revalidation: a session is attested exactly once

The EKM is constant for the lifetime of a TLS session. Re-attesting that
session would re-sign an identical payload and prove nothing new — there is no
fresh challenge left to answer.

So mutual sessions are **not** revalidated:

* **Client:** `revalidate_session()` raises, and the lazy revalidation timer is
  disabled. Passing `revalidation_timeout` alongside `mutual_attestation` to
  `PromptEncryptionClient` is a `ValueError`.
* **Server:** any further `/_attest-connection` on a mutually attested
  session, mutual or server-only, is refused with `403 Forbidden` and
  `Connection: close`, and the session's authorization is revoked so no further
  application traffic is served on it. The server tracks mutually attested
  sessions in a `weakref.WeakSet`, so an entry disappears with its socket.

To re-attest — after a key rotation, or when the attestation token nears
expiry — **open a new connection**. The new TLS session brings a new EKM and
therefore a genuinely fresh challenge.

A *failed* exchange does not consume the session: on a failed client check, the
server returns `403` without `Connection: close` and leaves the session
unmarked, so a rejected client may retry on the same connection. Retrying on
the same connection deviates from RFC 9266 section 4.1, which forbids reusing
the channel binding across more than one authentication instance on a given TLS
connection. This deviation is safe here because the server verifies the client
before signing and emits no server proof on failure, so a failed attempt
exposes no server signature over the channel binding.

---

## Session lifetime: the connection dies with the peer's token

The EKM binding never decays, but the evidence behind it does. A GCA attestation
token says the peer was policy-compliant when the token was issued, and it says
nothing after its `exp`. So each peer records an expiry time when it authorizes
the connection, and stops using the connection at that point.

* **Server:** records the `exp` claim of the client's verified token. The
  middleware keeps it per TLS socket in a `weakref.WeakKeyDictionary`. When a
  request arrives at or after that time, the server answers `401 Unauthorized`
  with `Connection: close` and drops the session's authorization.
* **Client:** records the earlier of the server token's verified `exp` and its
  own token's `exp`. The connection pool retires the connection 60 seconds
  before that time, so the next request opens a fresh TLS connection and
  attests over it the ordinary way. There is no separate renewal protocol.

The 60-second margin also absorbs clock skew between the two TEEs: the client
stops using the connection before the server's clock reaches the client
token's `exp`, as long as the clocks differ by less than 60 seconds minus the
request time. If the skew is larger, the server answers `401` with
`Connection: close`, and the client's next request opens a new connection.

In server-only mode the server holds no client evidence, so there is nothing for
it to expire. That mode keeps its existing client-side revalidation.

Two consequences worth stating plainly:

* **Expiry is enforced per request.** A request admitted before the token
  expires runs to completion, however long it takes; expiry blocks the
  *next* request on that connection. The effective bound is the token's `exp`
  plus the duration of the last request admitted before it.
* **The `TokenManager` refresher must be running** (`with token_manager:`).
  It refreshes synchronously on startup and at 90% of the token's lifespan,
  which is what keeps a presented token at least 10% away from expiry — roughly
  6 minutes for a 60-minute token. Without the refresher there is no such floor,
  and connections inherit whatever validity is left on a stale token.

---

## The trade-off: the client shows its evidence first

Collapsing to one round trip means the client cannot verify the server before
sending its own proof. Whoever terminates the TLS session sees the client's GCA
attestation token — its platform and workload measurements — even if that peer
then fails the client's policy check.

What limits the exposure:

* The evidence travels **inside** the TLS tunnel, after the client has already
  validated the server's certificate in the normal handshake. It is not visible
  to network observers. This holds only if the client verifies the
  certificate: in mutual mode, do not pass `verify=False` or `CERT_NONE`, or a
  network attacker can terminate TLS and read the client's evidence before
  the server's attestation fails.
* The client's proof is signed over **this session's** EKM, so a peer that
  harvests it cannot replay it on any other connection.
* `peer_role` is `CLIENT`, so the harvested proof cannot be turned around and
  presented as a server proof either.

What it costs: a peer holding a valid certificate for the endpoint learns the
client's measurements before proving it is a TEE. If your threat model treats
those measurements as secret from a certificate-holding-but-unattested peer,
prefer a two-flight exchange where the server proves itself first — at the cost
of the extra round trip and the per-connection handshake state it requires.

---

## Usage

### Server

```python
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import run_uvicorn_app  # or run_gunicorn_app

client_policy = attestation_pb2.AttestationPolicy(
    hw_model=attestation_pb2.HARDWARE_MODEL_TDX,
    workload=attestation_pb2.WorkloadPolicy(
        image_hash="sha256:YOUR_EXPECTED_CLIENT_IMAGE_HASH"
    ),
    gce_instance=attestation_pb2.GceInstancePolicy(project_id="your-project"),
    confidential_space=attestation_pb2.ConfidentialSpacePolicy(
        require_debug_disabled=True,
        require_secboot=True,
    ),
)

run_uvicorn_app(
    app,
    client_policy=client_policy,
    # Omit to keep accepting server-only clients as well.
    require_mutual_attestation=True,
    host="0.0.0.0",
    port=8443,
    ssl_certfile="server.crt",
    ssl_keyfile="server.key",
)
```

### Client

The client needs its own TEE identity — the same `TokenManager` the server
uses, rotating its own keys and fetching its own attestation token.

```python
from prompt_encryption_sdk.client import PromptEncryptionClient
from prompt_encryption_sdk.server import KeyManager, TokenManager

token_manager = TokenManager(key_manager=KeyManager())

with token_manager:  # Starts background key and token rotation.
    client = PromptEncryptionClient(
        server_policy,
        mutual_attestation=True,
        client_token_manager=token_manager,
    )
    with client.session() as session:
        response = session.post("https://server:8443/infer", json=payload)
```

If the same process also runs a mutual server, reuse that server's
`TokenManager` instead of entering `with token_manager:` a second time;
otherwise give the client its own `KeyManager` paths and
`attestation_token_path`, because the defaults are fixed paths (`/dev/shm/*`
and `attestation_token.txt`).

`prompt_encryption_sdk.server` imports lazily, so a client can use
`KeyManager` and `TokenManager` without installing the server extras.

---

## Failure modes

| Situation | Result |
| :--- | :--- |
| Server answers a mutual request in server-only mode | Client raises `AttestationHandshakeError` — no silent downgrade |
| Session is not TLS 1.3 | Client raises `AttestationHandshakeError` before it sends its proof; a server that gets a mutual request anyway answers `400` (`"Invalid attestation request."`) with no server proof |
| Client proof fails policy or signature check, or its token is expired | Server answers `403` (`"Client attestation failed."`); no server proof is produced; the client raises `AttestationHandshakeError` |
| Client proof is bound to a different TLS session | Signature check fails (`403` `"Client attestation failed."`); the EKM does not transfer |
| Server proof replayed to the server as a client proof | Signature check fails (`403` `"Client attestation failed."`); `peer_role` differs |
| Server-only client reaches a `require_mutual_attestation` server | `400` (`"Invalid attestation request."`) before any proof is produced; the client raises `AttestationHandshakeError` |
| Mutual request omits `client_attestation` | `400` (`"Invalid attestation request."`); no server proof is produced; the client raises `AttestationHandshakeError` |
| Mutual client reaches a server without `client_policy` | `400` (`"Invalid attestation request."`); the client raises `AttestationHandshakeError` |
| Mutual request carries a `nonce` | `400` (`"Invalid attestation request."`); the peers must derive the same binding |
| Malformed request body, or unsupported mode, protocol version, or verifier | `400` (`"Invalid request"` or `"Invalid attestation request."`); details stay in the server logs |
| Attested session re-attests | `403`, connection closed, authorization revoked |
| Peer's attestation token expires | `401`, connection closed, authorization dropped; the client opens a new connection |
| Server fault (missing keys or token, or EKM export failure) | `500` (`"Internal server error."`); details stay in the server logs |

---

## Wire compatibility

Every new proto field is added, none renumbered. `AttestationMode`'s zero value
is `SERVER_ONLY`, so an existing client's request parses as before and its
signed payload is unchanged. A server built from this SDK keeps serving
server-only clients unless `require_mutual_attestation` is set.
