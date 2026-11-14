# Mutual Attestation (Single Round Trip)

The base SDK proves one direction: the client verifies that the server is a
genuine TEE running approved software. Mutual attestation proves the other
direction too, so a server can refuse to answer anything but a confidential
client.

It costs **one round trip** — the same `/_attest-connection` request the
server-only flow already makes.

---

## The exchange

```ascii
Client (TEE)                                        Server (TEE)
|                                                              |
| [1] Standard TLS 1.3 handshake                               |
|<============================================================>|
|                                                              |
+--[2] EKM = export_keying_material("EXPORTER-Prompt-Encryption-SDK", 32)
+--[3] Proof_client = Sign(K_client, {SHA256(EKM), SHA256(T_client),
|                                     role=CLIENT, mode=MUTUAL, version=1})
|                                                              |
| [4] POST /_attest-connection { mode=MUTUAL, Proof_client }   |
|------------------------------------------------------------>|
|                                 +--[5] EKM derived independently
|                                 +--[6] Verify Proof_client, else 4xx/5xx
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

---

## Why there are no nonces

Both peers bind to the TLS **Exported Keying Material** (RFC 5705), exported
with the protocol label and *no context*.

The EKM is derived from the TLS master secret, which is derived from both
peers' handshake randoms. It is therefore already unique to this session and
unforgeable without the session keys — it *is* the freshness challenge. A
client nonce would add nothing the handshake did not already provide, and a
server nonce would force a second flight to carry it.

Removing the nonces is what collapses the exchange to one round trip. It also
removes the per-connection handshake state the server would otherwise have to
keep between flights.

### What replaces the nonces

Because both peers now sign over the *same* value, two fields inside
`SessionSignaturePayload` do the work the separate nonces used to:

| Field | Purpose |
| :--- | :--- |
| `peer_role` | `CLIENT` or `SERVER`. Stops a proof from being reflected back and accepted as the other side's proof. |
| `mode` + `protocol_version` | Pins the semantics of the binding, so a server-only proof cannot satisfy a mutual check (and vice versa). |

Both are absent from the wire for server-only proofs, so the existing signed
payload is byte-for-byte unchanged.

---

## No revalidation: a session is attested exactly once

The EKM is constant for the lifetime of a TLS session. Re-attesting that
session would re-sign an identical payload and prove nothing new — there is no
fresh challenge left to answer.

So mutual sessions are **not** revalidated:

* **Client:** `revalidate_session()` raises, and the lazy revalidation timer is
  disabled. Passing `revalidation_timeout` alongside `mutual_attestation` is a
  `ValueError`.
* **Server:** a second `/_attest-connection` on a mutually attested session is
  refused with `403 Forbidden` and `Connection: close`, and the session's
  authorization is revoked so no further application traffic is served on it.

To re-attest — after a key rotation, or when the attestation token nears
expiry — **open a new connection**. The new TLS session brings a new EKM and
therefore a genuinely fresh challenge.

A *failed* exchange does not consume the session: a client that is rejected on
policy may retry on the same connection.

---

## The trade-off: the client shows its evidence first

Collapsing to one round trip means the client cannot verify the server before
sending its own proof. Whoever terminates the TLS session sees the client's GCA
attestation token — its platform and workload measurements — even if that peer
then fails the client's policy check.

What limits the exposure:

* The evidence travels **inside** the TLS tunnel, after the client has already
  validated the server's certificate in the normal handshake. It is not visible
  to network observers.
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

`prompt_encryption_sdk.server` imports lazily, so a client can use
`KeyManager` and `TokenManager` without installing the server extras.

---

## Failure modes

| Situation | Result |
| :--- | :--- |
| Server answers a mutual request in server-only mode | Client raises `AttestationHandshakeError` — no silent downgrade |
| Client proof fails policy or signature check | Server errors out; no server proof is produced |
| Client proof is bound to a different TLS session | Signature check fails — the EKM does not transfer |
| Server proof replayed to the server as a client proof | Fails — `peer_role` differs |
| Server-only client reaches a `require_mutual_attestation` server | Rejected |
| Mutual request carries a `nonce` | Rejected — the peers must derive the same binding |
| Attested session re-attests | `403`, connection closed, authorization revoked |

---

## Wire compatibility

Every new proto field is added, none renumbered. `AttestationMode`'s zero value
is `SERVER_ONLY`, so an existing client's request parses as before and its
signed payload is unchanged. A server built from this SDK keeps serving
server-only clients unless `require_mutual_attestation` is set.
