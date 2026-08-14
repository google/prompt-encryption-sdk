# Mutual Post-Handshake Attested TLS

## Goal and compatibility

Mutual mode ensures that application data is accepted only after both TLS
endpoints have proved that their configured workload is running in an accepted
TEE. It is an opt-in extension of the existing post-handshake protocol:

- Existing clients keep using protocol version `0` and server-only attestation.
- A client opts in with `PromptEncryptionClient(mutual_attestation=True, ...)`.
- A server enables mutual support by configuring `client_policy`.
- A server sets `require_mutual_attestation=True` to reject all legacy clients.

Mutual mode does not replace X.509 TLS or run inside the TLS 1.3 handshake. A
normal TLS connection is established first, but the middleware rejects all
application endpoints until the post-handshake exchange completes.

## Protocol version 1

Both flights use `POST /_attest-connection` inside the established TLS channel.

```text
Confidential client                         Confidential server
       |                                            |
       |---- INITIAL(version=1, mode=MUTUAL, ------>|
       |     client_nonce)                          |
       |                                            | derive server_nonce,
       |                                            | handshake_id, transcript,
       |                                            | EKM(transcript_hash)
       |<--- server proof, server_nonce, -----------|
       |     handshake_id, mode=MUTUAL              |
       |                                            |
       | verify server token, policy, keys,         |
       | role, transcript, EKM signatures           |
       |                                            |
       |---- CLIENT_FINISH(handshake_id, ---------->|
       |     client proof)                          | verify client token,
       |                                            | policy, keys, role,
       |                                            | transcript, EKM signatures
       |<--- completion acknowledgement ------------|
       |                                            |
       |==== application traffic is now allowed ====|
```

The canonical transcript is a deterministic protobuf containing:

```text
protocol_version || mutual_mode || client_nonce || server_nonce || handshake_id
```

`SHA-256(transcript)` is used as the TLS exporter context. Each peer signs a
canonical `SessionSignaturePayload` with both ECDSA P-256 and ML-DSA-65:

```text
SHA-256(EKM) || SHA-256(attestation_token) || peer_role || mutual_mode
|| SHA-256(transcript)
```

The TEE token continues to endorse fingerprints of both ephemeral public keys.
The signatures prove possession of their private keys and bind that endorsed
identity to this TLS session and this negotiation.

## Server state machine

The server stores one pending record per TLS socket after `INITIAL`. It contains
the client nonce, handshake ID, transcript hash, EKM, and creation time. The
record is:

- bound to the socket on which it was created;
- consumed before client-proof verification, so it is one-use even on failure;
- rejected after 30 seconds by default;
- never sufficient to authorize application traffic.

The middleware removes any previous authorization when a new mutual `INITIAL`
flight begins. It authorizes the socket only after a successfully verified
`CLIENT_FINISH` response is marked complete.

## Downgrade and replay analysis

The client treats mutual mode as a requirement, not a preference. It rejects an
initial response unless the peer echoes protocol version `1` and `MUTUAL`.
Those values and the complete transcript are covered by both server signatures,
so a TLS endpoint or intermediary cannot strip the negotiation and still supply
a proof valid for the client's EKM.

Servers that require client identity must set `require_mutual_attestation=True`.
Such servers reject version `0` before producing a legacy proof. Servers may
instead support both modes deliberately; that is a deployment policy choice,
not silent fallback for a client that requested mutual mode.

Replay and reflection defenses are layered:

- EKM binds every proof to one TLS session.
- Fresh nonces and the handshake ID bind both protocol flights together.
- Per-socket one-time state prevents a finish from moving to another session.
- Expiration bounds unfinished state.
- Signed `SERVER`/`CLIENT` roles prevent reflection between peers.
- Revalidation repeats the complete two-flight exchange and revokes the old
  authorization while it is in progress.

## Configuration

The confidential client supplies a populated `TokenManager` as its identity:

```python
from prompt_encryption_sdk.client import PromptEncryptionClient
from prompt_encryption_sdk.server import KeyManager, TokenManager

client_identity = TokenManager(key_manager=KeyManager())
client_identity.refresh()  # Uses UDS by default or GoTPM with ATTESTATION_TYPE=gotpm.

with client_identity:
  client = PromptEncryptionClient(
      policy=server_policy,
      mutual_attestation=True,
      client_token_manager=client_identity,
  )
  with client.session() as session:
    response = session.post("https://server.example/infer", json=payload)
```

The server configures the independent policy used to accept confidential
clients:

```python
run_uvicorn_app(
    app,
    client_policy=trusted_client_policy,
    require_mutual_attestation=True,
    ssl_keyfile="key.pem",
    ssl_certfile="cert.pem",
)
```

The WSGI `run_gunicorn_app` entry point accepts the same two parameters.

## Test boundary

The repository test suite mocks token issuance and OIDC verification because no
Confidential Space environment is available. The integration test still uses
real ECDSA and ML-DSA key generation, signatures, key-fingerprint binding,
transcript derivation, peer verification, finish handling, and reflection
failure. A future Confidential Space system test should replace only the fake
token issuer/validator and mock TLS exporter with GCA tokens and a live socket.
