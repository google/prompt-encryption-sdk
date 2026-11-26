# Copyright 2026 The Prompt Encryption SDK Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Shared proof primitives for post-handshake attested TLS.

Both endpoints produce the same shape of proof, so the signing logic lives
here rather than in the server package. Mutual attestation is a single round
trip: the client puts its proof in the request, the server verifies it and
puts its own proof in the response.

In mutual mode, neither side contributes a nonce. The TLS 1.3 Exported Keying
Material (RFC 5705, RFC 8446 section 7.5) is already unique to the session -- it
is derived from both peers' handshake randoms and the ephemeral key exchange --
so it *is* the freshness challenge. Both peers therefore require TLS 1.3; see
`MUTUAL_ATTESTATION_TLS_VERSION`. The consequence is that the binding is
constant for the lifetime of the session, which is why a session is attested
exactly once; see `AttestationReplayError`.
"""

from collections.abc import Sequence
import hashlib
from typing import Protocol

from prompt_encryption_sdk.proto import attestation_pb2

# Wire version of the mutual exchange. Version 0 is the server-only flow.
MUTUAL_ATTESTATION_PROTOCOL_VERSION: int = 1

# TLS Exported Keying Material (RFC 5705 / RFC 9266) parameters.
# Server-only (v0) keeps the original label with the client nonce as context.
# Mutual (v1) uses the RFC 9266 `tls-exporter` channel binding label with no
# context.
EKM_LABEL: bytes = b"EXPORTER-Prompt-Encryption-SDK"
MUTUAL_EKM_LABEL: bytes = b"EXPORTER-Channel-Binding"
EKM_LENGTH: int = 32

# The only TLS version, as `ssl.SSLSocket.version()` reports it, over which
# either peer runs the mutual exchange. Mutual mode has no nonce, so the EKM is
# its only freshness. A TLS 1.3 exporter is unique to the session. A TLS 1.2
# exporter is not, unless both peers use the extended master secret (RFC 7627),
# and Python cannot check that.
MUTUAL_ATTESTATION_TLS_VERSION: str = "TLSv1.3"


class AttestationReplayError(Exception):
  """Raised when a TLS session that already attested attests again.

  Because the signed binding is the session's EKM, a second exchange over the
  same session would re-sign the identical payload and prove nothing new. The
  connection is dropped rather than re-attested.
  """


class AttestationRequestError(ValueError):
  """The peer sent an invalid attestation request."""


class SigningKeyManager(Protocol):
  """The subset of KeyManager used to produce channel-bound proofs."""

  def sign_payload(self, payload: bytes) -> bytes:
    """Returns the ECDSA P-256 signature of `payload`."""
    ...

  def sign_payload_mldsa(self, payload: bytes) -> bytes:
    """Returns the ML-DSA-65 signature of `payload`."""
    ...


class IdentitySnapshotProvider(Protocol):
  """Provides a TEE identity snapshot and the key manager that signs proofs.

  `get_identity_snapshot` returns a consistent snapshot of the public keys and
  the attestation token. `key_manager` signs with its current keys, so a key
  rotation between the snapshot and signing makes the peer reject that one
  proof.
  """

  @property
  def key_manager(self) -> SigningKeyManager:
    """The key manager that signs proofs with its current keys."""
    ...

  def get_identity_snapshot(self) -> tuple[bytes, bytes, bytes]:
    """Returns (ECDSA public key, ML-DSA public keyset, attestation token)."""
    ...


def validate_required_verifiers(
    verifier_types: Sequence[attestation_pb2.VerifierType],
) -> None:
  """Rejects empty or unsupported attestation verifier requirements.

  Args:
    verifier_types: The `required_verifier_type` values from a request.

  Raises:
    AttestationRequestError: If no verifier is requested or any is not GCA.
  """
  if not verifier_types:
    raise AttestationRequestError(
        "At least one required_verifier_type must be specified."
    )
  if any(
      verifier_type != attestation_pb2.VERIFIER_TYPE_GCA
      for verifier_type in verifier_types
  ):
    raise AttestationRequestError(
        f"Unsupported verifier types requested: {list(verifier_types)}"
    )


def build_signature_payload(
    *,
    tls_ekm: bytes,
    attestation_token: bytes,
    peer_role: attestation_pb2.AttestationPeerRole = (
        attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED
    ),
    mode: attestation_pb2.AttestationMode = (
        attestation_pb2.ATTESTATION_MODE_SERVER_ONLY
    ),
) -> bytes:
  """Builds the canonical payload signed by both the classical and PQC keys.

  In mutual mode both peers bind to the *same* EKM, so `peer_role` and `mode`
  are the domain separators that keep one side's proof from being replayed as
  the other's.

  Args:
    tls_ekm: Exported Keying Material for this TLS session.
    attestation_token: The raw GCA attestation token bytes.
    peer_role: Which endpoint produced the proof.
    mode: The negotiated attestation mode.

  Returns:
    The serialized SessionSignaturePayload. For server-only proofs every added
    field is at its default and therefore absent from the wire, so the bytes
    are unchanged from the pre-mutual-attestation SDK.

  Raises:
    ValueError: If `mode` and `peer_role` do not form a valid combination.
  """
  if (
      mode == attestation_pb2.ATTESTATION_MODE_SERVER_ONLY
      and peer_role == attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED
  ):
    protocol_version = 0
  elif mode == attestation_pb2.ATTESTATION_MODE_MUTUAL and peer_role in (
      attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
      attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
  ):
    protocol_version = MUTUAL_ATTESTATION_PROTOCOL_VERSION
  else:
    raise ValueError(
        f"Invalid (mode, peer_role) combination: ({mode!r}, {peer_role!r})."
    )
  return attestation_pb2.SessionSignaturePayload(
      ekm_hash=hashlib.sha256(tls_ekm).digest(),
      token_hash=hashlib.sha256(attestation_token).digest(),
      peer_role=peer_role,
      mode=mode,
      protocol_version=protocol_version,
  ).SerializeToString(deterministic=True)


class AttestationProver:
  """Produces a TEE identity proof bound to a live TLS session."""

  def __init__(self, identity: IdentitySnapshotProvider):
    """Initializes the instance.

    Args:
      identity: Supplies the keys and the attestation token of this endpoint,
        for example a started `server.TokenManager`.
    """
    self._identity = identity

  def __repr__(self) -> str:
    return f"AttestationProver(identity={self._identity!r})"

  def create_proof(
      self,
      tls_ekm: bytes,
      *,
      peer_role: attestation_pb2.AttestationPeerRole = (
          attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED
      ),
      mode: attestation_pb2.AttestationMode = (
          attestation_pb2.ATTESTATION_MODE_SERVER_ONLY
      ),
  ) -> attestation_pb2.AttestationProof:
    """Creates an ECDSA + ML-DSA proof for the supplied channel binding.

    Args:
      tls_ekm: Exported Keying Material for this TLS session.
      peer_role: The role this endpoint plays in the exchange.
      mode: The negotiated attestation mode.

    Returns:
      An AttestationProof carrying the GCA token, both public keys, and both
      signatures over the canonical payload.

    Raises:
      RuntimeError: If this endpoint has no attestation token yet.
      ValueError: If `mode` and `peer_role` do not form a valid combination.
    """
    ecdsa_public_key, pqc_public_key, attestation_token = (
        self._identity.get_identity_snapshot()
    )
    if not attestation_token:
      raise RuntimeError("Attestation identity has no token.")

    payload = build_signature_payload(
        tls_ekm=tls_ekm,
        attestation_token=attestation_token,
        peer_role=peer_role,
        mode=mode,
    )
    return attestation_pb2.AttestationProof(
        evidence=[
            attestation_pb2.AttestationEvidence(
                verifier_type=attestation_pb2.VERIFIER_TYPE_GCA,
                gca_bundle=attestation_pb2.GcaTrustBundle(
                    attestation_token=attestation_token.decode("utf-8")
                ),
            )
        ],
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=ecdsa_public_key
        ),
        session_signature=self._identity.key_manager.sign_payload(payload),
        pqc_public_key=attestation_pb2.MlDsaPublicKey(
            serialized_public_keyset=pqc_public_key
        ),
        pqc_session_signature=self._identity.key_manager.sign_payload_mldsa(
            payload
        ),
    )


def response_from_proof(
    proof: attestation_pb2.AttestationProof,
    *,
    protocol_version: int = 0,
    mode: attestation_pb2.AttestationMode = (
        attestation_pb2.ATTESTATION_MODE_SERVER_ONLY
    ),
    mutual_attestation_complete: bool = False,
) -> attestation_pb2.AttestConnectionResponse:
  """Copies a proof into the AttestConnectionResponse wire shape.

  Args:
    proof: The server's proof.
    protocol_version: The negotiated protocol version to echo.
    mode: The negotiated attestation mode to echo.
    mutual_attestation_complete: Whether the client's proof was verified.

  Returns:
    An AttestConnectionResponse carrying the proof and the echoed fields.
  """
  response = attestation_pb2.AttestConnectionResponse(
      instance_public_key=proof.instance_public_key,
      session_signature=proof.session_signature,
      pqc_public_key=proof.pqc_public_key,
      pqc_session_signature=proof.pqc_session_signature,
      protocol_version=protocol_version,
      mode=mode,
      mutual_attestation_complete=mutual_attestation_complete,
  )
  response.evidence.extend(proof.evidence)
  return response
