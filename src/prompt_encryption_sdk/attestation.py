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

The server proves its TEE identity with a proof bound to the TLS session. The
code that builds and signs that proof lives here, not in the server package,
so that a client that runs in a TEE can later produce the same proof.
"""

from collections.abc import Sequence
import hashlib
from typing import Protocol

from prompt_encryption_sdk.proto import attestation_pb2

# TLS Exported Keying Material (RFC 5705) parameters.
EKM_LABEL: bytes = b"EXPORTER-Prompt-Encryption-SDK"
EKM_LENGTH: int = 32


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
    ValueError: If no verifier is requested or any is not GCA.
  """
  if not verifier_types:
    raise ValueError("At least one required_verifier_type must be specified.")
  if any(
      verifier_type != attestation_pb2.VERIFIER_TYPE_GCA
      for verifier_type in verifier_types
  ):
    raise ValueError(
        f"Unsupported verifier types requested: {list(verifier_types)}"
    )


def build_signature_payload(
    *,
    tls_ekm: bytes,
    attestation_token: bytes,
) -> bytes:
  """Builds the canonical payload signed by both the classical and PQC keys.

  Args:
    tls_ekm: Exported Keying Material for this TLS session.
    attestation_token: The raw GCA attestation token bytes.

  Returns:
    The serialized SessionSignaturePayload.
  """
  return attestation_pb2.SessionSignaturePayload(
      ekm_hash=hashlib.sha256(tls_ekm).digest(),
      token_hash=hashlib.sha256(attestation_token).digest(),
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

  def create_proof(self, tls_ekm: bytes) -> attestation_pb2.AttestationProof:
    """Creates an ECDSA + ML-DSA proof for the supplied channel binding.

    Args:
      tls_ekm: Exported Keying Material for this TLS session.

    Returns:
      An AttestationProof carrying the GCA token, both public keys, and both
      signatures over the canonical payload.

    Raises:
      RuntimeError: If this endpoint has no attestation token yet.
    """
    ecdsa_public_key, pqc_public_key, attestation_token = (
        self._identity.get_identity_snapshot()
    )
    if not attestation_token:
      raise RuntimeError("Attestation identity has no token.")

    payload = build_signature_payload(
        tls_ekm=tls_ekm, attestation_token=attestation_token
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
) -> attestation_pb2.AttestConnectionResponse:
  """Copies a proof into the AttestConnectionResponse wire shape.

  Args:
    proof: The server's proof.

  Returns:
    An AttestConnectionResponse carrying the proof.
  """
  response = attestation_pb2.AttestConnectionResponse(
      instance_public_key=proof.instance_public_key,
      session_signature=proof.session_signature,
      pqc_public_key=proof.pqc_public_key,
      pqc_session_signature=proof.pqc_session_signature,
  )
  response.evidence.extend(proof.evidence)
  return response
