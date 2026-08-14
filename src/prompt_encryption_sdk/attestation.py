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

"""Shared proof and transcript primitives for post-handshake attestation."""

from collections.abc import Sequence
import hashlib
from typing import Protocol

from prompt_encryption_sdk.proto import attestation_pb2


MUTUAL_ATTESTATION_PROTOCOL_VERSION = 1
NONCE_LENGTH = 32
HANDSHAKE_ID_LENGTH = 32


class _SigningKeyManager(Protocol):
  """The subset of KeyManager used to produce channel-bound proofs."""

  def sign_payload(self, payload: bytes) -> bytes:
    ...

  def sign_payload_mldsa(self, payload: bytes) -> bytes:
    ...


class IdentitySnapshotProvider(Protocol):
  """Provides an atomic snapshot of a TEE identity and its signing keys."""

  key_manager: _SigningKeyManager

  def get_identity_snapshot(self) -> tuple[bytes, bytes, bytes]:
    ...


def validate_required_verifiers(verifier_types: Sequence[int]) -> None:
  """Rejects empty or unsupported attestation verifier requirements."""
  if not verifier_types:
    raise ValueError("At least one required_verifier_type must be specified.")
  if any(
      verifier_type != attestation_pb2.VERIFIER_TYPE_GCA
      for verifier_type in verifier_types
  ):
    raise ValueError(f"Unsupported verifier types requested: {list(verifier_types)}")


def build_mutual_transcript(
    *, client_nonce: bytes, server_nonce: bytes, handshake_id: bytes
) -> attestation_pb2.MutualAttestationTranscript:
  """Builds the canonical transcript shared by both mutual peers."""
  if len(client_nonce) != NONCE_LENGTH:
    raise ValueError(f"client nonce must be {NONCE_LENGTH} bytes.")
  if len(server_nonce) != NONCE_LENGTH:
    raise ValueError(f"server nonce must be {NONCE_LENGTH} bytes.")
  if len(handshake_id) != HANDSHAKE_ID_LENGTH:
    raise ValueError(f"handshake ID must be {HANDSHAKE_ID_LENGTH} bytes.")
  return attestation_pb2.MutualAttestationTranscript(
      protocol_version=MUTUAL_ATTESTATION_PROTOCOL_VERSION,
      mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      client_nonce=client_nonce,
      server_nonce=server_nonce,
      handshake_id=handshake_id,
  )


def transcript_hash(
    transcript: attestation_pb2.MutualAttestationTranscript,
) -> bytes:
  """Returns the hash used as both the EKM context and signed transcript."""
  return hashlib.sha256(transcript.SerializeToString(deterministic=True)).digest()


def build_signature_payload(
    *,
    tls_ekm: bytes,
    attestation_token: bytes,
    peer_role: int = attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
    mode: int = attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
    transcript_hash_bytes: bytes = b"",
) -> bytes:
  """Builds the canonical payload signed by both classical and PQC keys."""
  return attestation_pb2.SessionSignaturePayload(
      ekm_hash=hashlib.sha256(tls_ekm).digest(),
      token_hash=hashlib.sha256(attestation_token).digest(),
      peer_role=peer_role,
      mode=mode,
      transcript_hash=transcript_hash_bytes,
  ).SerializeToString(deterministic=True)


class AttestationProver:
  """Produces a TEE identity proof bound to a live TLS session."""

  def __init__(self, identity: IdentitySnapshotProvider):
    self._identity = identity

  def create_proof(
      self,
      tls_ekm: bytes,
      *,
      peer_role: int = attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
      mode: int = attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
      transcript_hash_bytes: bytes = b"",
  ) -> attestation_pb2.AttestationProof:
    """Creates an ECDSA + ML-DSA proof for the supplied channel binding."""
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
        transcript_hash_bytes=transcript_hash_bytes,
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
        pqc_session_signature=(self._identity.key_manager.sign_payload_mldsa(payload)),
    )


def proof_from_response(
    response: attestation_pb2.AttestConnectionResponse,
) -> attestation_pb2.AttestationProof:
  """Copies the compatibility response fields into a role-neutral proof."""
  proof = attestation_pb2.AttestationProof(
      instance_public_key=response.instance_public_key,
      session_signature=response.session_signature,
      pqc_public_key=response.pqc_public_key,
      pqc_session_signature=response.pqc_session_signature,
  )
  proof.evidence.extend(response.evidence)
  return proof


def response_from_proof(
    proof: attestation_pb2.AttestationProof,
    **response_fields,
) -> attestation_pb2.AttestConnectionResponse:
  """Copies a proof into the existing AttestConnectionResponse wire shape."""
  response = attestation_pb2.AttestConnectionResponse(
      instance_public_key=proof.instance_public_key,
      session_signature=proof.session_signature,
      pqc_public_key=proof.pqc_public_key,
      pqc_session_signature=proof.pqc_session_signature,
      **response_fields,
  )
  response.evidence.extend(proof.evidence)
  return response
