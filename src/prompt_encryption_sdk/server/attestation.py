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

"""Server-side state machine for post-handshake attested TLS."""

import dataclasses
import secrets
import threading
import time
from typing import Any, Callable
import weakref

from absl import logging
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.ekm import exporter
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import token


_EKM_LABEL = b"EXPORTER-Prompt-Encryption-SDK"
_EKM_LENGTH = 32
_DEFAULT_HANDSHAKE_TIMEOUT_SECONDS = 30.0


@dataclasses.dataclass(frozen=True)
class _PendingMutualAttestation:
  """One-time server state for a mutual CLIENT_FINISH flight."""

  client_nonce: bytes
  handshake_id: bytes
  transcript_hash: bytes
  tls_ekm: bytes
  created_at: float


class AttestedTLS:
  """Produces server proofs and verifies optional client proofs.

  The legacy server-only request remains a one-flight exchange. Mutual mode is
  a two-flight exchange: the initial request returns the server proof and saves
  one-time state for this TLS socket; CLIENT_FINISH verifies the client's proof
  before returning a completion acknowledgement.
  """

  def __init__(
      self,
      token_manager: token.TokenManager,
      *,
      client_policy: attestation_pb2.AttestationPolicy | None = None,
      require_mutual_attestation: bool = False,
      attestation_validator_cls=validator.AttestationValidator,
      nonce_fn: Callable[[int], bytes] = secrets.token_bytes,
      clock: Callable[[], float] = time.monotonic,
      handshake_timeout_seconds: float = _DEFAULT_HANDSHAKE_TIMEOUT_SECONDS,
  ):
    if require_mutual_attestation and client_policy is None:
      raise ValueError("client_policy is required when mutual attestation is required.")
    if handshake_timeout_seconds <= 0:
      raise ValueError("handshake_timeout_seconds must be positive.")

    self.token_manager = token_manager
    self._prover = attestation_protocol.AttestationProver(token_manager)
    self._client_policy = client_policy
    self._require_mutual_attestation = require_mutual_attestation
    self._attestation_validator_cls = attestation_validator_cls
    self._nonce_fn = nonce_fn
    self._clock = clock
    self._handshake_timeout_seconds = handshake_timeout_seconds
    self._pending_mutual: weakref.WeakKeyDictionary[Any, _PendingMutualAttestation] = (
        weakref.WeakKeyDictionary()
    )
    self._pending_lock = threading.Lock()

  def __repr__(self):
    return (
        f"AttestedTLS(token_manager={self.token_manager!r}, "
        f"client_policy={self._client_policy!r}, "
        f"require_mutual_attestation={self._require_mutual_attestation!r})"
    )

  def attest_connection(
      self,
      request: attestation_pb2.AttestConnectionRequest,
      *,
      ssl_obj: Any,
  ) -> attestation_pb2.AttestConnectionResponse:
    """Processes a legacy or mutual post-handshake attestation flight."""
    attestation_protocol.validate_required_verifiers(request.required_verifier_type)

    if request.mode == attestation_pb2.ATTESTATION_MODE_MUTUAL:
      if (
          request.protocol_version
          != attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
      ):
        raise ValueError("Unsupported mutual attestation protocol version.")
      if self._client_policy is None:
        raise ValueError("Server is not configured to verify client evidence.")
      if request.phase == attestation_pb2.ATTESTATION_HANDSHAKE_PHASE_INITIAL:
        return self._start_mutual_attestation(request, ssl_obj=ssl_obj)
      if request.phase == attestation_pb2.ATTESTATION_HANDSHAKE_PHASE_CLIENT_FINISH:
        return self._finish_mutual_attestation(request, ssl_obj=ssl_obj)
      raise ValueError("Unsupported mutual attestation handshake phase.")

    if request.mode != attestation_pb2.ATTESTATION_MODE_SERVER_ONLY:
      raise ValueError("Unsupported attestation mode.")
    if self._require_mutual_attestation:
      raise ValueError("This server requires mutual attestation.")
    if request.phase != attestation_pb2.ATTESTATION_HANDSHAKE_PHASE_INITIAL:
      raise ValueError("CLIENT_FINISH is valid only for mutual attestation.")
    return self._attest_server_only(request, ssl_obj=ssl_obj)

  def _attest_server_only(
      self,
      request: attestation_pb2.AttestConnectionRequest,
      *,
      ssl_obj: Any,
  ) -> attestation_pb2.AttestConnectionResponse:
    """Runs the wire-compatible legacy server-only exchange."""
    tls_ekm = self._export_ekm(ssl_obj, context=request.nonce)
    proof = self._prover.create_proof(tls_ekm)
    return attestation_protocol.response_from_proof(proof)

  def _start_mutual_attestation(
      self,
      request: attestation_pb2.AttestConnectionRequest,
      *,
      ssl_obj: Any,
  ) -> attestation_pb2.AttestConnectionResponse:
    """Returns the server proof and registers a one-time client challenge."""
    if len(request.nonce) != attestation_protocol.NONCE_LENGTH:
      raise ValueError(
          f"client nonce must be {attestation_protocol.NONCE_LENGTH} bytes."
      )
    if request.handshake_id or request.HasField("client_attestation"):
      raise ValueError("Initial mutual request contains finish-only fields.")

    server_nonce = self._nonce_fn(attestation_protocol.NONCE_LENGTH)
    handshake_id = self._nonce_fn(attestation_protocol.HANDSHAKE_ID_LENGTH)
    transcript = attestation_protocol.build_mutual_transcript(
        client_nonce=request.nonce,
        server_nonce=server_nonce,
        handshake_id=handshake_id,
    )
    transcript_hash_bytes = attestation_protocol.transcript_hash(transcript)
    tls_ekm = self._export_ekm(ssl_obj, context=transcript_hash_bytes)
    proof = self._prover.create_proof(
        tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        transcript_hash_bytes=transcript_hash_bytes,
    )

    pending = _PendingMutualAttestation(
        client_nonce=request.nonce,
        handshake_id=handshake_id,
        transcript_hash=transcript_hash_bytes,
        tls_ekm=tls_ekm,
        created_at=self._clock(),
    )
    with self._pending_lock:
      self._pending_mutual[ssl_obj] = pending

    return attestation_protocol.response_from_proof(
        proof,
        protocol_version=(attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION),
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        handshake_id=handshake_id,
        server_nonce=server_nonce,
        mutual_attestation_complete=False,
    )

  def _finish_mutual_attestation(
      self,
      request: attestation_pb2.AttestConnectionRequest,
      *,
      ssl_obj: Any,
  ) -> attestation_pb2.AttestConnectionResponse:
    """Verifies the client proof and consumes the per-socket challenge."""
    with self._pending_lock:
      pending = self._pending_mutual.pop(ssl_obj, None)
    if pending is None:
      raise ValueError("No pending mutual attestation for this TLS session.")
    if self._clock() - pending.created_at > self._handshake_timeout_seconds:
      raise ValueError("Mutual attestation handshake expired.")
    if request.handshake_id != pending.handshake_id:
      raise ValueError("Mutual attestation handshake ID mismatch.")
    if request.nonce != pending.client_nonce:
      raise ValueError("Mutual attestation client nonce mismatch.")
    if not request.HasField("client_attestation"):
      raise ValueError("Client attestation proof is missing.")

    peer_validator = self._attestation_validator_cls(self._client_policy)
    try:
      peer_validator.validate_proof(
          request.client_attestation,
          pending.tls_ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
          transcript_hash_bytes=pending.transcript_hash,
      )
    finally:
      close = getattr(peer_validator, "close", None)
      if close is not None:
        close()

    return attestation_pb2.AttestConnectionResponse(
        protocol_version=(attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION),
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        handshake_id=pending.handshake_id,
        mutual_attestation_complete=True,
    )

  @staticmethod
  def completes_attestation(
      request: attestation_pb2.AttestConnectionRequest,
      response: attestation_pb2.AttestConnectionResponse,
  ) -> bool:
    """Returns whether this successful flight authorizes application data."""
    if request.mode == attestation_pb2.ATTESTATION_MODE_SERVER_ONLY:
      return True
    return (
        request.mode == attestation_pb2.ATTESTATION_MODE_MUTUAL
        and request.phase == attestation_pb2.ATTESTATION_HANDSHAKE_PHASE_CLIENT_FINISH
        and response.mutual_attestation_complete
    )

  @staticmethod
  def _export_ekm(ssl_obj: Any, *, context: bytes) -> bytes:
    """Extracts EKM using stdlib support with the C extension as fallback."""
    ekm_bytes = None
    first_ekm_exception = None
    if hasattr(ssl_obj, "export_keying_material"):
      try:
        ekm_bytes = ssl_obj.export_keying_material(
            _EKM_LABEL, _EKM_LENGTH, context=context
        )
      except Exception as e:  # pylint: disable=broad-except
        logging.exception("Failed to extract EKM using export_keying_material.")
        first_ekm_exception = e

    if ekm_bytes is None:
      target_obj = getattr(ssl_obj, "_sslobj", ssl_obj)
      ekm_bytes = exporter.export_keying_material(
          sock=target_obj,
          length=_EKM_LENGTH,
          label=_EKM_LABEL,
          context=context,
      )

    if ekm_bytes is not None:
      return ekm_bytes
    if first_ekm_exception:
      raise RuntimeError(
          "EKM extraction failed. The initial attempt using"
          " ssl_obj.export_keying_material failed."
      ) from first_ekm_exception
    raise RuntimeError(
        "EKM extraction failed. Both ssl_obj.export_keying_material and"
        " the fallback exporter failed to extract keying material."
    )
