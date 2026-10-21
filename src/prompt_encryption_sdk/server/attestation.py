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

"""Attested TLS logic for Prompt Encryption SDK."""

import threading
from typing import Any
import weakref

from absl import logging
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.ekm import exporter
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import token

_EKM_LABEL = b"EXPORTER-Prompt-Encryption-SDK"
_EKM_LENGTH = 32


class AttestedTLS:
  """Handles AttestConnection logic.

  Two modes share one round trip:

  * Server-only (the default) returns the server's proof, bound to an EKM
    derived with the client's nonce as context.
  * Mutual verifies the client's proof carried in the request and, only if it
    passes, returns the server's proof. Both proofs bind to the same
    no-context EKM: the TLS session is itself the freshness challenge, so
    neither side needs to contribute a nonce.

  Because a mutual proof binds to a value that is constant for the session,
  a second attestation on an already-mutually-attested session would prove
  nothing new. Such a session is not re-attested; `attest_connection` raises
  `AttestationReplayError` and the caller drops the connection.
  """

  def __init__(
      self,
      token_manager: token.TokenManager,
      *,
      client_policy: attestation_pb2.AttestationPolicy | None = None,
      require_mutual_attestation: bool = False,
      attestation_validator_cls=validator.AttestationValidator,
  ):
    """Initializes the handler.

    Args:
      token_manager: Supplies this server's keys and attestation token.
      client_policy: Policy a confidential client's evidence must satisfy.
        Providing it enables mutual attestation.
      require_mutual_attestation: Reject server-only clients.
      attestation_validator_cls: Dependency injection for the validator used
        to check client proofs.

    Raises:
      ValueError: If mutual attestation is required without a client policy.
    """
    if require_mutual_attestation and client_policy is None:
      raise ValueError(
          "client_policy is required when mutual attestation is required."
      )

    self.token_manager = token_manager
    self._prover = attestation_protocol.AttestationProver(token_manager)
    self._client_policy = client_policy
    self._require_mutual_attestation = require_mutual_attestation
    self._attestation_validator_cls = attestation_validator_cls
    self._client_validator = None
    # Guards both the lazily built validator and the attested-session set,
    # which are shared across concurrently served connections.
    self._lock = threading.Lock()
    # Sessions that already completed mutual attestation. Weak so entries
    # disappear with the TLS socket.
    self._mutually_attested = weakref.WeakSet()

  def __repr__(self):
    return (
        f"AttestedTLS(token_manager={self.token_manager!r},"
        f" client_policy={self._client_policy!r},"
        f" require_mutual_attestation={self._require_mutual_attestation!r})"
    )

  def attest_connection(
      self,
      request: attestation_pb2.AttestConnectionRequest,
      *,
      ssl_obj: Any,
  ) -> attestation_pb2.AttestConnectionResponse:
    """Processes the AttestConnectionRequest and returns an AttestConnectionResponse.

    This function returns an attested TLS response containing an attestation
    token with the hash of the server's public key embedded in it. It also signs
    the TLS session material and hash of the attestation token with the private
    key and includes the signature in the response.

    In mutual mode it first verifies the client proof carried in the request,
    and only produces the server proof if that check passes.

    Args:
      request: The AttestConnectionRequest message.
      ssl_obj: The SSL object from the TLS connection.

    Returns:
      An AttestConnectionResponse message containing the attestation token and
      the server's public key and signed TLS session material.

    Raises:
      AttestationReplayError: If this TLS session already completed mutual
        attestation.
      ValueError: If the request is malformed or asks for an unsupported
        verifier, mode, or protocol version.
      RuntimeError: If EKM extraction fails.
    """
    attestation_protocol.validate_required_verifiers(
        request.required_verifier_type
    )

    with self._lock:
      already_attested = ssl_obj in self._mutually_attested
    if already_attested:
      raise attestation_protocol.AttestationReplayError(
          "This TLS session is already mutually attested. Re-attestation over"
          " the same session proves no new freshness; establish a new"
          " connection instead."
      )

    if request.mode == attestation_pb2.ATTESTATION_MODE_MUTUAL:
      return self._attest_mutual(request, ssl_obj=ssl_obj)

    if request.mode != attestation_pb2.ATTESTATION_MODE_SERVER_ONLY:
      raise ValueError(f"Unsupported attestation mode: {request.mode}")
    if self._require_mutual_attestation:
      raise ValueError("This server requires mutual attestation.")
    if request.HasField("client_attestation"):
      raise ValueError(
          "client_attestation is valid only for mutual attestation."
      )
    return self._attest_server_only(request, ssl_obj=ssl_obj)

  def _attest_server_only(
      self,
      request: attestation_pb2.AttestConnectionRequest,
      *,
      ssl_obj: Any,
  ) -> attestation_pb2.AttestConnectionResponse:
    """Runs the server-only exchange, using the client nonce as EKM context."""
    tls_ekm = self._export_ekm(ssl_obj, context=request.nonce)
    return attestation_protocol.response_from_proof(
        self._prover.create_proof(tls_ekm)
    )

  def _attest_mutual(
      self,
      request: attestation_pb2.AttestConnectionRequest,
      *,
      ssl_obj: Any,
  ) -> attestation_pb2.AttestConnectionResponse:
    """Verifies the client's proof, then answers with the server's own."""
    if (
        request.protocol_version
        != attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
    ):
      raise ValueError(
          "Unsupported mutual attestation protocol version:"
          f" {request.protocol_version}"
      )
    if self._client_policy is None:
      raise ValueError("Server is not configured to verify client evidence.")
    if request.nonce:
      # Mutual mode binds to the bare session EKM. Honoring a caller-supplied
      # context here would let the peers derive different bindings.
      raise ValueError("nonce must be empty for mutual attestation.")
    if not request.HasField("client_attestation"):
      raise ValueError("Client attestation proof is missing.")

    tls_ekm = self._export_ekm(ssl_obj, context=None)
    self._client_verifier().validate_proof(
        request.client_attestation,
        tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    proof = self._prover.create_proof(
        tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    with self._lock:
      self._mutually_attested.add(ssl_obj)
    return attestation_protocol.response_from_proof(
        proof,
        protocol_version=(
            attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
        ),
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        mutual_attestation_complete=True,
    )

  def _client_verifier(self):
    """Returns the shared client-proof validator, building it on first use.

    Construction reaches out for OIDC discovery, so it is deferred until a
    mutual request actually arrives and then reused across connections.
    """
    if self._client_validator is None:
      with self._lock:
        if self._client_validator is None:
          self._client_validator = self._attestation_validator_cls(
              self._client_policy
          )
    return self._client_validator

  @staticmethod
  def _export_ekm(ssl_obj: Any, *, context: bytes | None) -> bytes:
    """Extracts EKM using the standard library, falling back to the C extension.

    Args:
      ssl_obj: The SSL object from the TLS connection.
      context: RFC 5705 context, or None for no context at all. Both peers
        must agree, since an empty context and no context derive different
        keying material.

    Returns:
      The exported keying material.

    Raises:
      RuntimeError: If both extraction paths fail.
    """
    ekm_bytes = None
    first_ekm_exception = None
    # Attempt to extract EKM using the standard library.
    # If the standard API fails or is missing, we fallback
    # to a custom exporter, which uses SSL socket injected in request scope by
    # middleware.
    if hasattr(ssl_obj, "export_keying_material"):
      try:
        ekm_bytes = ssl_obj.export_keying_material(
            _EKM_LABEL, _EKM_LENGTH, context=context
        )
      except Exception as e:  # pylint: disable=broad-except
        # If export_keying_material fails, we will try to extract EKM using
        # exporter.export_keying_material.
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
