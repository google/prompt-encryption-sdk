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

from collections.abc import Callable
import dataclasses
import math
import threading
from typing import Any
import weakref

from absl import logging
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.ekm import exporter
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import token

_REPLAY_MESSAGE = (
    "This TLS session is already mutually attested. Re-attestation over the"
    " same session proves no new freshness; establish a new connection"
    " instead."
)


def _export_ekm(ssl_obj: Any, *, context: bytes | None) -> bytes:
  """Extracts EKM using the standard library, falling back to the C extension.

  Args:
    ssl_obj: The SSL object from the TLS connection.
    context: RFC 5705 context, or None for no context at all. Both peers must
      use the same one, because under TLS 1.2 an empty context and no context
      derive different keying material. Under TLS 1.3 they derive the same
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
          attestation_protocol.EKM_LABEL,
          attestation_protocol.EKM_LENGTH,
          context=context,
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
        length=attestation_protocol.EKM_LENGTH,
        label=attestation_protocol.EKM_LABEL,
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


@dataclasses.dataclass(frozen=True)
class AttestationResult:
  """The outcome of an AttestConnection exchange.

  Attributes:
    response: The proof to send back to the peer.
    expires_at: Unix time after which this connection is no longer authorized,
      taken from the `exp` claim of the peer's attestation token. `math.inf` in
      server-only mode, where the server holds no client evidence and so has
      nothing to expire.
  """

  response: attestation_pb2.AttestConnectionResponse
  expires_at: float = math.inf


def _pins_peer_identity(policy: attestation_pb2.AttestationPolicy) -> bool:
  """Checks if policy pins workload identity or a GCE project/instance ID."""
  if policy.HasField("workload"):
    workload = policy.workload
    if (
        workload.image_hash
        or workload.signing_key_id
        or workload.image_signatures
    ):
      return True
  if policy.HasField("gce_instance"):
    gce = policy.gce_instance
    if gce.project_id or gce.instance_id:
      return True
  return False


class AttestedTLS:
  """Handles AttestConnection logic.

  Two modes share one round trip:

  * Server-only (the default) returns the server's proof, bound to an EKM
    derived with the client's nonce as context.
  * Mutual verifies the client's proof carried in the request and, only if it
    passes, returns the server's proof. Both proofs bind to the same
    no-context EKM: the TLS 1.3 session is itself the freshness challenge, so
    neither side needs to contribute a nonce. Mutual requests over older TLS
    versions are rejected.

  Because a mutual proof binds to a value that is constant for the session,
  a second attestation on an already-mutually-attested session would prove
  nothing new. Such a session is not re-attested; `attest_connection` raises
  `AttestationReplayError` and the caller drops the connection.

  Attributes:
    token_manager: Supplies this server's keys and attestation token.
  """

  def __init__(
      self,
      token_manager: token.TokenManager,
      *,
      client_policy: attestation_pb2.AttestationPolicy | None = None,
      require_mutual_attestation: bool = False,
      attestation_validator_cls: Callable[
          ..., validator.AttestationValidator
      ] = validator.AttestationValidator,
  ):
    """Initializes the handler.

    Args:
      token_manager: Supplies this server's keys and attestation token.
      client_policy: Policy a confidential client's evidence must satisfy.
        Providing it enables mutual attestation. None means the server serves
        only server-only clients. Only fields that are set are checked: a policy
        that pins neither workload identity nor a GCE project_id or instance_id
        admits peers from any project, leaving hw_model unspecified admits
        non-confidential VMs, and leaving
        confidential_space.require_debug_disabled unset admits debug
        Confidential Space instances.
      require_mutual_attestation: Reject server-only clients. When False,
        server-only sessions are authorized the same as mutual ones and the
        application cannot tell them apart.
      attestation_validator_cls: Dependency injection for the validator used to
        check client proofs.

    Raises:
      ValueError: If mutual attestation is required without a client policy.
    """
    if require_mutual_attestation and client_policy is None:
      raise ValueError(
          "client_policy is required when mutual attestation is required."
      )
    if client_policy is not None:
      if not _pins_peer_identity(client_policy):
        logging.warning(
            "client_policy pins neither workload identity nor a GCE project_id"
            " or instance_id; any GCA-attested peer can satisfy those checks."
        )
      if client_policy.hw_model == attestation_pb2.HARDWARE_MODEL_UNSPECIFIED:
        logging.warning(
            "client_policy leaves hw_model unspecified; non-confidential VMs"
            " can satisfy the policy."
        )
      if not client_policy.confidential_space.require_debug_disabled:
        logging.warning(
            "client_policy does not set"
            " confidential_space.require_debug_disabled; debug Confidential"
            " Space instances are admitted."
        )

    self.token_manager = token_manager
    self._prover = attestation_protocol.AttestationProver(token_manager)
    self._client_policy = client_policy
    self._require_mutual_attestation = require_mutual_attestation
    self._attestation_validator_cls = attestation_validator_cls
    self._client_validator: validator.AttestationValidator | None = None
    # Dedicated lock so OIDC discovery during first validator construction does
    # not block server-only handshakes or replay checks on self._lock.
    self._validator_lock = threading.Lock()
    # Guards the attested-session set across concurrently served connections.
    self._lock = threading.Lock()
    # Sessions that already completed mutual attestation. Weak so entries
    # disappear with the TLS socket.
    self._mutually_attested: weakref.WeakSet[Any] = weakref.WeakSet()

  def __repr__(self) -> str:
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
  ) -> AttestationResult:
    """Processes the AttestConnectionRequest and returns an AttestationResult.

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
      An AttestationResult holding the response to send back and, in mutual
      mode, the time at which the client's evidence stops being valid.

    Raises:
      AttestationReplayError: If this TLS session already completed mutual
        attestation.
      AttestationVerificationError: If the client's proof does not verify, or
        its token has no usable expiry.
      PolicyViolationError: If the client fails `client_policy`.
      ValueError: If the request is malformed or asks for an unsupported
        verifier, mode, or protocol version, or if a mutual request arrives
        over a session that is not TLS 1.3.
      RuntimeError: If EKM extraction fails, or if this server has no
        attestation token yet.
    """
    with self._lock:
      already_attested = ssl_obj in self._mutually_attested
    if already_attested:
      raise attestation_protocol.AttestationReplayError(_REPLAY_MESSAGE)

    attestation_protocol.validate_required_verifiers(
        request.required_verifier_type
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
    if request.protocol_version != 0:
      # An unknown mode value parses as SERVER_ONLY, so a request from a newer
      # protocol must not get a server-only answer.
      raise ValueError(
          "Unsupported server-only protocol version:"
          f" {request.protocol_version}"
      )
    return self._attest_server_only(request, ssl_obj=ssl_obj)

  def _attest_server_only(
      self,
      request: attestation_pb2.AttestConnectionRequest,
      *,
      ssl_obj: Any,
  ) -> AttestationResult:
    """Runs the server-only exchange, using the client nonce as EKM context."""
    # No expiry is recorded: the server verified no client evidence here, so it
    # holds nothing that can go stale. The client enforces its own revalidation
    # interval in this mode.
    tls_ekm = _export_ekm(ssl_obj, context=request.nonce)
    proof = self._prover.create_proof(tls_ekm)
    with self._lock:
      # A mutual exchange on this session can finish while this one runs. Its
      # expiry must not be replaced by a server-only result that never expires.
      if ssl_obj in self._mutually_attested:
        raise attestation_protocol.AttestationReplayError(_REPLAY_MESSAGE)
    return AttestationResult(
        response=attestation_protocol.response_from_proof(proof)
    )

  def _attest_mutual(
      self,
      request: attestation_pb2.AttestConnectionRequest,
      *,
      ssl_obj: Any,
  ) -> AttestationResult:
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
    # The EKM is the only freshness in this mode, and only a TLS 1.3 exporter
    # is guaranteed unique to the session. Check before any proof is verified
    # or produced, so a TLS 1.2 session gets no server proof.
    tls_version = ssl_obj.version()
    if tls_version != attestation_protocol.MUTUAL_ATTESTATION_TLS_VERSION:
      raise ValueError(
          "Mutual attestation requires"
          f" {attestation_protocol.MUTUAL_ATTESTATION_TLS_VERSION}, but the"
          f" session uses {tls_version}."
      )
    if request.nonce:
      # Mutual mode binds to the bare session EKM. Honoring a caller-supplied
      # context here would let the peers derive different bindings.
      raise ValueError("nonce must be empty for mutual attestation.")
    if not request.HasField("client_attestation"):
      raise ValueError("Client attestation proof is missing.")

    tls_ekm = _export_ekm(ssl_obj, context=None)
    claims = self._client_verifier().validate_proof(
        request.client_attestation,
        tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    # The session cannot be re-attested, so the client's evidence is only as
    # good as the token backing it. Stop trusting the connection when that
    # token expires rather than for as long as the socket happens to live.
    expires_at = validator.verified_expiry(claims)

    proof = self._prover.create_proof(
        tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    with self._lock:
      # Re-check under the same lock as the add: the early check in
      # attest_connection does not hold the lock across verification.
      if ssl_obj in self._mutually_attested:
        raise attestation_protocol.AttestationReplayError(_REPLAY_MESSAGE)
      self._mutually_attested.add(ssl_obj)
    return AttestationResult(
        response=attestation_protocol.response_from_proof(
            proof,
            protocol_version=(
                attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
            ),
            mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
            mutual_attestation_complete=True,
        ),
        expires_at=expires_at,
    )

  def _client_verifier(self) -> validator.AttestationValidator:
    """Returns the shared client-proof validator, building it on first use.

    Construction reaches out for OIDC discovery, so it is deferred until a
    mutual request actually arrives and then reused across connections.
    """
    if self._client_validator is not None:
      return self._client_validator
    with self._validator_lock:
      if self._client_validator is None:
        self._client_validator = self._attestation_validator_cls(
            self._client_policy
        )
      return self._client_validator
