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

"""Provides custom urllib3 connection classes for Prompt Encryption SDK.

This module defines `AttestedHTTPSConnection`, `AttestedHTTPSConnectionPool`,
and `AttestedPoolManager` which extend urllib3's classes to perform
attestation handshakes and session revalidation.

Mutual attestation is a single round trip. The client exports the session EKM,
signs its own proof over it, and sends that proof in the very first request;
the server verifies it and answers with its own proof. Since the binding is
the session EKM rather than a per-exchange nonce, a mutually attested session
is never revalidated -- the server drops any session that tries.
"""

import base64
from collections.abc import Callable, Mapping
import datetime
import json
import logging
import secrets
import socket
import ssl
import time
from typing import Any

from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.ekm import exporter as ekm_exporter
from prompt_encryption_sdk.proto import attestation_pb2
from google.protobuf import json_format
import tink
from urllib3 import connection
from urllib3 import connectionpool
from urllib3 import poolmanager

from . import constants
from . import exceptions
from . import validator

logger = logging.getLogger(__name__)

# How far ahead of the peer's token expiry the client stops reusing a
# connection. Covers clock skew between the two TEEs plus the time a request
# spends in flight.
_EXPIRY_MARGIN_SECONDS = 60


def _extract_token_exp(
    proof: attestation_pb2.AttestationProof,
) -> float | None:
  """Returns the `exp` claim of the GCA token in `proof`, without verifying it.

  The client reads its own token here, to bound how long it reuses a
  connection.

  Args:
    proof: The client's own proof.

  Returns:
    The `exp` claim of the first GCA token whose payload is a JSON object with
    a finite numeric `exp`, or None if no token in `proof` has one.
  """
  for evidence in proof.evidence:
    if not evidence.HasField("gca_bundle"):
      continue
    parts = evidence.gca_bundle.attestation_token.split(".")
    if len(parts) != 3:
      continue
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
      claims = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, RecursionError):
      continue
    if not isinstance(claims, Mapping):
      continue
    try:
      return validator.verified_expiry(claims)
    except exceptions.AttestationVerificationError:
      continue
  return None


def validate_mutual_settings(
    mutual_attestation: bool,
    attestation_prover: attestation_protocol.AttestationProver | None,
) -> None:
  """Checks that a prover is given exactly when mutual attestation is on.

  A prover without mutual mode would be ignored, and the client would attest
  only the server without saying so.

  Args:
    mutual_attestation: Whether the client also proves its own identity.
    attestation_prover: Signs the client's proofs.

  Raises:
    ValueError: If the two settings do not match.
  """
  if mutual_attestation and attestation_prover is None:
    raise ValueError(
        "attestation_prover is required when mutual_attestation is enabled."
    )
  if not mutual_attestation and attestation_prover is not None:
    raise ValueError(
        "attestation_prover is valid only when mutual_attestation is enabled."
    )


class AttestedHTTPSConnection(connection.HTTPSConnection):
  """An HTTPS connection that performs attestation immediately after handshake.

  Inherits from urllib3.connection.HTTPSConnection.
  """

  def __init__(
      self,
      *args: Any,
      ekm_exporter_fn: Callable[
          ..., bytes
      ] = ekm_exporter.export_keying_material,
      attestation_validator_cls: Callable[
          ..., validator.AttestationValidator
      ] = validator.AttestationValidator,
      **kwargs: Any,
  ):
    """Initializes the instance.

    Args:
      *args: Passed to `urllib3.connection.HTTPSConnection`.
      ekm_exporter_fn: Exports the TLS keying material of a socket.
      attestation_validator_cls: Makes the validator for the server's proof from
        the policy.
      **kwargs: Passed to `urllib3.connection.HTTPSConnection`, except these,
        which this class takes out: `policy`, the `AttestationPolicy` that the
        server must satisfy; `mutual_attestation`, whether to also prove this
        client's identity (default False); `attestation_prover`, which signs
        that proof and is required in mutual mode; and `revalidation_timeout`,
        seconds or a `timedelta` after which a server-only session attests again
        (default 55 minutes).

    Raises:
      ValueError: If `attestation_prover` is given without
        `mutual_attestation`, or `mutual_attestation` without it.
    """
    self._policy = kwargs.pop("policy", None)
    self._mutual_attestation = kwargs.pop("mutual_attestation", False)
    self._attestation_prover = kwargs.pop("attestation_prover", None)
    validate_mutual_settings(self._mutual_attestation, self._attestation_prover)
    # Default revalidation timeout is 55 minutes.
    revalidation_timeout = kwargs.pop(
        "revalidation_timeout", datetime.timedelta(seconds=3300)
    )
    if isinstance(revalidation_timeout, (int, float)):
      self._revalidation_timeout = datetime.timedelta(
          seconds=revalidation_timeout
      )
    else:
      self._revalidation_timeout = revalidation_timeout
    self._ekm_exporter_fn = ekm_exporter_fn
    self._attestation_validator_cls = attestation_validator_cls

    self.is_attested = False
    self._last_attestation_time = 0.0
    # When the mutual attestation tokens expire. None until a mutual handshake
    # validates a token.
    self._attestation_expires_at: float | None = None

    super().__init__(*args, **kwargs)

  def __repr__(self) -> str:
    return (
        f"AttestedHTTPSConnection(host={self.host!r}, port={self.port}, "
        f"is_attested={self.is_attested}, "
        f"mutual_attestation={self._mutual_attestation}, "
        f"revalidation_timeout={self._revalidation_timeout})"
    )

  def _process_attestation_response(
      self, response
  ) -> attestation_pb2.AttestConnectionResponse:
    """Reads and parses the attestation response from the connection.

    Args:
      response: The urllib3 response object from the attestation request.

    Returns:
      An AttestConnectionResponse proto.

    Raises:
      exceptions.AttestationHandshakeError: If the response status is not 200
        or if there is an error parsing the response body.
    """
    try:
      response_body = response.data
      if response.status != 200:
        raise exceptions.AttestationHandshakeError(
            f"Server returned {response.status} during attestation:"
            f" {response_body}"
        )

      # C. Parse Response (JSON or Proto)
      content_type = response.headers.get("Content-Type", "")

      if "application/json" in content_type:
        # Handle JSON response from Server Middleware
        json_dict = json.loads(response_body)
        attest_resp = json_format.ParseDict(
            json_dict,
            attestation_pb2.AttestConnectionResponse(),
            ignore_unknown_fields=True,
        )
      else:
        # Handle Standard Protobuf response
        attest_resp = attestation_pb2.AttestConnectionResponse.FromString(
            response_body
        )
      return attest_resp
    except Exception as e:
      # If the socket was closed by the server while we were writing,
      # we might get a read error.
      raise exceptions.AttestationHandshakeError(
          "Connection error reading response"
      ) from e

  def _perform_attestation_handshake(self) -> None:
    """Executes server-only or mutual post-handshake attestation."""
    try:
      if self._mutual_attestation:
        self._perform_mutual_attestation()
      else:
        self._perform_server_attestation()

      # Update timestamp on success
      self._last_attestation_time = time.time()

    except (socket.error, ssl.SSLError) as e:
      raise exceptions.AttestationHandshakeError(
          "Network error during attestation"
      ) from e

  def _send_attestation_request(
      self, request: attestation_pb2.AttestConnectionRequest
  ) -> attestation_pb2.AttestConnectionResponse:
    """Sends the attestation flight over the established TLS socket."""
    json_body = json_format.MessageToJson(request)
    # Note: We call the superclass's `request` method explicitly here to
    # avoid a recursive loop during the handshake.
    # Using HTTPConnection request method to send raw bytes.
    super().request(
        "POST",
        constants.ATTESTATION_ENDPOINT,
        body=json_body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, application/x-protobuf",
        },
    )
    return self._process_attestation_response(self.getresponse())

  def _perform_server_attestation(self) -> None:
    """Runs the server-only exchange, challenging with a fresh client nonce."""
    # A. Generate a fresh nonce
    nonce = secrets.token_bytes(constants.NONCE_LENGTH)

    attestation_req = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
        nonce=nonce,
    )
    # B. Send Request
    attest_resp = self._send_attestation_request(attestation_req)
    if self.sock is None:
      raise exceptions.AttestationHandshakeError(
          "The server closed the connection during attestation."
      )

    # C. Export Keying Material
    tls_ekm = self._ekm_exporter_fn(
        self.sock,  # pyrefly: ignore[bad-argument-type]
        constants.EKM_LENGTH,
        constants.EKM_LABEL,
        context=nonce,
    )

    # D. Validate
    self._validate_server_proof(attest_resp, tls_ekm)

  def _perform_mutual_attestation(self) -> None:
    """Runs the one-round-trip mutual exchange.

    The EKM is exported with no context, so both peers derive the same value
    straight from the TLS session and neither has to contribute a nonce. That
    is sound only for a TLS 1.3 session, so any other session is refused
    before the client signs or sends its proof.

    Raises:
      exceptions.AttestationHandshakeError: If the session is not TLS 1.3, if
        this client's identity is unavailable, or if the server does not
        complete the mutual exchange.
    """
    tls_version = self.sock.version()  # pyrefly: ignore[missing-attribute]
    if tls_version != attestation_protocol.MUTUAL_ATTESTATION_TLS_VERSION:
      raise exceptions.AttestationHandshakeError(
          "Mutual attestation requires"
          f" {attestation_protocol.MUTUAL_ATTESTATION_TLS_VERSION}, but the"
          f" session uses {tls_version}."
      )

    # A. Export Keying Material -- this is the challenge for both peers.
    tls_ekm = self._ekm_exporter_fn(
        self.sock,  # pyrefly: ignore[bad-argument-type]
        constants.EKM_LENGTH,
        constants.MUTUAL_EKM_LABEL,
    )

    # B. Prove our own identity before asking the server for its proof.
    try:
      client_proof = self._attestation_prover.create_proof(
          tls_ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )
    except (OSError, ValueError, RuntimeError, tink.TinkError) as e:
      # Not a network error: the key or token files of this client are
      # missing or unreadable, for example because its TokenManager has not
      # started.
      raise exceptions.AttestationHandshakeError(
          "This client's attestation identity is unavailable."
      ) from e
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
        protocol_version=(
            attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
        ),
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        client_attestation=client_proof,
    )
    response = self._send_attestation_request(request)

    # C. Fail closed unless the server echoed the mode we asked for. A server
    # that answers with a server-only proof must not be silently accepted.
    if (
        response.protocol_version
        != attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
        or response.mode != attestation_pb2.ATTESTATION_MODE_MUTUAL
        or not response.mutual_attestation_complete
    ):
      raise exceptions.AttestationHandshakeError(
          "Mutual attestation negotiation failed; refusing server-only"
          " downgrade."
      )

    # D. Validate the server proof against the same binding.
    self._validate_server_proof(
        response,
        tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        client_proof=client_proof,
    )

  def _validate_server_proof(
      self,
      response: attestation_pb2.AttestConnectionResponse,
      tls_ekm: bytes,
      *,
      peer_role: attestation_pb2.AttestationPeerRole = (
          attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED
      ),
      mode: attestation_pb2.AttestationMode = (
          attestation_pb2.ATTESTATION_MODE_SERVER_ONLY
      ),
      client_proof: attestation_pb2.AttestationProof | None = None,
  ) -> None:
    """Validates a server proof and releases validator-owned resources.

    In mutual mode, also records when the earliest of the server's or client's
    attestation tokens expires so the connection is retired before either peer's
    evidence lapses.

    Args:
      response: The server's attestation proof.
      tls_ekm: The exported keying material the proof is bound to.
      peer_role: The role the server proof must have been produced under.
      mode: The attestation mode the server proof must have been produced under.
      client_proof: The client's own proof sent during mutual attestation, used
        to bound session lifetime by the client token's expiry as well. None in
        server-only mode.

    Raises:
      exceptions.AttestationVerificationError: If the proof does not verify.
      exceptions.PolicyViolationError: If the peer fails the policy check.
    """
    server_validator = self._attestation_validator_cls(self._policy)
    try:
      if self._mutual_attestation:
        claims = server_validator.validate(
            response, tls_ekm, peer_role=peer_role, mode=mode
        )
      else:
        claims = server_validator.validate(response, tls_ekm)
    finally:
      server_validator.close()

    if self._mutual_attestation:
      expiries = [validator.verified_expiry(claims)]
      if client_proof is not None:
        client_exp = _extract_token_exp(client_proof)
        if client_exp is not None:
          expiries.append(client_exp)
      self._attestation_expires_at = min(expiries)

  def connect(self) -> None:
    """Establishes the TLS connection and performs attestation."""
    try:
      # 1. Standard TLS Connection (Creates self.sock)
      super().connect()

      # 2. Post-Handshake Attestation
      self._perform_attestation_handshake()
      if self.sock is None:
        raise exceptions.AttestationHandshakeError(
            "The server closed the connection after attestation."
        )
    except BaseException:
      # A failed TLS handshake can leave the plain TCP socket in self.sock.
      # Close it, so that the next request connects again.
      self.close()
      raise
    else:
      self.is_attested = True

  def request(self, method, url, body=None, headers=None, **kwargs) -> None:
    """Overrides request to connect if closed and to revalidate if stale.

    A closed connection connects, and so attests, before it sends anything.
    Using **kwargs ensures compatibility with different versions of
    urllib3/requests
    that might pass 'chunked', 'encode_chunked', or other arguments.

    Args:
      method: The HTTP method (e.g., "GET", "POST").
      url: The URL to request.
      body: The request body.
      headers: Dictionary of HTTP headers.
      **kwargs: Additional keyword arguments to pass to the superclass request
        method.

    Raises:
      exceptions.PromptEncryptionError: If the attestation of a closed
        connection fails, or if session revalidation fails before sending the
        request.
      urllib3.exceptions.HTTPError: If a closed connection cannot connect
        again, for example `NewConnectionError`.
      OSError: If the TLS handshake of a closed connection fails.
    """
    # A closed connection connects, and so attests, before it sends. Otherwise
    # http.client would reconnect inside send(), and the attestation request
    # would start while this request is half sent. An open connection
    # revalidates if its attestation is older than the revalidation time.
    if self.sock is None:
      self.connect()
    elif self.is_attested and self._should_revalidate():
      logger.info(
          "Session age exceeds %s. Revalidating...",
          self._revalidation_timeout,
      )
      try:
        self.revalidate_session()
      except Exception as e:
        # If revalidation fails, we cannot safely send the request.
        self.close()
        raise exceptions.PromptEncryptionError(
            "Session revalidation failed"
        ) from e

    # Proceed with standard request, passing all arguments through
    super().request(method, url, body=body, headers=headers, **kwargs)

  def _should_revalidate(self) -> bool:
    """Checks if the time since last attestation exceeds the timeout."""
    # A mutual session binds to the session EKM, which never changes, so
    # re-attesting it would prove nothing. The server drops such a session.
    if self._mutual_attestation:
      return False

    # Initial connection case
    if self._last_attestation_time == 0.0:
      return False

    return (
        time.time() - self._last_attestation_time
    ) > self._revalidation_timeout.total_seconds()

  def revalidate_session(self) -> None:
    """Performs session revalidation on the existing connection.

    Triggers a fresh attestation handshake to verify key rotation and validity.

    Raises:
      exceptions.PromptEncryptionError: If the socket is closed, or if this is
        a mutually attested session, which cannot be revalidated.
    """
    if self._mutual_attestation:
      raise exceptions.PromptEncryptionError(
          "Mutually attested sessions cannot be revalidated. Open a new"
          " connection to re-attest."
      )
    if self.sock is None:
      raise exceptions.PromptEncryptionError(
          "Cannot revalidate: Socket is closed."
      )

    try:
      self._perform_attestation_handshake()
      logger.info("Session revalidation successful.")
    except Exception as e:
      self.close()
      raise exceptions.AttestationVerificationError(
          "Revalidation failed"
      ) from e

  def is_expired(self) -> bool:
    """Reports whether the peer's attestation token has run out.

    The margin makes the client give up on the connection slightly before the
    server does, so a request in flight does not race the server's own check.

    Returns:
      True if the connection should be retired rather than reused.
    """
    return (
        self._attestation_expires_at is not None
        and time.time() + _EXPIRY_MARGIN_SECONDS >= self._attestation_expires_at
    )

  def close(self) -> None:
    """Closes the socket and forgets the attestation bound to it."""
    try:
      super().close()
    finally:
      self.is_attested = False
      self._attestation_expires_at = None


class AttestedHTTPSConnectionPool(connectionpool.HTTPSConnectionPool):
  """Pool that spawns AttestedHTTPSConnections."""

  ConnectionCls = AttestedHTTPSConnection  # pyrefly: ignore[bad-assignment]

  def __init__(
      self,
      host: str,
      *,
      port: int | None = None,
      policy: attestation_pb2.AttestationPolicy | None = None,
      mutual_attestation: bool = False,
      attestation_prover: attestation_protocol.AttestationProver | None = None,
      revalidation_timeout: datetime.timedelta | float = datetime.timedelta(
          seconds=3300
      ),
      ekm_exporter_fn: Callable[
          ..., bytes
      ] = ekm_exporter.export_keying_material,
      attestation_validator_cls: Callable[
          ..., validator.AttestationValidator
      ] = validator.AttestationValidator,
      **kwargs: Any,
  ):
    """Initializes the instance.

    Args:
      host: The server host.
      port: The server port. None means the HTTPS default.
      policy: The policy that the server must satisfy.
      mutual_attestation: Whether connections also prove this client's own TEE
        identity.
      attestation_prover: Signs this client's proofs. Required in mutual mode;
        None otherwise.
      revalidation_timeout: Seconds or a `timedelta` after which a server-only
        session attests again on the same connection.
      ekm_exporter_fn: Exports the TLS keying material of a socket.
      attestation_validator_cls: Makes the validator for the server's proof.
      **kwargs: Passed to `urllib3.connectionpool.HTTPSConnectionPool`.

    Raises:
      ValueError: If `attestation_prover` is given without
        `mutual_attestation`, or `mutual_attestation` without it.
    """
    validate_mutual_settings(mutual_attestation, attestation_prover)
    kwargs.update({
        "policy": policy,
        "mutual_attestation": mutual_attestation,
        "attestation_prover": attestation_prover,
        "revalidation_timeout": revalidation_timeout,
        "ekm_exporter_fn": ekm_exporter_fn,
        "attestation_validator_cls": attestation_validator_cls,
    })
    self._policy = policy
    self._mutual_attestation = mutual_attestation
    self._revalidation_timeout = revalidation_timeout
    super().__init__(host, port=port, **kwargs)

  def __repr__(self) -> str:
    return (
        f"AttestedHTTPSConnectionPool(host={self.host!r}, port={self.port}, "
        f"mutual_attestation={self._mutual_attestation}, "
        f"revalidation_timeout={self._revalidation_timeout}, "
        f"policy={self._policy!r})"
    )

  def _get_conn(self, timeout: float | None = None) -> Any:
    """Returns a pooled connection, retiring one whose attestation lapsed.

    Args:
      timeout: Seconds to wait for a connection from the pool. None means the
        pool's own timeout.

    Returns:
      A connection. Closing it is enough to retire it: the HTTPS pool calls
      `connect()` on a closed connection before it sends the request, which
      reruns the TLS handshake and the attestation handshake.
    """
    conn = super()._get_conn(timeout=timeout)
    if isinstance(conn, AttestedHTTPSConnection) and conn.is_expired():
      logger.info("Attestation expired on a pooled connection; reconnecting.")
      conn.close()
    return conn


class AttestedPoolManager(poolmanager.PoolManager):
  """Manager that creates AttestedHTTPSConnectionPools."""

  def __init__(
      self,
      *,
      policy: attestation_pb2.AttestationPolicy | None = None,
      mutual_attestation: bool = False,
      attestation_prover: attestation_protocol.AttestationProver | None = None,
      revalidation_timeout: datetime.timedelta | float = datetime.timedelta(
          seconds=3300
      ),
      ekm_exporter_fn: Callable[
          ..., bytes
      ] = ekm_exporter.export_keying_material,
      attestation_validator_cls: Callable[
          ..., validator.AttestationValidator
      ] = validator.AttestationValidator,
      **kwargs: Any,
  ):
    """Initializes the instance.

    Args:
      policy: The policy that the server must satisfy.
      mutual_attestation: Whether connections also prove this client's own TEE
        identity.
      attestation_prover: Signs this client's proofs. Required in mutual mode;
        None otherwise.
      revalidation_timeout: Seconds or a `timedelta` after which a server-only
        session attests again on the same connection.
      ekm_exporter_fn: Exports the TLS keying material of a socket.
      attestation_validator_cls: Makes the validator for the server's proof.
      **kwargs: Passed to `urllib3.poolmanager.PoolManager`.

    Raises:
      ValueError: If `attestation_prover` is given without
        `mutual_attestation`, or `mutual_attestation` without it.
    """
    validate_mutual_settings(mutual_attestation, attestation_prover)
    self._policy = policy
    self._mutual_attestation = mutual_attestation
    self._attestation_prover = attestation_prover
    self._revalidation_timeout = revalidation_timeout
    self._ekm_exporter_fn = ekm_exporter_fn
    self._attestation_validator_cls = attestation_validator_cls
    super().__init__(**kwargs)

  def __repr__(self) -> str:
    return (
        f"AttestedPoolManager(mutual_attestation={self._mutual_attestation},"
        f" revalidation_timeout={self._revalidation_timeout},"
        f" policy={self._policy!r})"
    )

  def _new_pool(
      self, scheme, host, port, request_context=None
  ) -> connectionpool.HTTPConnectionPool:
    """Injects custom pool class for HTTPS schemes."""
    if scheme == "https":
      return AttestedHTTPSConnectionPool(
          host,
          port=port,
          policy=self._policy,
          mutual_attestation=self._mutual_attestation,
          attestation_prover=self._attestation_prover,
          ekm_exporter_fn=self._ekm_exporter_fn,
          attestation_validator_cls=self._attestation_validator_cls,
          revalidation_timeout=self._revalidation_timeout,
          **self.connection_pool_kw,
      )
    return super()._new_pool(scheme, host, port, request_context)
