# Copyright 2026 Google LLC
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
"""

import datetime
import json
import logging
import secrets
import socket
import ssl
import time

from prompt_encryption_sdk.ekm import exporter as ekm_exporter
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.security import config as security_config
from prompt_encryption_sdk.security import logging as security_logging
from prompt_encryption_sdk.security import pinning
from prompt_encryption_sdk.security import replay_protection
from google.protobuf import json_format
from urllib3 import connection
from urllib3 import connectionpool
from urllib3 import poolmanager

from . import constants
from . import exceptions
from . import validator


logger = logging.getLogger(__name__)


class AttestedHTTPSConnection(connection.HTTPSConnection):
  """An HTTPS connection that performs attestation immediately after handshake.

  Inherits from urllib3.connection.HTTPSConnection.
  """

  def __init__(
      self,
      *args,
      ekm_exporter_fn=ekm_exporter.export_keying_material,
      attestation_validator_cls=validator.AttestationValidator,
      security_config_obj=None,
      **kwargs,
  ):
    self._policy = kwargs.pop("policy", None)
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
    
    # Security configuration (optional)
    self._security_config = security_config_obj or security_config.SecurityConfig()
    self._security_logger = (
        security_logging.SecurityLogger(level=self._security_config.security_log_level)
        if self._security_config.enable_security_logging
        else None
    )
    
    # Certificate pinning (optional)
    self._certificate_pinner = None
    if self._security_config.enable_certificate_pinning:
      self._certificate_pinner = pinning.CertificatePinner(
          pinned_fingerprints=self._security_config.pinned_cert_fingerprints,
          security_logger=self._security_logger,
      )
    
    # Replay protection (optional)
    self._replay_validator = None
    if self._security_config.enable_replay_protection:
      self._replay_validator = replay_protection.ReplayProtectionValidator(
          nonce_ttl_seconds=self._security_config.replay_protection_nonce_ttl_seconds,
          timestamp_skew_seconds=self._security_config.replay_protection_timestamp_skew_seconds,
          security_logger=self._security_logger,
      )

    self.is_attested = False
    self._last_attestation_time = 0.0

    super().__init__(*args, **kwargs)

  def __repr__(self) -> str:
    return (
        f"AttestedHTTPSConnection(host={self.host!r}, port={self.port}, "
        f"is_attested={self.is_attested}, "
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
    """Executes the attestation protocol (Request -> Response -> Validate)."""

    # A. Generate a fresh nonce
    nonce = secrets.token_bytes(constants.NONCE_LENGTH)

    attestation_req = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
        nonce=nonce,
    )
    json_body = json_format.MessageToJson(attestation_req)
    # B. Send Request
    try:
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
      response = self.getresponse()
      attest_resp = self._process_attestation_response(response)

      # D. Export Keying Material
      tls_ekm = self._ekm_exporter_fn(
          self.sock, constants.EKM_LENGTH, constants.EKM_LABEL, context=nonce
      )

      # E. Validate
      att_validator = self._attestation_validator_cls(
          self._policy,
          replay_validator=self._replay_validator,
          security_logger=self._security_logger,
      )
      att_validator.validate(attest_resp, tls_ekm, expected_nonce=nonce)

      # Update timestamp on success
      self._last_attestation_time = time.time()

    except (socket.error, ssl.SSLError) as e:
      raise exceptions.AttestationHandshakeError(
          "Network error during attestation"
      ) from e

  def connect(self) -> None:
    """Establishes the TLS connection and performs attestation."""
    # 1. Standard TLS Connection (Creates self.sock)
    super().connect()

    # 2. Certificate Pinning Validation (Optional)
    if self._certificate_pinner:
      cert_der = self._certificate_pinner.get_certificate_der_from_socket(
          self.sock
      )
      if cert_der:
        self._certificate_pinner.validate_certificate(cert_der, self.host)

    # 3. Post-Handshake Attestation
    try:
      self._perform_attestation_handshake()
    except Exception:
      self.close()
      raise
    else:
      self.is_attested = True

  def request(self, method, url, body=None, headers=None, **kwargs) -> None:
    """Overrides request to perform Lazy Session Revalidation.

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
      exceptions.PromptEncryptionError: If session revalidation fails
        before sending the request.
    """
    # Check if we need to revalidate
    if self.is_attested and self._should_revalidate():
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
    # Initial connection case
    if self._last_attestation_time == 0.0:
      return False

    return (
        time.time() - self._last_attestation_time
    ) > self._revalidation_timeout.total_seconds()

  def revalidate_session(self) -> None:
    """Performs session revalidation on the existing connection.

    Triggers a fresh attestation handshake to verify key rotation and validity.
    """
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


class AttestedHTTPSConnectionPool(connectionpool.HTTPSConnectionPool):
  """Pool that spawns AttestedHTTPSConnections."""

  ConnectionCls = AttestedHTTPSConnection

  def __init__(
      self,
      host,
      *,
      port=None,
      policy=None,
      revalidation_timeout=datetime.timedelta(seconds=3300),
      ekm_exporter_fn=ekm_exporter.export_keying_material,
      attestation_validator_cls=validator.AttestationValidator,
      security_config_obj=None,
      **kwargs,
  ):
    kwargs.update({
        "policy": policy,
        "revalidation_timeout": revalidation_timeout,
        "ekm_exporter_fn": ekm_exporter_fn,
        "attestation_validator_cls": attestation_validator_cls,
        "security_config_obj": security_config_obj,
    })
    self._policy = policy
    self._revalidation_timeout = revalidation_timeout
    super().__init__(host, port=port, **kwargs)

  def __repr__(self) -> str:
    return (
        f"AttestedHTTPSConnectionPool(host={self.host!r}, port={self.port}, "
        f"revalidation_timeout={self._revalidation_timeout}, "
        f"policy={self._policy!r})"
    )


class AttestedPoolManager(poolmanager.PoolManager):
  """Manager that creates AttestedHTTPSConnectionPools."""

  def __init__(
      self,
      *,
      policy=None,
      revalidation_timeout=datetime.timedelta(seconds=3300),
      ekm_exporter_fn=ekm_exporter.export_keying_material,
      attestation_validator_cls=validator.AttestationValidator,
      security_config_obj=None,
      **kwargs,
  ):
    self._policy = policy
    self._revalidation_timeout = revalidation_timeout
    self._ekm_exporter_fn = ekm_exporter_fn
    self._attestation_validator_cls = attestation_validator_cls
    self._security_config = security_config_obj or security_config.SecurityConfig()
    super().__init__(**kwargs)

  def __repr__(self) -> str:
    return (
        f"AttestedPoolManager(revalidation_timeout={self._revalidation_timeout},"
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
          ekm_exporter_fn=self._ekm_exporter_fn,
          attestation_validator_cls=self._attestation_validator_cls,
          revalidation_timeout=self._revalidation_timeout,
          security_config_obj=self._security_config,
          **self.connection_pool_kw,
      )
    return super()._new_pool(scheme, host, port, request_context)
