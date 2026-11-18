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

from typing import Any

from absl import logging
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.ekm import exporter
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import token


def _export_ekm(ssl_obj: Any, *, context: bytes) -> bytes:
  """Extracts EKM using the standard library, falling back to the C extension.

  Args:
    ssl_obj: The SSL object from the TLS connection.
    context: RFC 5705 context. The server-only flow uses the client nonce.

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


class AttestedTLS:
  """Handles AttestConnection logic."""

  def __init__(self, token_manager: token.TokenManager):
    self.token_manager = token_manager
    self._prover = attestation_protocol.AttestationProver(token_manager)

  def __repr__(self):
    return f"AttestedTLS(token_manager={self.token_manager!r})"

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

    Args:
      request: The AttestConnectionRequest message.
      ssl_obj: The SSL object from the TLS connection.

    Returns:
      An AttestConnectionResponse message containing the attestation token and
      the server's public key and signed TLS session material.

    Raises:
      ValueError: If no required_verifier_type is specified or if an unsupported
        verifier type is requested.
      RuntimeError: If EKM extraction fails, or if this server has no
        attestation token yet.
    """
    attestation_protocol.validate_required_verifiers(
        request.required_verifier_type
    )
    tls_ekm = _export_ekm(ssl_obj, context=request.nonce)
    return attestation_protocol.response_from_proof(
        self._prover.create_proof(tls_ekm)
    )
