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

import hashlib
from typing import Any

from absl import logging
from prompt_encryption_sdk.ekm import exporter
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import token

_EKM_LABEL = b"EXPORTER-Prompt-Encryption-SDK"

class AttestedTLS:
  """Handles AttestConnection logic."""

  def __init__(self, token_manager: token.TokenManager):
    self.token_manager = token_manager

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
      RuntimeError: If EKM extraction fails.
    """
    if not request.required_verifier_type:
      raise ValueError("At least one required_verifier_type must be specified.")
    ekm_bytes = None
    first_ekm_exception = None
    # Attempt to extract EKM using the standard library.
    # If the standard API fails or is missing, we fallback
    # to a custom exporter, which uses SSL socket injected in request scope by
    # middleware.
    if hasattr(ssl_obj, "export_keying_material"):
      try:
        ekm_bytes = ssl_obj.export_keying_material(
            _EKM_LABEL, 32, context=request.nonce
        )
      except Exception as e:
        # If export_keying_material fails, we will try to extract EKM using
        # exporter.export_keying_material.
        logging.exception("Failed to extract EKM using export_keying_material.")
        first_ekm_exception = e

    if ekm_bytes is None:
      target_obj = getattr(ssl_obj, "_sslobj", ssl_obj)
      ekm_bytes = exporter.export_keying_material(
          sock=target_obj,
          length=32,
          label=_EKM_LABEL,
          context=request.nonce,
      )

    if ekm_bytes is None:
      if first_ekm_exception:
        raise RuntimeError(
            "EKM extraction failed. The initial attempt using"
            " ssl_obj.export_keying_material failed."
        ) from first_ekm_exception
      else:
        raise RuntimeError(
            "EKM extraction failed. Both ssl_obj.export_keying_material and"
            " the fallback exporter failed to extract keying material."
        )

    ecdsa_pub, pqc_pub, attestation_token = (
        self.token_manager.get_identity_snapshot()
    )
    token_hash_bytes = hashlib.sha256(attestation_token).digest()
    ekm_hash_bytes = hashlib.sha256(ekm_bytes).digest()
    payload = attestation_pb2.SessionSignaturePayload(
        ekm_hash=ekm_hash_bytes, token_hash=token_hash_bytes
    )
    ecdsa_signature = self.token_manager.key_manager.sign_payload(
        payload.SerializeToString()
    )
    pqc_signature = self.token_manager.key_manager.sign_payload_mldsa(
        payload.SerializeToString()
    )

    for verifier_type in request.required_verifier_type:
      if verifier_type != attestation_pb2.VerifierType.VERIFIER_TYPE_GCA:
        raise ValueError(
            "Unsupported verifier types requested:"
            f" {request.required_verifier_type}"
        )

    response = attestation_pb2.AttestConnectionResponse(
        evidence=[
            attestation_pb2.AttestationEvidence(
                verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
                gca_bundle=attestation_pb2.GcaTrustBundle(
                    attestation_token=attestation_token.decode("utf-8")
                ),
            )
        ],
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=ecdsa_pub
        ),
        session_signature=ecdsa_signature,
        pqc_public_key=attestation_pb2.MlDsaPublicKey(
            serialized_public_keyset=pqc_pub
        ),
        pqc_session_signature=pqc_signature,
    )
    return response
