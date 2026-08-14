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

"""Provides classes for validating OIDC tokens and attestation evidence."""

from collections.abc import Mapping
import hashlib
import json
import logging
import ssl
import types
from typing import Any

from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import constants
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.proto import attestation_pb2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import jwt
import requests
import tink
from tink import jwt as tink_jwt
from tink import signature as tink_signature

tink_signature.register()


logger = logging.getLogger(__name__)
tink_jwt.register_jwt_signature()


_GCA_STRING_BY_HW_MODEL = types.MappingProxyType(
    {
        attestation_pb2.HARDWARE_MODEL_TDX: "GCP_INTEL_TDX",
        attestation_pb2.HARDWARE_MODEL_SEV: "GCP_AMD_SEV",
        attestation_pb2.HARDWARE_MODEL_SEV_SNP: "GCP_AMD_SEV_SNP",
    }
)
_GCE_POLICY_FIELDS = ("project_id", "zone", "instance_id", "instance_name")


def _safe_get_map(data: Any, key: str) -> Mapping[str, Any]:
  """Safely extracts a nested dictionary, verifying the type."""
  if not isinstance(data, Mapping):
    raise exceptions.AttestationVerificationError(
        f"Expected mapping for claim structure, got {type(data).__name__}"
    )
  val = data.get(key, {})
  if not isinstance(val, Mapping):
    raise exceptions.AttestationVerificationError(
        f"Claim {key!r} is not a mapping (got {type(val).__name__})"
    )
  return val


class OIDCTokenValidator:
  """Validates OIDC tokens issued by Confidential Space using PyJWT."""

  def __init__(self, session: requests.Session | None = None):
    self._session = session or requests.Session()
    self._jwks_client = None
    self._issuer = None
    self._initialize_oidc_config()

  def close(self) -> None:
    """Closes the underlying requests session."""
    self._session.close()

  def _initialize_oidc_config(self):
    """Initializes the JWKS client, preferring Discovery but falling back to static URLs."""
    jwks_uri = constants.CS_DEFAULT_JWKS_URI
    self._issuer = constants.CS_DEFAULT_ISSUER

    try:
      resp = self._session.get(constants.CS_OIDC_DISCOVERY_URL, timeout=5)
      if resp.status_code == 200:
        data = resp.json()
        jwks_uri = data.get("jwks_uri", jwks_uri)
        self._issuer = data.get("issuer", self._issuer)
    except requests.RequestException:
      logger.warning(
          "OIDC Discovery failed; using fallback configuration.", exc_info=True
      )

    # Initialize PyJWT's JWKS Client with the resolved URI
    ssl_context = ssl.create_default_context(cafile=requests.certs.where())
    self._jwks_client = jwt.PyJWKClient(jwks_uri, ssl_context=ssl_context)

  def validate_token(self, token: str) -> dict[str, Any]:
    """Decodes and validates the OIDC token signature and standard claims.

    Args:
        token: The raw JWT string.

    Returns:
        The decoded claims dictionary.
    """
    try:
      # 1. Fetch the signing key that matches the 'kid' in the token header
      assert self._jwks_client is not None
      jwk_set_dict = self._jwks_client.fetch_data()
      jwk_set_json_str = json.dumps(jwk_set_dict)
      public_keyset_handle = tink_jwt.jwk_set_to_public_keyset_handle(jwk_set_json_str)
      verifier = public_keyset_handle.primitive(tink_jwt.JwtPublicKeyVerify)
      validator = tink_jwt.new_validator(
          expected_issuer=self._issuer,
          expected_audience=constants.DEFAULT_AUDIENCE,
          expected_type_header="JWT",
      )
      result = verifier.verify_and_decode(token, validator)
      return result._raw_jwt._payload
    except (tink.TinkError, Exception) as e:
      raise exceptions.AttestationVerificationError(
          "OIDC Token validation failed."
      ) from e


class AttestationValidator:
  """Validates attestation evidence against policies and cryptographic bindings."""

  def __init__(
      self,
      policy: attestation_pb2.AttestationPolicy,
      oidc_validator: OIDCTokenValidator | None = None,
      pem_loader: Any = serialization.load_pem_public_key,
  ):
    self._policy = policy
    self._oidc_validator = oidc_validator or OIDCTokenValidator()
    self._owns_oidc_validator = oidc_validator is None
    self._pem_loader = pem_loader

  def close(self) -> None:
    """Closes resources held by the validator."""
    if self._owns_oidc_validator:
      self._oidc_validator.close()

  def validate(
      self,
      response: attestation_pb2.AttestConnectionResponse,
      tls_ekm: bytes,
      expected_nonce: bytes | None = None,
      *,
      peer_role: int = attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
      mode: int = attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
      transcript_hash_bytes: bytes = b"",
  ) -> None:
    """Validates the AttestConnectionResponse from the server.

    Args:
        response: The parsed proto response.
        tls_ekm: The Exported Keying Material from the TLS socket.
        expected_nonce: The fresh challenge nonce generated by the client.
        peer_role: Expected producer role included in the signed payload.
        mode: Negotiated attestation mode included in the signed payload.
        transcript_hash_bytes: Mutual handshake transcript hash.

    Raises:
        AttestationVerificationError: If validation fails.
        PolicyViolationError: If policy check fails.
    """
    self.validate_proof(
        attestation_protocol.proof_from_response(response),
        tls_ekm,
        expected_nonce=expected_nonce,
        peer_role=peer_role,
        mode=mode,
        transcript_hash_bytes=transcript_hash_bytes,
    )

  def validate_proof(
      self,
      proof: attestation_pb2.AttestationProof,
      tls_ekm: bytes,
      expected_nonce: bytes | None = None,
      *,
      peer_role: int = attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
      mode: int = attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
      transcript_hash_bytes: bytes = b"",
  ) -> None:
    """Validates a role-neutral server or client attestation proof."""
    if not proof.evidence:
      raise exceptions.AttestationVerificationError("No attestation evidence provided.")

    # 1. Extract GCA Bundle
    gca_bundle = next(
        (
            ev.gca_bundle
            for ev in proof.evidence
            if ev.verifier_type == attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
        ),
        None,
    )

    if not gca_bundle:
      raise exceptions.AttestationVerificationError("required GCA evidence missing.")

    if not gca_bundle.attestation_token:
      raise exceptions.AttestationVerificationError("GCA attestation token is empty.")

    # 2. Verify OIDC Token Signature (GCA Validation)
    claims = self._oidc_validator.validate_token(gca_bundle.attestation_token)

    # 3. Policy Enforcement (Workload, Image, Project)
    self._enforce_policy(claims)

    # 4. Verify Instance Key Binding
    # Checks that the Instance Public Key hashes are inside the Token's 'eat_nonce'
    ecdsa_pub_bytes = proof.instance_public_key.key_bytes
    if not ecdsa_pub_bytes:
      raise exceptions.AttestationVerificationError("ECDSA public key is missing.")
    pqc_pub_bytes = proof.pqc_public_key.serialized_public_keyset
    if not pqc_pub_bytes:
      raise exceptions.AttestationVerificationError("PQC public key is missing.")

    self._verify_instance_key_binding(
        claims,
        ecdsa_pub_bytes=ecdsa_pub_bytes,
        pqc_pub_bytes=pqc_pub_bytes,
        expected_nonce=expected_nonce,
    )

    # 5. Verify TLS Session Binding (Signature over EKM)
    if not proof.session_signature:
      raise exceptions.AttestationVerificationError("session signature is missing.")
    if not proof.pqc_session_signature:
      raise exceptions.AttestationVerificationError("PQC session signature is missing.")

    # Reconstruct the payload to verify the cryptographic binding of the
    # TLS session.
    payload = attestation_protocol.build_signature_payload(
        tls_ekm=tls_ekm,
        attestation_token=gca_bundle.attestation_token.encode("utf-8"),
        peer_role=peer_role,
        mode=mode,
        transcript_hash_bytes=transcript_hash_bytes,
    )

    # Verify classical signature
    self._verify_session_signature(
        proof.instance_public_key,
        signature=proof.session_signature,
        payload=payload,
    )

    # Verify PQC signature
    self._verify_session_signature_mldsa(
        proof.pqc_public_key,
        signature=proof.pqc_session_signature,
        payload=payload,
    )

  def _enforce_policy(self, claims: Mapping[str, Any]) -> None:
    """Validates OIDC claims against the configured AttestationPolicy.

    This function follows a "strict validation" model: it only validates fields
    explicitly set in the policy. If a policy field is set but the corresponding
    claim is missing or mismatched, a PolicyViolationError is raised.

    Args:
        claims: The decoded OIDC token claims.

    Raises:
        PolicyViolationError: If policy check fails.
    """
    if not self._policy:
      logger.warning("No attestation policy configured; skipping enforcement.")
      return

    # Extract sub-sections for easier access based on GCA claim structure
    try:
      submods = _safe_get_map(claims, "submods")
      container_claims = _safe_get_map(submods, "container")
      gce_claims = _safe_get_map(submods, "gce")
    except exceptions.AttestationVerificationError as e:
      raise exceptions.PolicyViolationError(f"Malformed token structure: {e}") from e

    # 1. Hardware Model Validation
    # GCA Profile: 'hwmodel' claim contains the TEE type
    if self._policy.hw_model != attestation_pb2.HARDWARE_MODEL_UNSPECIFIED:
      token_hw = claims.get("hwmodel")
      # Map Protocol Buffer Enum to GCA string representations
      # Example: HARDWARE_MODEL_SEV -> "GCP_AMD_SEV"
      expected_hw_string = _GCA_STRING_BY_HW_MODEL.get(self._policy.hw_model)

      # Explicitly fail if the policy specifies a model unknown to the validator
      if expected_hw_string is None:
        raise exceptions.PolicyViolationError(
            f"Policy requires hardware model {self._policy.hw_model}, "
            "but this model is not supported by the validator."
        )

      if token_hw != expected_hw_string:
        raise exceptions.PolicyViolationError(
            f"Hardware model mismatch. Expected {expected_hw_string!r}, got"
            f" {token_hw!r}"
        )

    # 2. Workload Policy Validation
    if self._policy.HasField("workload"):
      workload_policy = self._policy.workload
      # 2a. Image Hash Validation
      if workload_policy.image_hash:
        token_digest = container_claims.get("image_digest")
        if token_digest != workload_policy.image_hash:
          raise exceptions.PolicyViolationError(
              "Workload image hash mismatch. Expected"
              f" {workload_policy.image_hash}, got {token_digest}"
          )

      # 2b. Signing Key Validation (Workload Image Signature)
      # Validates if any of the image signatures were produced by the trusted key
      if workload_policy.signing_key_id:
        signatures = container_claims.get("image_signatures", [])
        if not isinstance(signatures, list) or not all(
            isinstance(sig, Mapping) for sig in signatures
        ):
          raise exceptions.PolicyViolationError("Malformed image signatures claim.")
        # Check if any signature key_id matches the policy
        found_key = any(
            sig.get("key_id") == workload_policy.signing_key_id for sig in signatures
        )

        if not found_key:
          raise exceptions.PolicyViolationError(
              "Workload image not signed by trusted key:"
              f" {workload_policy.signing_key_id}"
          )

    # 3. GCE Instance Policy Validation
    # These properties ensure the workload runs in the correct project/zone
    if self._policy.HasField("gce_instance"):
      gce_policy = self._policy.gce_instance

      for field_name in _GCE_POLICY_FIELDS:
        expected_value = getattr(gce_policy, field_name)
        # Only validate if the field is set in the policy
        if not expected_value:
          continue
        actual_value = gce_claims.get(field_name)
        if actual_value != expected_value:
          raise exceptions.PolicyViolationError(
              f"GCE Instance {field_name} mismatch. "
              f"Expected {expected_value}, got {actual_value}"
          )

  def _verify_instance_key_binding(
      self,
      claims: Mapping[str, Any],
      ecdsa_pub_bytes: bytes,
      pqc_pub_bytes: bytes,
      expected_nonce: bytes | None = None,
  ) -> None:
    """Verifies that the instance key hashes match the token's eat_nonce.

    Args:
        claims: The decoded OIDC token claims.
        ecdsa_pub_bytes: The raw bytes of ECDSA public key.
        pqc_pub_bytes: The serialized PQC public keyset.
        expected_nonce: The fresh challenge nonce generated by the client.

    Raises:
        AttestationVerificationError: If instance key binding fails.
    """

    # 1. Calculate Hex Digests of the received public keys
    ecdsa_fingerprint = hashlib.sha256(ecdsa_pub_bytes).hexdigest()
    pqc_fingerprint = hashlib.sha256(pqc_pub_bytes).hexdigest()

    # 2. Extract eat_nonce from claims
    eat_nonce = claims.get("eat_nonce")

    if not eat_nonce:
      raise exceptions.AttestationVerificationError(
          "No eat_nonce claim found in OIDC token."
      )

    # Normalize to list
    eat_nonce_list = [eat_nonce] if isinstance(eat_nonce, str) else eat_nonce

    # 3. Check for existence
    if ecdsa_fingerprint not in eat_nonce_list:
      raise exceptions.AttestationVerificationError(
          "ECDSA Instance Key binding failed. Key fingerprint"
          f" {ecdsa_fingerprint} not found in token nonces {eat_nonce_list!r}."
      )
    if pqc_fingerprint not in eat_nonce_list:
      raise exceptions.AttestationVerificationError(
          "PQC Instance Key binding failed. Key fingerprint"
          f" {pqc_fingerprint} not found in token nonces {eat_nonce_list!r}."
      )

    # 4. Check for freshness (challenge nonce)
    if expected_nonce is not None:
      challenge_nonce_hex = expected_nonce.hex()
      if challenge_nonce_hex not in eat_nonce_list:
        raise exceptions.AttestationVerificationError(
            "Nonce verification failed. Expected challenge nonce"
            f" {challenge_nonce_hex} not found in token nonces"
            f" {eat_nonce_list!r}."
        )

  def _verify_session_signature(
      self,
      pub_key_proto: attestation_pb2.EcdsaP256PublicKey,
      *,
      signature: bytes,
      payload: bytes,
  ) -> None:
    """Verifies that the signature is valid for the given payload.

    Args:
        pub_key_proto: The ECDSA P256 public key used for verification.
        signature: The signature bytes to verify.
        payload: The payload bytes that were signed.

    Raises:
        AttestationVerificationError: If the public key is invalid, not an
          Elliptic Curve key, or the signature verification fails.
    """
    try:
      public_key = self._pem_loader(pub_key_proto.key_bytes)

      if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise exceptions.AttestationVerificationError(
            "instance key is not an Elliptic Curve key."
        )

      public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
      if isinstance(e, exceptions.AttestationVerificationError):
        raise
      raise exceptions.AttestationVerificationError(
          "session signature verification failed."
      ) from e

  def _verify_session_signature_mldsa(
      self,
      pub_key_proto: attestation_pb2.MlDsaPublicKey,
      *,
      signature: bytes,
      payload: bytes,
  ) -> None:
    """Verifies that the ML-DSA signature is valid for the given payload.

    Args:
        pub_key_proto: The ML-DSA public keyset used for verification.
        signature: The signature bytes to verify.
        payload: The payload bytes that were signed.

    Raises:
        AttestationVerificationError: If signature verification fails or the
          keyset key-type is not ML-DSA.
    """
    try:
      public_handle = tink.proto_keyset_format.parse_without_secret(
          pub_key_proto.serialized_public_keyset
      )
      keyset_info = public_handle.keyset_info()
      if not any(
          key_info.type_url == constants.ML_DSA_PUBLIC_KEY_TYPE_URL
          for key_info in keyset_info.key_info
      ):
        raise exceptions.AttestationVerificationError(
            "PQC keyset key-type is not ML-DSA."
        )

      verifier = public_handle.primitive(tink_signature.PublicKeyVerify)
      verifier.verify(signature, payload)
    except Exception as e:
      if isinstance(e, exceptions.AttestationVerificationError):
        raise
      raise exceptions.AttestationVerificationError(
          "PQC session signature verification failed."
      ) from e
