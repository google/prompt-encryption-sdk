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

"""Tests for the AttestationValidator and OIDCTokenValidator classes."""

import hashlib
import json
from typing import Any
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk.client import constants
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.proto import attestation_pb2
import jwt
import requests
import tink
from tink import jwt as tink_jwt


# --- Deterministic Test Constants ---
# Using fixed constants ensures tests are hermetic and repeatable.
_FAKE_IMAGE_HASH = (
    "sha256:67682bda769fae1ccf5183192b8daf37b64cae99c6c3302650f6f8bf5f0f95df"
)
_FAKE_SIGNING_KEY = (
    "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/v"
)
_FAKE_PROJECT = "confidential-ai-2"
_FAKE_ZONE = "us-central1-a"
_FAKE_INSTANCE_NAME = "mhv-test-atls2"
_FAKE_INSTANCE_ID = "2725765997796889912"
_FAKE_PUB_KEY = b"fake-ecdsa-public-key-bytes"
_FAKE_SESSION_SIGNATURE = b"fake-session-signature"
_FAKE_CHALLENGE_NONCE = b"0123456789abcdef0123456789abcdef"


def _get_valid_claims(nonce: bytes | None = None) -> dict[str, Any]:
  """Returns deterministic claims matching the GCA profile."""
  pub_key_nonce = hashlib.sha256(_FAKE_PUB_KEY).hexdigest()
  eat_nonce_list = (
      [pub_key_nonce, nonce.hex()] if nonce else [pub_key_nonce]
  )

  return {
      "hwmodel": "GCP_AMD_SEV",
      "eat_nonce": eat_nonce_list,
      "submods": {
          "container": {
              "image_digest": _FAKE_IMAGE_HASH,
              "image_signatures": [{"key_id": _FAKE_SIGNING_KEY}],
          },
          "gce": {
              "project_id": _FAKE_PROJECT,
              "zone": _FAKE_ZONE,
              "instance_name": _FAKE_INSTANCE_NAME,
              "instance_id": _FAKE_INSTANCE_ID,
          },
      },
  }


class AttestationValidatorTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_get = self.enter_context(
        mock.patch.object(requests.Session, "get", autospec=True)
    )
    self.policy = attestation_pb2.AttestationPolicy()
    self.mock_pem_loader = mock.Mock(
        spec=validator.serialization.load_pem_public_key
    )
    self.mock_ec_pub_key = mock.create_autospec(
        validator.ec.EllipticCurvePublicKey, instance=True
    )
    self.mock_pem_loader.return_value = self.mock_ec_pub_key
    self.validator = validator.AttestationValidator(
        self.policy, pem_loader=self.mock_pem_loader
    )

  # --- 1. Instance Key Binding Tests ---

  def test_verify_instance_key_binding_success(self):
    """Tests that a matching public key hash passes validation."""
    claims = _get_valid_claims()
    self.validator._verify_instance_key_binding(claims, _FAKE_PUB_KEY)

  def test_verify_instance_key_binding_single_string_nonce(self):
    """Tests that validator handles 'eat_nonce' as a string instead of a list."""
    pub_key_nonce = hashlib.sha256(_FAKE_PUB_KEY).hexdigest()
    claims = {"eat_nonce": pub_key_nonce}
    self.validator._verify_instance_key_binding(claims, _FAKE_PUB_KEY)

  def test_verify_instance_key_binding_fails_on_mismatch(self):
    """Tests that mismatched public key triggers an error."""
    claims = _get_valid_claims()
    wrong_key = b"different-public-key-material"
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "Instance Key binding failed"
    ):
      self.validator._verify_instance_key_binding(claims, wrong_key)

  def test_verify_instance_key_binding_fails_on_empty_nonce(self):
    """Tests that missing eat_nonce claim triggers an error."""
    claims = {}
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "No eat_nonce claim found in OIDC token.",
    ):
      self.validator._verify_instance_key_binding(claims, _FAKE_PUB_KEY)

  def test_verify_instance_key_binding_fails_on_none_nonce(self):
    """Tests that eat_nonce claim being None triggers an error."""
    claims = {"eat_nonce": None}
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "No eat_nonce claim found in OIDC token.",
    ):
      self.validator._verify_instance_key_binding(claims, _FAKE_PUB_KEY)

  def test_verify_nonce_success(self):
    """Tests that verification passes when the correct nonce is present."""
    # We pass the nonce to the helper so it's included in the mock OIDC claims
    claims = _get_valid_claims(nonce=_FAKE_CHALLENGE_NONCE)
    self.validator._verify_instance_key_binding(
        claims, _FAKE_PUB_KEY, expected_nonce=_FAKE_CHALLENGE_NONCE
    )

  def test_verify_nonce_fails_on_mismatch(self):
    """Tests that verification fails if the challenge nonce is missing from the token."""
    # Claims only contains the pubkey hash, simulating a replayed/stale token
    claims = _get_valid_claims(nonce=None)
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "Nonce verification failed"
    ):
      self.validator._verify_instance_key_binding(
          claims, _FAKE_PUB_KEY, expected_nonce=_FAKE_CHALLENGE_NONCE
      )
  # --- 2. Policy Enforcement Tests ---

  @parameterized.named_parameters(
      (
          "hw_model_mismatch",
          attestation_pb2.AttestationPolicy(
              hw_model=attestation_pb2.HARDWARE_MODEL_TDX
          ),
          "Hardware model mismatch",
      ),
      (
          "image_hash_mismatch",
          attestation_pb2.AttestationPolicy(
              workload=attestation_pb2.WorkloadPolicy(image_hash="wrong_hash")
          ),
          "Workload image hash mismatch",
      ),
      (
          "signing_key_missing",
          attestation_pb2.AttestationPolicy(
              workload=attestation_pb2.WorkloadPolicy(
                  signing_key_id="other_key"
              )
          ),
          "Workload image not signed by trusted key",
      ),
      (
          "project_id_mismatch",
          attestation_pb2.AttestationPolicy(
              gce_instance=attestation_pb2.GceInstancePolicy(
                  project_id="wrong-proj"
              )
          ),
          "GCE Instance project_id mismatch",
      ),
      (
          "zone_mismatch",
          attestation_pb2.AttestationPolicy(
              gce_instance=attestation_pb2.GceInstancePolicy(
                  zone="europe-west1-b"
              )
          ),
          "GCE Instance zone mismatch",
      ),
  )
  def test_enforce_policy_violations(self, policy, expected_error):
    """Tests that policy mismatches trigger PolicyViolationError."""
    self.validator._policy = policy
    claims = _get_valid_claims()

    with self.assertRaisesRegex(
        exceptions.PolicyViolationError, expected_error
    ):
      self.validator._enforce_policy(claims)

  def test_enforce_policy_optional_fields_ignored(self):
    """Ensures fields NOT set in policy are NOT validated."""
    self.validator._policy = attestation_pb2.AttestationPolicy(
        hw_model=attestation_pb2.HARDWARE_MODEL_SEV
    )

    claims = _get_valid_claims()
    claims["submods"]["gce"]["project_id"] = "different-untracked-project"

    # Should pass because project_id is not in the active policy.
    self.validator._enforce_policy(claims)

  def test_enforce_policy_missing_claim_fails(self):
    """Tests that a missing claim expected by the policy raises an error."""
    policy = attestation_pb2.AttestationPolicy(
        workload=attestation_pb2.WorkloadPolicy(image_hash=_FAKE_IMAGE_HASH)
    )
    self.validator._policy = policy
    claims = _get_valid_claims()
    # Remove the claim expected by the policy
    del claims["submods"]["container"]["image_digest"]

    with self.assertRaisesRegex(
        exceptions.PolicyViolationError,
        f"Workload image hash mismatch. Expected {_FAKE_IMAGE_HASH}, got None",
    ):
      self.validator._enforce_policy(claims)

  @parameterized.named_parameters(
      (
          "unknown_hw_model",
          attestation_pb2.AttestationPolicy(hw_model=999),
          {"hwmodel": None},
          "not supported by the validator",
      ),
      (
          "malformed_structure",
          attestation_pb2.AttestationPolicy(),
          {"submods": "malicious_string"},
          "Malformed token structure",
      ),
      (
          "missing_sub_mapping",
          attestation_pb2.AttestationPolicy(),
          {"submods": {"container": ["not", "a", "dict"]}},
          "Malformed token structure",
      ),
      (
          "malformed_image_signatures_type",
          attestation_pb2.AttestationPolicy(
              workload=attestation_pb2.WorkloadPolicy(
                  signing_key_id=_FAKE_SIGNING_KEY
              )
          ),
          {
              "submods": {
                  "container": {"image_signatures": "not_a_list"},
                  "gce": {},
              }
          },
          "Malformed image signatures claim.",
      ),
      (
          "malformed_image_signatures_element_type",
          attestation_pb2.AttestationPolicy(
              workload=attestation_pb2.WorkloadPolicy(
                  signing_key_id=_FAKE_SIGNING_KEY
              )
          ),
          {
              "submods": {
                  "container": {"image_signatures": [123]},
                  "gce": {},
              }
          },
          "Malformed image signatures claim.",
      ),
  )
  def test_enforce_policy_malformed_or_unsupported_fails(
      self, policy, claims, expected_error
  ):
    """Verifies that unknown model or malformed/invalid claims trigger an error."""
    self.validator._policy = policy
    with self.assertRaisesRegex(
        exceptions.PolicyViolationError, expected_error
    ):
      self.validator._enforce_policy(claims)

  # --- 3. Main Validation Orchestration Tests ---

  def test_validate_full_success(self):
    """Tests the full validation flow including token extraction."""
    mock_oidc = self.enter_context(
        mock.patch.object(
            validator.OIDCTokenValidator, "validate_token", autospec=True
        )
    )
    mock_oidc.return_value = _get_valid_claims(nonce=_FAKE_CHALLENGE_NONCE)
    mock_verify_session_signature = self.enter_context(
        mock.patch.object(
            self.validator, "_verify_session_signature", autospec=True
        )
    )

    response = attestation_pb2.AttestConnectionResponse(
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=_FAKE_PUB_KEY
        ),
        session_signature=_FAKE_SESSION_SIGNATURE,
        evidence=[
            attestation_pb2.AttestationEvidence(
                verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
                gca_bundle=attestation_pb2.GcaTrustBundle(
                    attestation_token="valid.jwt.payload"
                ),
            ),
        ],
    )

    self.validator.validate(
        response,
        tls_ekm=b"fake_ekm_material",
        expected_nonce=_FAKE_CHALLENGE_NONCE,
    )
    mock_oidc.assert_called_once_with(mock.ANY, "valid.jwt.payload")
    mock_verify_session_signature.assert_called_once()

  def test_validate_nonce_mismatch_fails(self):
    """Tests that validate() raises an error if the challenge nonce is mismatched."""
    mock_oidc = self.enter_context(
        mock.patch.object(
            validator.OIDCTokenValidator, "validate_token", autospec=True
        )
    )
    # Return claims that do NOT contain the expected nonce
    mock_oidc.return_value = _get_valid_claims(nonce=None)

    response = attestation_pb2.AttestConnectionResponse(
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=_FAKE_PUB_KEY
        ),
        session_signature=_FAKE_SESSION_SIGNATURE,
        evidence=[
            attestation_pb2.AttestationEvidence(
                verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
                gca_bundle=attestation_pb2.GcaTrustBundle(
                    attestation_token="valid.jwt.payload"
                ),
            ),
        ],
    )

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "Nonce verification failed"
    ):
      self.validator.validate(
          response,
          tls_ekm=b"fake_ekm_material",
          expected_nonce=_FAKE_CHALLENGE_NONCE,
      )

  def test_validate_no_evidence_fails(self):
    """Tests failure when no attestation evidence is provided."""
    response = attestation_pb2.AttestConnectionResponse()
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "No attestation evidence provided",
    ):
      self.validator.validate(response, tls_ekm=b"")

  def test_validate_missing_gca_evidence_fails(self):
    """Tests failure when GCA evidence is missing."""
    response = attestation_pb2.AttestConnectionResponse()
    response.evidence.add(
        verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_UNSPECIFIED
    )
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "required GCA evidence missing"
    ):
      self.validator.validate(response, tls_ekm=b"")

  def test_validate_empty_attestation_token_fails(self):
    """Tests failure when GCA attestation token is empty."""
    response = attestation_pb2.AttestConnectionResponse()
    response.evidence.add(
        verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
    )
    # gca_bundle exists but attestation_token is empty
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "GCA attestation token is empty",
    ):
      self.validator.validate(response, tls_ekm=b"")

  def test_validate_missing_instance_public_key_fails(self):
    """Tests failure when instance public key is missing."""
    with mock.patch.object(
        self.validator._oidc_validator,
        "validate_token",
        return_value=_get_valid_claims(),
        autospec=True,
    ):
      response = attestation_pb2.AttestConnectionResponse(
          evidence=[
              attestation_pb2.AttestationEvidence(
                  verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
                  gca_bundle=attestation_pb2.GcaTrustBundle(
                      attestation_token="valid.jwt.payload"
                  ),
              ),
          ],
          # instance_public_key is missing
      )
      with self.assertRaisesRegex(
          exceptions.AttestationVerificationError,
          "Instance public key is missing",
      ):
        self.validator.validate(response, tls_ekm=b"")

  def test_validate_missing_session_signature_fails(self):
    with mock.patch.object(
        self.validator._oidc_validator,
        "validate_token",
        return_value=_get_valid_claims(),
        autospec=True,
    ):
      response = attestation_pb2.AttestConnectionResponse(
          instance_public_key=attestation_pb2.EcdsaP256PublicKey(
              key_bytes=_FAKE_PUB_KEY
          ),
          evidence=[
              attestation_pb2.AttestationEvidence(
                  verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
                  gca_bundle=attestation_pb2.GcaTrustBundle(
                      attestation_token="valid.jwt.payload"
                  ),
              ),
          ],
          # session_signature is missing
      )
      with self.assertRaisesRegex(
          exceptions.AttestationVerificationError,
          "session signature is missing",
      ):
        self.validator.validate(response, tls_ekm=b"")

  def test_validate_uses_passed_oidc_validator(self):
    """Tests that validate() uses the passed oidc_validator instance."""
    mock_oidc_validator = mock.create_autospec(validator.OIDCTokenValidator)
    mock_oidc_validator.validate_token.return_value = _get_valid_claims()
    av = validator.AttestationValidator(
        self.policy,
        oidc_validator=mock_oidc_validator,
        pem_loader=self.mock_pem_loader,
    )
    self.enter_context(
        mock.patch.object(av, "_verify_session_signature", autospec=True)
    )

    response = attestation_pb2.AttestConnectionResponse(
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=_FAKE_PUB_KEY
        ),
        session_signature=_FAKE_SESSION_SIGNATURE,
        evidence=[
            attestation_pb2.AttestationEvidence(
                verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
                gca_bundle=attestation_pb2.GcaTrustBundle(
                    attestation_token="valid.jwt.payload"
                ),
            ),
        ],
    )

    av.validate(response, tls_ekm=b"fake_ekm_material")
    mock_oidc_validator.validate_token.assert_called_once_with(
        "valid.jwt.payload"
    )

  # --- 4. Resource Management Tests ---

  def test_close_with_owned_oidc_validator_closes_oidc(self):
    """Tests AttestationValidator.close() closes OIDC validator if it owns it."""
    with mock.patch.object(
        validator, "OIDCTokenValidator", autospec=True
    ) as mock_cls:
      av = validator.AttestationValidator(self.policy)
      av.close()
      mock_cls.return_value.close.assert_called_once()

  def test_close_with_passed_oidc_validator_does_not_close_oidc(self):
    """Tests AttestationValidator.close() does not close OIDC validator if it doesn't own it."""
    mock_oidc_validator = mock.create_autospec(validator.OIDCTokenValidator)
    av = validator.AttestationValidator(
        self.policy, oidc_validator=mock_oidc_validator
    )
    av.close()
    mock_oidc_validator.close.assert_not_called()

  def test_validate_calls_enforce_policy_and_key_binding(self):
    """Tests that validate() calls _enforce_policy and _verify_instance_key_binding."""
    mock_oidc = self.enter_context(
        mock.patch.object(
            validator.OIDCTokenValidator, "validate_token", autospec=True
        )
    )
    claims = _get_valid_claims()
    mock_oidc.return_value = claims

    # We wrap the existing methods in mocks so we can verify they were called
    # while still allowing them to execute their logic.
    with mock.patch.object(
        self.validator, "_enforce_policy", wraps=self.validator._enforce_policy
    ) as spy_policy:
      with mock.patch.object(
          self.validator,
          "_verify_instance_key_binding",
          wraps=self.validator._verify_instance_key_binding,
      ) as spy_binding:
        with mock.patch.object(
            self.validator,
            "_verify_session_signature",
            wraps=self.validator._verify_session_signature,
        ) as spy_sig:
          response = attestation_pb2.AttestConnectionResponse(
              instance_public_key=attestation_pb2.EcdsaP256PublicKey(
                  key_bytes=_FAKE_PUB_KEY
              ),
              session_signature=_FAKE_SESSION_SIGNATURE,
              evidence=[
                  attestation_pb2.AttestationEvidence(
                      verifier_type=(
                          attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
                      ),
                      gca_bundle=attestation_pb2.GcaTrustBundle(
                          attestation_token="valid.jwt.payload"
                      ),
                  ),
              ],
          )

          self.validator.validate(response, tls_ekm=b"fake_ekm_material")

          with self.subTest(name="enforce_policy_called"):
            spy_policy.assert_called_once_with(claims)
          with self.subTest(name="verify_instance_key_binding_called"):
            spy_binding.assert_called_once_with(claims, _FAKE_PUB_KEY, expected_nonce=None)
          with self.subTest(name="verify_session_signature_called"):
            spy_sig.assert_called_once()

  # --- 5. Session Signature Verification Tests ---
  def test_verify_session_signature_success(self):
    """Tests successful session signature verification."""
    mock_pub_key = mock.MagicMock(spec=validator.ec.EllipticCurvePublicKey)
    self.mock_pem_loader.return_value = mock_pub_key
    pub_key_proto = attestation_pb2.EcdsaP256PublicKey(key_bytes=_FAKE_PUB_KEY)
    payload = b"payload"

    self.validator._verify_session_signature(
        pub_key_proto, signature=_FAKE_SESSION_SIGNATURE, payload=payload
    )
    self.mock_pem_loader.assert_called_once_with(_FAKE_PUB_KEY)
    mock_pub_key.verify.assert_called_once_with(
        _FAKE_SESSION_SIGNATURE, payload, mock.ANY
    )

  def test_verify_session_signature_fails_on_bad_key_type(self):
    """Tests session signature verification fails with a bad public key type."""
    mock_pub_key = mock.Mock()  # Not an EC key
    self.mock_pem_loader.return_value = mock_pub_key
    pub_key_proto = attestation_pb2.EcdsaP256PublicKey(key_bytes=_FAKE_PUB_KEY)
    payload = b"payload"

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "instance key is not an Elliptic Curve key.",
    ):
      self.validator._verify_session_signature(
          pub_key_proto, signature=_FAKE_SESSION_SIGNATURE, payload=payload
      )
    self.mock_pem_loader.assert_called_once_with(_FAKE_PUB_KEY)
    mock_pub_key.verify.assert_not_called()

  def test_verify_session_signature_fails_on_bad_signature(self):
    """Tests session signature verification fails on an invalid signature."""
    mock_pub_key = mock.MagicMock(spec=validator.ec.EllipticCurvePublicKey)
    mock_pub_key.verify.side_effect = Exception("Invalid signature")
    self.mock_pem_loader.return_value = mock_pub_key
    pub_key_proto = attestation_pb2.EcdsaP256PublicKey(key_bytes=_FAKE_PUB_KEY)
    payload = b"payload"

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "session signature verification failed.",
    ):
      self.validator._verify_session_signature(
          pub_key_proto, signature=_FAKE_SESSION_SIGNATURE, payload=payload
      )
    self.mock_pem_loader.assert_called_once_with(_FAKE_PUB_KEY)
    mock_pub_key.verify.assert_called_once_with(
        _FAKE_SESSION_SIGNATURE, payload, mock.ANY
    )


class OIDCTokenValidatorTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_get = self.enter_context(
        mock.patch.object(requests.Session, "get", autospec=True)
    )

  def test_validate_token_success_and_options(self):
    """Tests that validate_token succeeds with tink-jwt."""
    self.mock_get.return_value.status_code = 200
    self.mock_get.return_value.json.return_value = {
        "issuer": "http://test-issuer",
        "jwks_uri": "http://test-jwks-uri",
    }
    mock_jwk_client = self.enter_context(
        mock.patch.object(jwt, "PyJWKClient", autospec=True)
    )
    jwk_set_dict = {"keys": [{"kid": "123"}]}
    mock_jwk_client.return_value.fetch_data.return_value = jwk_set_dict

    mock_verifier = mock.Mock()
    mock_keyset_handle = mock.Mock()
    mock_keyset_handle.primitive.return_value = mock_verifier

    mock_jwk_set_to_public_keyset_handle = self.enter_context(
        mock.patch.object(
            tink_jwt, "jwk_set_to_public_keyset_handle", autospec=True
        )
    )
    mock_jwk_set_to_public_keyset_handle.return_value = mock_keyset_handle

    mock_tink_validator = mock.Mock()
    mock_new_validator = self.enter_context(
        mock.patch.object(
            tink_jwt, "new_validator", return_value=mock_tink_validator
        )
    )

    mock_verified_jwt = mock.Mock()
    mock_verified_jwt._raw_jwt._payload = {"claim": "value"}
    mock_verifier.verify_and_decode.return_value = mock_verified_jwt

    v = validator.OIDCTokenValidator()
    token = "some.valid.token"
    result = v.validate_token(token)

    self.assertEqual(result, {"claim": "value"})
    mock_jwk_set_to_public_keyset_handle.assert_called_once_with(
        json.dumps(jwk_set_dict)
    )
    mock_keyset_handle.primitive.assert_called_once_with(
        tink_jwt.JwtPublicKeyVerify
    )
    mock_new_validator.assert_called_once_with(
        expected_issuer="http://test-issuer",
        expected_audience=constants.DEFAULT_AUDIENCE,
        expected_type_header="JWT",
    )
    mock_verifier.verify_and_decode.assert_called_once_with(
        token, mock_tink_validator
    )

  def test_oidc_discovery_fallback_on_network_error(self):
    """Tests fallback to defaults if OIDC discovery fails."""
    self.mock_get.side_effect = requests.RequestException("Timeout")

    v = validator.OIDCTokenValidator()
    self.assertEqual(v._issuer, constants.CS_DEFAULT_ISSUER)

  def test_validate_token_failure(self):
    """Tests that JWT decode errors are correctly caught and wrapped."""
    mock_jwk_client = self.enter_context(
        mock.patch.object(jwt, "PyJWKClient", autospec=True)
    )
    mock_jwk_client.return_value.fetch_data.return_value = {"keys": []}

    mock_jwk_set_to_public_keyset_handle = self.enter_context(
        mock.patch.object(
            tink_jwt, "jwk_set_to_public_keyset_handle", autospec=True
        )
    )
    mock_verifier = mock.Mock()
    mock_keyset_handle = mock.Mock()
    mock_keyset_handle.primitive.return_value = mock_verifier
    mock_jwk_set_to_public_keyset_handle.return_value = mock_keyset_handle

    mock_verifier.verify_and_decode.side_effect = tink.TinkError("Bad Signature")

    v = validator.OIDCTokenValidator()

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "OIDC Token validation failed"
    ):
      v.validate_token("some.invalid.token")

  def test_oidc_token_validator_close_closes_session(self):
    mock_session = mock.create_autospec(requests.Session)
    oidc_validator = validator.OIDCTokenValidator(session=mock_session)
    oidc_validator.close()
    mock_session.close.assert_called_once()


if __name__ == "__main__":
  absltest.main()
