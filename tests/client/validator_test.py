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

import datetime
import hashlib
import json
from typing import Any
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk import attestation as attestation_protocol
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
_FAKE_PQC_PUB_KEY = b"fake-pqc-public-keyset-bytes"
_FAKE_PQC_SESSION_SIGNATURE = b"fake-pqc-session-signature"
_FAKE_CHALLENGE_NONCE = b"0123456789abcdef0123456789abcdef"
_FAKE_KEY_ID_1 = "key_fingerprint_1"
_FAKE_KEY_ID_2 = "key_fingerprint_2"
_FAKE_KEY_ID_3 = "key_fingerprint_3"
_ISSUED_AT = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_TOKEN_LIFETIME = datetime.timedelta(hours=1)


def _get_valid_claims(nonce: bytes | None = None) -> dict[str, Any]:
  """Returns deterministic claims matching the GCA profile."""
  ecdsa_nonce = hashlib.sha256(_FAKE_PUB_KEY).hexdigest()
  pqc_nonce = hashlib.sha256(_FAKE_PQC_PUB_KEY).hexdigest()
  eat_nonce_list = [ecdsa_nonce, pqc_nonce]
  if nonce:
    eat_nonce_list.append(nonce.hex())

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
    """Tests that matching public key hashes pass validation."""
    claims = _get_valid_claims()
    self.validator._verify_instance_key_binding(
        claims, _FAKE_PUB_KEY, _FAKE_PQC_PUB_KEY
    )

  def test_verify_instance_key_binding_fails_on_mismatch_ecdsa(self):
    """Tests that mismatched ECDSA public key triggers an error."""
    claims = _get_valid_claims()
    wrong_key = b"different-public-key-material"
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "ECDSA Instance Key binding failed",
    ):
      self.validator._verify_instance_key_binding(
          claims, wrong_key, _FAKE_PQC_PUB_KEY
      )

  def test_verify_instance_key_binding_fails_on_mismatch_pqc(self):
    """Tests that mismatched PQC public key triggers an error."""
    claims = _get_valid_claims()
    wrong_key = b"different-pqc-public-key-material"
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "PQC Instance Key binding failed",
    ):
      self.validator._verify_instance_key_binding(
          claims, _FAKE_PUB_KEY, wrong_key
      )

  def test_verify_instance_key_binding_fails_on_empty_nonce(self):
    """Tests that missing eat_nonce claim triggers an error."""
    claims = {}
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "No eat_nonce claim found in OIDC token.",
    ):
      self.validator._verify_instance_key_binding(
          claims, _FAKE_PUB_KEY, _FAKE_PQC_PUB_KEY
      )

  def test_verify_instance_key_binding_fails_on_none_nonce(self):
    """Tests that eat_nonce claim being None triggers an error."""
    claims = {"eat_nonce": None}
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "No eat_nonce claim found in OIDC token.",
    ):
      self.validator._verify_instance_key_binding(
          claims, _FAKE_PUB_KEY, _FAKE_PQC_PUB_KEY
      )

  @parameterized.named_parameters(
      ("int", 123),
      ("bool", True),
      (
          "dict_keyed_by_fingerprints",
          dict.fromkeys(_get_valid_claims()["eat_nonce"], 1),
      ),
      ("list_with_a_non_string", _get_valid_claims()["eat_nonce"] + [7]),
  )
  def test_verify_instance_key_binding_rejects_a_malformed_nonce(
      self, eat_nonce
  ):
    """A peer token whose eat_nonce is not a string list fails closed."""
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "must be a string or a list of strings",
    ):
      self.validator._verify_instance_key_binding(
          {"eat_nonce": eat_nonce}, _FAKE_PUB_KEY, _FAKE_PQC_PUB_KEY
      )

  def test_verify_instance_key_binding_rejects_identical_key_fingerprints(self):
    """A scalar eat_nonce cannot satisfy both key bindings via one digest."""
    shared_digest = hashlib.sha256(_FAKE_PUB_KEY).hexdigest()
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "ECDSA and PQC instance key fingerprints must be distinct",
    ):
      self.validator._verify_instance_key_binding(
          {"eat_nonce": shared_digest}, _FAKE_PUB_KEY, _FAKE_PUB_KEY
      )

  def test_verify_nonce_success(self):
    """Tests that verification passes when the correct nonce is present."""
    claims = _get_valid_claims(nonce=_FAKE_CHALLENGE_NONCE)
    self.validator._verify_instance_key_binding(
        claims,
        _FAKE_PUB_KEY,
        _FAKE_PQC_PUB_KEY,
        expected_nonce=_FAKE_CHALLENGE_NONCE,
    )

  def test_verify_nonce_fails_on_mismatch(self):
    """Tests that verification fails if the challenge nonce is missing."""
    claims = _get_valid_claims(nonce=None)
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "Nonce verification failed"
    ):
      self.validator._verify_instance_key_binding(
          claims,
          _FAKE_PUB_KEY,
          _FAKE_PQC_PUB_KEY,
          expected_nonce=_FAKE_CHALLENGE_NONCE,
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

  def test_enforce_policy_image_signatures_success(self):
    """Tests that all required image signatures present in claims pass validation."""
    policy = attestation_pb2.AttestationPolicy(
        workload=attestation_pb2.WorkloadPolicy(
            image_signatures=[
                _FAKE_KEY_ID_1,
                f"ECDSA_P256_SHA256:{_FAKE_KEY_ID_2}",
            ]
        )
    )
    self.validator._policy = policy
    claims = _get_valid_claims()
    claims["submods"]["container"]["image_signatures"] = [
        {"key_id": _FAKE_KEY_ID_1, "signature_algorithm": "ECDSA_P256_SHA256"},
        {"key_id": _FAKE_KEY_ID_2, "signature_algorithm": "ECDSA_P256_SHA256"},
        {"key_id": _FAKE_KEY_ID_3, "signature_algorithm": "ECDSA_P256_SHA256"},
    ]
    self.validator._enforce_policy(claims)

  @parameterized.named_parameters(
      (
          "missing_required_key_id",
          [_FAKE_KEY_ID_1, _FAKE_KEY_ID_2],
          [
              {
                  "key_id": _FAKE_KEY_ID_1,
                  "signature_algorithm": "ECDSA_P256_SHA256",
              },
          ],
          f"Missing required container image signature: {_FAKE_KEY_ID_2}",
      ),
      (
          "algorithm_mismatch",
          [f"ECDSA_P256_SHA256:{_FAKE_KEY_ID_1}"],
          [
              {
                  "key_id": _FAKE_KEY_ID_1,
                  "signature_algorithm": "RSASSA_PSS_SHA256",
              },
          ],
          (
              "Missing required container image signature:"
              f" ECDSA_P256_SHA256:{_FAKE_KEY_ID_1}"
          ),
      ),
      (
          "missing_algorithm_in_claim_when_pinned",
          [f"ECDSA_P256_SHA256:{_FAKE_KEY_ID_1}"],
          [
              {"key_id": _FAKE_KEY_ID_1},
          ],
          (
              "Missing required container image signature:"
              f" ECDSA_P256_SHA256:{_FAKE_KEY_ID_1}"
          ),
      ),
      (
          "empty_image_signatures_claim",
          [_FAKE_KEY_ID_1],
          [],
          f"Missing required container image signature: {_FAKE_KEY_ID_1}",
      ),
  )
  def test_enforce_policy_image_signatures_missing_or_mismatched_fails(
      self, required_signatures, claim_signatures, expected_error
  ):
    """Tests that missing or algorithm-mismatched image signatures raise PolicyViolationError."""
    self.validator._policy = attestation_pb2.AttestationPolicy(
        workload=attestation_pb2.WorkloadPolicy(
            image_signatures=required_signatures
        )
    )
    claims = _get_valid_claims()
    claims["submods"]["container"]["image_signatures"] = claim_signatures
    with self.assertRaisesRegex(
        exceptions.PolicyViolationError,
        expected_error,
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
      (
          "malformed_multi_image_signatures_type",
          attestation_pb2.AttestationPolicy(
              workload=attestation_pb2.WorkloadPolicy(
                  image_signatures=[_FAKE_KEY_ID_1]
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
          "malformed_multi_image_signatures_element_type",
          attestation_pb2.AttestationPolicy(
              workload=attestation_pb2.WorkloadPolicy(
                  image_signatures=[_FAKE_KEY_ID_1]
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
      (
          "malformed_confidential_space_submod",
          attestation_pb2.AttestationPolicy(
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  support_attributes=["STABLE"]
              )
          ),
          {
              "swname": "CONFIDENTIAL_SPACE",
              "submods": {
                  "container": {},
                  "gce": {},
                  "confidential_space": "not_a_dict",
              },
          },
          "Malformed token structure",
      ),
      (
          "malformed_support_attributes_type",
          attestation_pb2.AttestationPolicy(
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  support_attributes=["STABLE"]
              )
          ),
          {
              "swname": "CONFIDENTIAL_SPACE",
              "submods": {
                  "container": {},
                  "gce": {},
                  "confidential_space": {"support_attributes": "STABLE"},
              },
          },
          "Malformed support_attributes claim.",
      ),
      (
          "malformed_support_attributes_element_type",
          attestation_pb2.AttestationPolicy(
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  support_attributes=["STABLE"]
              )
          ),
          {
              "swname": "CONFIDENTIAL_SPACE",
              "submods": {
                  "container": {},
                  "gce": {},
                  "confidential_space": {"support_attributes": [123]},
              },
          },
          "Malformed support_attributes claim.",
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

  def test_enforce_policy_confidential_space_success(self):
    """Tests that ConfidentialSpacePolicy passes when all platform claims match."""
    self.validator._policy = attestation_pb2.AttestationPolicy(
        confidential_space=attestation_pb2.ConfidentialSpacePolicy(
            require_debug_disabled=True,
            require_secboot=True,
            support_attributes=["STABLE", "LATEST"],
        )
    )
    claims = _get_valid_claims()
    claims["swname"] = "CONFIDENTIAL_SPACE"
    claims["dbgstat"] = "disabled-since-boot"
    claims["secboot"] = True
    claims["submods"]["confidential_space"] = {
        "support_attributes": ["STABLE", "LATEST", "USABLE"]
    }
    self.validator._enforce_policy(claims)

  @parameterized.named_parameters(
      (
          "empty_policy_rejects_non_cs_swname",
          attestation_pb2.ConfidentialSpacePolicy(),
          {"swname": "GCE"},
          "Software name mismatch. Expected 'CONFIDENTIAL_SPACE', got 'GCE'",
      ),
      (
          "swname_mismatch",
          attestation_pb2.ConfidentialSpacePolicy(require_debug_disabled=True),
          {
              "swname": "OTHER_OS",
              "dbgstat": "disabled-since-boot",
              "secboot": True,
          },
          (
              "Software name mismatch. Expected 'CONFIDENTIAL_SPACE', got"
              " 'OTHER_OS'"
          ),
      ),
      (
          "swname_missing",
          attestation_pb2.ConfidentialSpacePolicy(require_secboot=True),
          {"secboot": True},
          "Software name mismatch. Expected 'CONFIDENTIAL_SPACE', got None",
      ),
      (
          "dbgstat_enabled",
          attestation_pb2.ConfidentialSpacePolicy(require_debug_disabled=True),
          {
              "swname": "CONFIDENTIAL_SPACE",
              "dbgstat": "enabled",
              "secboot": True,
          },
          (
              "Debug status mismatch. Expected 'disabled-since-boot', got"
              " 'enabled'"
          ),
      ),
      (
          "dbgstat_wrong_case",
          attestation_pb2.ConfidentialSpacePolicy(require_debug_disabled=True),
          {
              "swname": "CONFIDENTIAL_SPACE",
              "dbgstat": "Disabled-Since-Boot",
              "secboot": True,
          },
          (
              "Debug status mismatch. Expected 'disabled-since-boot', got"
              " 'Disabled-Since-Boot'"
          ),
      ),
      (
          "dbgstat_non_string",
          attestation_pb2.ConfidentialSpacePolicy(require_debug_disabled=True),
          {
              "swname": "CONFIDENTIAL_SPACE",
              "dbgstat": False,
              "secboot": True,
          },
          "Debug status mismatch. Expected 'disabled-since-boot', got False",
      ),
      (
          "dbgstat_missing",
          attestation_pb2.ConfidentialSpacePolicy(require_debug_disabled=True),
          {"swname": "CONFIDENTIAL_SPACE", "secboot": True},
          "Debug status mismatch. Expected 'disabled-since-boot', got None",
      ),
      (
          "secboot_false",
          attestation_pb2.ConfidentialSpacePolicy(require_secboot=True),
          {"swname": "CONFIDENTIAL_SPACE", "secboot": False},
          "Secure boot required, got False",
      ),
      (
          "secboot_non_bool_truthy_string",
          attestation_pb2.ConfidentialSpacePolicy(require_secboot=True),
          {"swname": "CONFIDENTIAL_SPACE", "secboot": "true"},
          "Secure boot required, got 'true'",
      ),
      (
          "missing_confidential_space_submod_section",
          attestation_pb2.ConfidentialSpacePolicy(
              support_attributes=["STABLE"]
          ),
          {"swname": "CONFIDENTIAL_SPACE"},
          (
              r"Missing required Confidential Space support attribute:"
              r" STABLE\. Found attributes: \[\]"
          ),
      ),
      (
          "missing_support_attribute",
          attestation_pb2.ConfidentialSpacePolicy(
              support_attributes=["STABLE"]
          ),
          {
              "swname": "CONFIDENTIAL_SPACE",
              "submods": {
                  "confidential_space": {"support_attributes": ["USABLE"]}
              },
          },
          "Missing required Confidential Space support attribute: STABLE",
      ),
  )
  def test_enforce_policy_confidential_space_violation_fails(
      self, cs_policy, claim_overrides, expected_error
  ):
    """Tests that ConfidentialSpacePolicy violations raise PolicyViolationError."""
    self.validator._policy = attestation_pb2.AttestationPolicy(
        confidential_space=cs_policy
    )
    claims = _get_valid_claims()
    for key, val in claim_overrides.items():
      if key == "submods":
        claims["submods"].update(val)
      else:
        claims[key] = val
    with self.assertRaisesRegex(
        exceptions.PolicyViolationError, expected_error
    ):
      self.validator._enforce_policy(claims)

  def test_validate_with_sanitized_confidential_space_token_claims(self):
    """Tests end-to-end validate() against a sanitized GCA Confidential Space token payload."""
    self.validator._policy = attestation_pb2.AttestationPolicy(
        hw_model=attestation_pb2.HardwareModel.HARDWARE_MODEL_SEV,
        workload=attestation_pb2.WorkloadPolicy(
            image_hash=_FAKE_IMAGE_HASH,
            signing_key_id=_FAKE_SIGNING_KEY,
        ),
        gce_instance=attestation_pb2.GceInstancePolicy(
            project_id=_FAKE_PROJECT,
            zone=_FAKE_ZONE,
            instance_name=_FAKE_INSTANCE_NAME,
            instance_id=_FAKE_INSTANCE_ID,
        ),
        confidential_space=attestation_pb2.ConfidentialSpacePolicy(
            require_debug_disabled=True,
            require_secboot=True,
            support_attributes=["STABLE"],
        ),
    )
    sanitized_gca_claims = {
        "aud": "https://sts.google.com",
        "dbgstat": "disabled-since-boot",
        "eat_nonce": [
            hashlib.sha256(_FAKE_PUB_KEY).hexdigest(),
            hashlib.sha256(_FAKE_PQC_PUB_KEY).hexdigest(),
            _FAKE_CHALLENGE_NONCE.hex(),
        ],
        "eat_profile": (
            "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims"
        ),
        "hwmodel": "GCP_AMD_SEV",
        "iss": "https://confidentialcomputing.googleapis.com",
        "secboot": True,
        "submods": {
            "confidential_space": {
                "support_attributes": ["STABLE", "USABLE"],
            },
            "container": {
                "cmd": [],
                "env": {},
                "image_digest": _FAKE_IMAGE_HASH,
                "image_id": (
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                ),
                "image_reference": (
                    "us-docker.pkg.dev/example-project/repo/workload@sha256:abcdef"
                ),
                "image_signatures": [{
                    "key_id": _FAKE_SIGNING_KEY,
                    "signature": "MEUCIQ...",
                    "signature_algorithm": "ECDSA_P256_SHA256",
                }],
                "restart_policy": "Never",
            },
            "gce": {
                "instance_id": _FAKE_INSTANCE_ID,
                "instance_name": _FAKE_INSTANCE_NAME,
                "project_id": _FAKE_PROJECT,
                "project_number": "123456789012",
                "zone": _FAKE_ZONE,
            },
        },
        "swname": "CONFIDENTIAL_SPACE",
        "swversion": ["250200"],
    }

    mock_oidc = self.enter_context(
        mock.patch.object(
            validator.OIDCTokenValidator,
            "validate_token",
            return_value=sanitized_gca_claims,
            autospec=True,
        )
    )
    mock_verify_session_signature = self.enter_context(
        mock.patch.object(
            self.validator, "_verify_session_signature", autospec=True
        )
    )
    mock_verify_pqc_signature = self.enter_context(
        mock.patch.object(
            self.validator, "_verify_session_signature_mldsa", autospec=True
        )
    )

    response = attestation_pb2.AttestConnectionResponse(
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=_FAKE_PUB_KEY
        ),
        session_signature=_FAKE_SESSION_SIGNATURE,
        pqc_public_key=attestation_pb2.MlDsaPublicKey(
            serialized_public_keyset=_FAKE_PQC_PUB_KEY
        ),
        pqc_session_signature=_FAKE_PQC_SESSION_SIGNATURE,
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
    mock_oidc.assert_called_once()
    mock_verify_session_signature.assert_called_once()
    mock_verify_pqc_signature.assert_called_once()

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
    mock_verify_pqc_signature = self.enter_context(
        mock.patch.object(
            self.validator, "_verify_session_signature_mldsa", autospec=True
        )
    )

    response = attestation_pb2.AttestConnectionResponse(
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=_FAKE_PUB_KEY
        ),
        session_signature=_FAKE_SESSION_SIGNATURE,
        pqc_public_key=attestation_pb2.MlDsaPublicKey(
            serialized_public_keyset=_FAKE_PQC_PUB_KEY
        ),
        pqc_session_signature=_FAKE_PQC_SESSION_SIGNATURE,
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
    mock_verify_pqc_signature.assert_called_once()

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
        pqc_public_key=attestation_pb2.MlDsaPublicKey(
            serialized_public_keyset=_FAKE_PQC_PUB_KEY
        ),
        pqc_session_signature=_FAKE_PQC_SESSION_SIGNATURE,
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

  def test_validate_missing_ecdsa_public_key_fails(self):
    """Tests failure when ECDSA public key is missing."""
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
          pqc_public_key=attestation_pb2.MlDsaPublicKey(
              serialized_public_keyset=_FAKE_PQC_PUB_KEY
          ),
          pqc_session_signature=_FAKE_PQC_SESSION_SIGNATURE,
          # instance_public_key is missing
      )
      with self.assertRaisesRegex(
          exceptions.AttestationVerificationError,
          "ECDSA public key is missing",
      ):
        self.validator.validate(response, tls_ekm=b"")

  def test_validate_missing_pqc_public_key_fails(self):
    """Tests failure when PQC public key is missing."""
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
          session_signature=_FAKE_SESSION_SIGNATURE,
          # pqc_public_key is missing
      )
      with self.assertRaisesRegex(
          exceptions.AttestationVerificationError,
          "PQC public key is missing",
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
          pqc_public_key=attestation_pb2.MlDsaPublicKey(
              serialized_public_keyset=_FAKE_PQC_PUB_KEY
          ),
          pqc_session_signature=_FAKE_PQC_SESSION_SIGNATURE,
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

  def test_validate_missing_pqc_session_signature_fails(self):
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
          session_signature=_FAKE_SESSION_SIGNATURE,
          pqc_public_key=attestation_pb2.MlDsaPublicKey(
              serialized_public_keyset=_FAKE_PQC_PUB_KEY
          ),
          evidence=[
              attestation_pb2.AttestationEvidence(
                  verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
                  gca_bundle=attestation_pb2.GcaTrustBundle(
                      attestation_token="valid.jwt.payload"
                  ),
              ),
          ],
          # pqc_session_signature is missing
      )
      with self.assertRaisesRegex(
          exceptions.AttestationVerificationError,
          "PQC session signature is missing",
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
    self.enter_context(
        mock.patch.object(av, "_verify_session_signature_mldsa", autospec=True)
    )

    response = attestation_pb2.AttestConnectionResponse(
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=_FAKE_PUB_KEY
        ),
        session_signature=_FAKE_SESSION_SIGNATURE,
        pqc_public_key=attestation_pb2.MlDsaPublicKey(
            serialized_public_keyset=_FAKE_PQC_PUB_KEY
        ),
        pqc_session_signature=_FAKE_PQC_SESSION_SIGNATURE,
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
            autospec=True,
        ) as spy_sig:
          with mock.patch.object(
              self.validator,
              "_verify_session_signature_mldsa",
              autospec=True,
          ) as spy_pqc_sig:
            response = attestation_pb2.AttestConnectionResponse(
                instance_public_key=attestation_pb2.EcdsaP256PublicKey(
                    key_bytes=_FAKE_PUB_KEY
                ),
                session_signature=_FAKE_SESSION_SIGNATURE,
                pqc_public_key=attestation_pb2.MlDsaPublicKey(
                    serialized_public_keyset=_FAKE_PQC_PUB_KEY
                ),
                pqc_session_signature=_FAKE_PQC_SESSION_SIGNATURE,
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
              spy_binding.assert_called_once_with(
                  claims,
                  ecdsa_pub_bytes=_FAKE_PUB_KEY,
                  pqc_pub_bytes=_FAKE_PQC_PUB_KEY,
                  expected_nonce=None,
              )
            with self.subTest(name="verify_session_signature_called"):
              spy_sig.assert_called_once()
            with self.subTest(name="verify_session_signature_mldsa_called"):
              spy_pqc_sig.assert_called_once()

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

  @mock.patch.object(
      validator.tink.proto_keyset_format,
      "parse_without_secret",
      autospec=True,
  )
  def test_verify_session_signature_mldsa_success(self, mock_parse):
    mock_handle = mock.Mock()
    mock_handle.keyset_info.return_value.key_info = [
        mock.Mock(type_url=constants.ML_DSA_PUBLIC_KEY_TYPE_URL)
    ]
    mock_verifier = mock.Mock()
    mock_handle.primitive.return_value = mock_verifier
    mock_parse.return_value = mock_handle

    pub_key_proto = attestation_pb2.MlDsaPublicKey(
        serialized_public_keyset=_FAKE_PQC_PUB_KEY
    )
    payload = b"payload"

    self.validator._verify_session_signature_mldsa(
        pub_key_proto, signature=_FAKE_PQC_SESSION_SIGNATURE, payload=payload
    )

    mock_parse.assert_called_once_with(_FAKE_PQC_PUB_KEY)
    mock_handle.primitive.assert_called_once_with(
        validator.tink_signature.PublicKeyVerify
    )
    mock_verifier.verify.assert_called_once_with(
        _FAKE_PQC_SESSION_SIGNATURE, payload
    )

  @mock.patch.object(
      validator.tink.proto_keyset_format,
      "parse_without_secret",
      autospec=True,
  )
  def test_verify_session_signature_mldsa_fails(self, mock_parse):
    mock_handle = mock.Mock()
    mock_handle.keyset_info.return_value.key_info = [
        mock.Mock(type_url=constants.ML_DSA_PUBLIC_KEY_TYPE_URL)
    ]
    mock_verifier = mock.Mock()
    mock_verifier.verify.side_effect = Exception("verification failed")
    mock_handle.primitive.return_value = mock_verifier
    mock_parse.return_value = mock_handle

    pub_key_proto = attestation_pb2.MlDsaPublicKey(
        serialized_public_keyset=_FAKE_PQC_PUB_KEY
    )
    payload = b"payload"

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "PQC session signature verification failed.",
    ):
      self.validator._verify_session_signature_mldsa(
          pub_key_proto, signature=_FAKE_PQC_SESSION_SIGNATURE, payload=payload
      )

  @mock.patch.object(
      validator.tink.proto_keyset_format,
      "parse_without_secret",
      autospec=True,
  )
  def test_verify_session_signature_mldsa_wrong_key_type(self, mock_parse):
    mock_handle = mock.Mock()
    mock_handle.keyset_info.return_value.key_info = [
        mock.Mock(
            type_url="type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
        )
    ]
    mock_parse.return_value = mock_handle

    pub_key_proto = attestation_pb2.MlDsaPublicKey(
        serialized_public_keyset=_FAKE_PQC_PUB_KEY
    )
    payload = b"payload"

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "PQC keyset key-type is not ML-DSA.",
    ):
      self.validator._verify_session_signature_mldsa(
          pub_key_proto, signature=_FAKE_PQC_SESSION_SIGNATURE, payload=payload
      )

  def test_verify_session_signature_mldsa_integration(self):
    """Tests ML-DSA signature verification using real Tink keysets without mocks."""
    mldsa_template = validator.tink_signature.signature_key_templates.ML_DSA_65
    private_handle = validator.tink.new_keyset_handle(mldsa_template)
    public_handle = private_handle.public_keyset_handle()
    serialized_pub_bytes = (
        validator.tink.proto_keyset_format.serialize_without_secret(
            public_handle
        )
    )

    signer = private_handle.primitive(validator.tink_signature.PublicKeySign)
    payload = b"test_payload_bytes"
    signature_bytes = signer.sign(payload)

    pub_key_proto = attestation_pb2.MlDsaPublicKey(
        serialized_public_keyset=serialized_pub_bytes
    )

    self.validator._verify_session_signature_mldsa(
        pub_key_proto, signature=signature_bytes, payload=payload
    )

  @parameterized.named_parameters(
      dict(
          testcase_name="unset_expected_audience",
          policy=attestation_pb2.AttestationPolicy(),
          expected_kwargs={},
      ),
      dict(
          testcase_name="custom_expected_audience",
          policy=attestation_pb2.AttestationPolicy(
              expected_audience="custom-tee-audience"
          ),
          expected_kwargs={"expected_audience": "custom-tee-audience"},
      ),
  )
  def test_validate_policy_expected_audience(self, policy, expected_kwargs):
    """Tests that AttestationValidator forwards policy.expected_audience to OIDCTokenValidator."""
    mock_oidc_validator = mock.create_autospec(validator.OIDCTokenValidator)
    mock_oidc_validator.validate_token.return_value = _get_valid_claims()
    av = validator.AttestationValidator(
        policy,
        oidc_validator=mock_oidc_validator,
    )
    self.enter_context(
        mock.patch.object(av, "_verify_session_signature", autospec=True)
    )
    self.enter_context(
        mock.patch.object(av, "_verify_session_signature_mldsa", autospec=True)
    )

    response = attestation_pb2.AttestConnectionResponse(
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=_FAKE_PUB_KEY
        ),
        session_signature=_FAKE_SESSION_SIGNATURE,
        pqc_public_key=attestation_pb2.MlDsaPublicKey(
            serialized_public_keyset=_FAKE_PQC_PUB_KEY
        ),
        pqc_session_signature=_FAKE_PQC_SESSION_SIGNATURE,
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
        "valid.jwt.payload",
        **expected_kwargs,
    )


class ValidateProofTest(parameterized.TestCase):
  """`validate_proof` checks the role and the mode that the proof is bound to."""

  _EKM = b"session-ekm"
  _TOKEN = "valid.jwt.payload"

  def setUp(self):
    super().setUp()
    self.enter_context(
        mock.patch.object(requests.Session, "get", autospec=True)
    )
    self.enter_context(
        mock.patch.object(
            validator.OIDCTokenValidator,
            "validate_token",
            autospec=True,
            return_value=_get_valid_claims(),
        )
    )
    self.validator = validator.AttestationValidator(
        attestation_pb2.AttestationPolicy()
    )
    # Both signature checks accept only the payload of a mutual client proof,
    # as real signatures over that payload would.
    signed_payload = attestation_protocol.build_signature_payload(
        tls_ekm=self._EKM,
        attestation_token=self._TOKEN.encode("utf-8"),
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    def verify(public_key, *, signature, payload):
      del public_key, signature  # Unused.
      if payload != signed_payload:
        raise exceptions.AttestationVerificationError("Bad signature.")

    for name in (
        "_verify_session_signature",
        "_verify_session_signature_mldsa",
    ):
      self.enter_context(
          mock.patch.object(
              self.validator, name, autospec=True, side_effect=verify
          )
      )
    self.proof = attestation_pb2.AttestationProof(
        evidence=[
            attestation_pb2.AttestationEvidence(
                verifier_type=attestation_pb2.VERIFIER_TYPE_GCA,
                gca_bundle=attestation_pb2.GcaTrustBundle(
                    attestation_token=self._TOKEN
                ),
            )
        ],
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=_FAKE_PUB_KEY
        ),
        session_signature=_FAKE_SESSION_SIGNATURE,
        pqc_public_key=attestation_pb2.MlDsaPublicKey(
            serialized_public_keyset=_FAKE_PQC_PUB_KEY
        ),
        pqc_session_signature=_FAKE_PQC_SESSION_SIGNATURE,
    )

  def test_returns_the_claims_for_the_signed_role_and_mode(self):
    claims = self.validator.validate_proof(
        self.proof,
        self._EKM,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    self.assertEqual(claims, _get_valid_claims())

  @parameterized.named_parameters(
      (
          "server_role",
          attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
          attestation_pb2.ATTESTATION_MODE_MUTUAL,
      ),
      (
          "server_only_mode",
          attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
          attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
      ),
  )
  def test_rejects_another_role_or_mode(self, peer_role, mode):
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "Bad signature"
    ):
      self.validator.validate_proof(
          self.proof, self._EKM, peer_role=peer_role, mode=mode
      )

  @parameterized.named_parameters(
      (
          "mutual_with_unspecified_role",
          attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
          attestation_pb2.ATTESTATION_MODE_MUTUAL,
      ),
      (
          "server_only_with_client_role",
          attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
      ),
  )
  def test_rejects_invalid_role_and_mode_pair(self, peer_role, mode):
    with self.assertRaisesRegex(
        ValueError, r"Invalid \(mode, peer_role\) combination"
    ):
      self.validator.validate_proof(
          self.proof, self._EKM, peer_role=peer_role, mode=mode
      )


class VerifiedExpiryTest(parameterized.TestCase):

  @parameterized.parameters(1_700_000_000, 1_700_000_000.5)
  def test_returns_a_finite_exp(self, exp):
    expiry = validator.verified_expiry({"exp": exp})

    self.assertIsInstance(expiry, float)
    self.assertEqual(expiry, exp)

  @parameterized.named_parameters(
      ("missing", {}),
      ("nan", {"exp": float("nan")}),
      ("infinity", {"exp": float("inf")}),
      ("bool", {"exp": True}),
      ("string", {"exp": "1700000000"}),
      ("too_large_for_a_float", {"exp": 10**400}),
  )
  def test_rejects_an_unusable_exp(self, claims):
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "must be a finite number"
    ):
      validator.verified_expiry(claims)


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
        fixed_now=None,
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

    mock_verifier.verify_and_decode.side_effect = tink.TinkError(
        "Bad Signature"
    )

    v = validator.OIDCTokenValidator()

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "OIDC Token validation failed"
    ):
      v.validate_token("some.invalid.token")

  def test_validate_token_jwks_fetch_failure(self):
    """Tests that JWKS fetch errors raise AttestationVerificationError."""
    mock_jwk_client = self.enter_context(
        mock.patch.object(jwt, "PyJWKClient", autospec=True)
    )
    mock_jwk_client.return_value.fetch_data.side_effect = (
        requests.RequestException("network error")
    )

    v = validator.OIDCTokenValidator()

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "Failed to fetch OIDC JWK set"
    ):
      v.validate_token("some.token")

  def test_validate_token_missing_issuer_raises(self):
    """Tests that an unconfigured issuer raises before fetching JWKS."""
    mock_jwk_client = self.enter_context(
        mock.patch.object(jwt, "PyJWKClient", autospec=True)
    )
    v = validator.OIDCTokenValidator()
    v._issuer = ""

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "OIDC issuer is not configured",
    ):
      v.validate_token("some.token")
    mock_jwk_client.return_value.fetch_data.assert_not_called()

  def test_validate_token_empty_audience_raises_before_fetch(self):
    """Tests that an empty expected_audience raises ValueError before fetching JWKS."""
    mock_jwk_client = self.enter_context(
        mock.patch.object(jwt, "PyJWKClient", autospec=True)
    )
    v = validator.OIDCTokenValidator()

    with self.assertRaisesRegex(
        ValueError, "expected_audience must be a non-empty string"
    ):
      v.validate_token("some.token", expected_audience="")
    mock_jwk_client.return_value.fetch_data.assert_not_called()

  def test_oidc_token_validator_close_closes_session(self):
    mock_session = mock.create_autospec(requests.Session)
    oidc_validator = validator.OIDCTokenValidator(session=mock_session)
    oidc_validator.close()
    mock_session.close.assert_called_once()

  @parameterized.named_parameters(
      dict(
          testcase_name="default_audience_accepted",
          token_audience=constants.DEFAULT_AUDIENCE,
          validate_kwargs={},
          should_succeed=True,
      ),
      dict(
          testcase_name="custom_audience_accepted",
          token_audience="custom-tee-audience",
          validate_kwargs={"expected_audience": "custom-tee-audience"},
          should_succeed=True,
      ),
      dict(
          testcase_name="custom_audience_mismatch_rejected",
          token_audience=constants.DEFAULT_AUDIENCE,
          validate_kwargs={"expected_audience": "custom-tee-audience"},
          should_succeed=False,
      ),
      dict(
          testcase_name="default_audience_rejects_custom_token",
          token_audience="custom-tee-audience",
          validate_kwargs={},
          should_succeed=False,
      ),
  )
  def test_validate_token_audience_enforcement(
      self,
      token_audience,
      validate_kwargs,
      should_succeed,
  ):
    """Tests cryptographic Tink JWT validation across default, custom, and mismatched audiences."""
    private_handle = tink.new_keyset_handle(
        tink_jwt.jwt_rs256_2048_f4_template()
    )
    public_handle = private_handle.public_keyset_handle()
    jwk_set_dict = json.loads(
        tink_jwt.jwk_set_from_public_keyset_handle(public_handle)
    )

    self.mock_get.return_value.status_code = 200
    self.mock_get.return_value.json.return_value = {
        "issuer": "http://test-issuer",
        "jwks_uri": "http://test-jwks-uri",
    }
    mock_jwk_client = self.enter_context(
        mock.patch.object(jwt, "PyJWKClient", autospec=True)
    )
    mock_jwk_client.return_value.fetch_data.return_value = jwk_set_dict

    signer = private_handle.primitive(tink_jwt.JwtPublicKeySign)
    raw_jwt = tink_jwt.new_raw_jwt(
        type_header="JWT",
        issuer="http://test-issuer",
        audiences=[token_audience],
        expiration=datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=5),
        custom_claims={"claim": "value"},
    )
    signed_token = signer.sign_and_encode(raw_jwt)

    oidc_validator = validator.OIDCTokenValidator()
    if should_succeed:
      claims = oidc_validator.validate_token(signed_token, **validate_kwargs)
      self.assertEqual(claims["claim"], "value")
      self.assertEqual(claims["aud"], [token_audience])
    else:
      with self.assertRaisesRegex(
          exceptions.AttestationVerificationError,
          "OIDC Token validation failed",
      ):
        oidc_validator.validate_token(signed_token, **validate_kwargs)


def _new_jwt_signing_key() -> tink.KeysetHandle:
  return tink.new_keyset_handle(tink_jwt.jwt_es256_template())


def _jwk_set_json(private_handle: tink.KeysetHandle) -> str:
  return tink_jwt.jwk_set_from_public_keyset_handle(
      private_handle.public_keyset_handle()
  )


def _sign_token(
    private_handle: tink.KeysetHandle,
    *,
    issuer: str = constants.CS_DEFAULT_ISSUER,
    audience: str = constants.DEFAULT_AUDIENCE,
    type_header: str = "JWT",
) -> str:
  signer = private_handle.primitive(tink_jwt.JwtPublicKeySign)
  return signer.sign_and_encode(
      tink_jwt.new_raw_jwt(
          type_header=type_header,
          issuer=issuer,
          audiences=[audience],
          issued_at=_ISSUED_AT,
          not_before=_ISSUED_AT,
          expiration=_ISSUED_AT + _TOKEN_LIFETIME,
          custom_claims={"claim": "value"},
      )
  )


class VerifyOidcJwtTest(parameterized.TestCase):

  def test_accepts_token_at_fixed_time_within_validity(self):
    private_handle = _new_jwt_signing_key()

    claims = validator.verify_oidc_jwt(
        _sign_token(private_handle),
        _jwk_set_json(private_handle),
        expected_issuer=constants.CS_DEFAULT_ISSUER,
        expected_audience=constants.DEFAULT_AUDIENCE,
        fixed_now=_ISSUED_AT + datetime.timedelta(minutes=30),
    )

    self.assertEqual(claims["claim"], "value")
    self.assertEqual(claims["iss"], constants.CS_DEFAULT_ISSUER)
    self.assertEqual(claims["aud"], [constants.DEFAULT_AUDIENCE])

  @parameterized.named_parameters(
      dict(
          testcase_name="current_time_after_expiry",
          fixed_now=None,
      ),
      dict(
          testcase_name="at_expiry",
          fixed_now=_ISSUED_AT + _TOKEN_LIFETIME,
      ),
      dict(
          testcase_name="before_not_before",
          fixed_now=_ISSUED_AT - datetime.timedelta(seconds=1),
      ),
  )
  def test_rejects_token_outside_validity(self, fixed_now):
    private_handle = _new_jwt_signing_key()

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "OIDC Token validation failed"
    ):
      validator.verify_oidc_jwt(
          _sign_token(private_handle),
          _jwk_set_json(private_handle),
          expected_issuer=constants.CS_DEFAULT_ISSUER,
          expected_audience=constants.DEFAULT_AUDIENCE,
          fixed_now=fixed_now,
      )

  @parameterized.named_parameters(
      dict(
          testcase_name="other_signing_key",
          sign_kwargs={},
          jwks_from_other_key=True,
      ),
      dict(
          testcase_name="other_issuer",
          sign_kwargs={"issuer": "https://other-issuer.example"},
          jwks_from_other_key=False,
      ),
      dict(
          testcase_name="other_audience",
          sign_kwargs={"audience": "other-audience"},
          jwks_from_other_key=False,
      ),
      dict(
          testcase_name="wrong_type_header",
          sign_kwargs={"type_header": "at+jwt"},
          jwks_from_other_key=False,
      ),
  )
  def test_rejects_token_failing_signature_or_claims(
      self, sign_kwargs, jwks_from_other_key
  ):
    private_handle = _new_jwt_signing_key()
    jwks_handle = (
        _new_jwt_signing_key() if jwks_from_other_key else private_handle
    )

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "OIDC Token validation failed"
    ):
      validator.verify_oidc_jwt(
          _sign_token(private_handle, **sign_kwargs),
          _jwk_set_json(jwks_handle),
          expected_issuer=constants.CS_DEFAULT_ISSUER,
          expected_audience=constants.DEFAULT_AUDIENCE,
          fixed_now=_ISSUED_AT + datetime.timedelta(minutes=30),
      )

  def test_rejects_invalid_jwk_set(self):
    private_handle = _new_jwt_signing_key()

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "OIDC Token validation failed"
    ):
      validator.verify_oidc_jwt(
          _sign_token(private_handle),
          "not a JWK set",
          expected_issuer=constants.CS_DEFAULT_ISSUER,
          expected_audience=constants.DEFAULT_AUDIENCE,
          fixed_now=_ISSUED_AT + datetime.timedelta(minutes=30),
      )

  @parameterized.named_parameters(
      dict(
          testcase_name="empty_expected_issuer",
          expected_issuer="",
          expected_audience=constants.DEFAULT_AUDIENCE,
          fixed_now=_ISSUED_AT + datetime.timedelta(minutes=30),
          expected_error="expected_issuer must be a non-empty string",
      ),
      dict(
          testcase_name="empty_expected_audience",
          expected_issuer=constants.CS_DEFAULT_ISSUER,
          expected_audience="",
          fixed_now=_ISSUED_AT + datetime.timedelta(minutes=30),
          expected_error="expected_audience must be a non-empty string",
      ),
      dict(
          testcase_name="fixed_now_without_time_zone",
          expected_issuer=constants.CS_DEFAULT_ISSUER,
          expected_audience=constants.DEFAULT_AUDIENCE,
          fixed_now=datetime.datetime(2026, 1, 1, 0, 30),
          expected_error="tzinfo",
      ),
  )
  def test_invalid_validator_arguments_raise_value_error(
      self, expected_issuer, expected_audience, fixed_now, expected_error
  ):
    private_handle = _new_jwt_signing_key()

    with self.assertRaisesRegex(ValueError, expected_error):
      validator.verify_oidc_jwt(
          _sign_token(private_handle),
          _jwk_set_json(private_handle),
          expected_issuer=expected_issuer,
          expected_audience=expected_audience,
          fixed_now=fixed_now,
      )


if __name__ == "__main__":
  absltest.main()
