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

"""Tests for server.attestation."""

import hashlib
from unittest import mock

from absl.testing import absltest
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.ekm import exporter
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token


class AttestedTlsImplTest(absltest.TestCase):

  def test_attest_connection_success(self):
    mock_key_manager = mock.create_autospec(keys.KeyManager, instance=True)
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_token_manager.key_manager = mock_key_manager
    public_key = b"test_public_key"
    pqc_public_key = b"test_pqc_public_key"
    attestation_token = b"test_attestation_token"
    signature = b"test_signature"
    pqc_signature = b"test_pqc_signature"
    ekm_bytes = b"test_ekm"

    mock_token_manager.get_identity_snapshot.return_value = (
        public_key,
        pqc_public_key,
        attestation_token,
    )
    mock_token_manager.key_manager.sign_payload.return_value = signature
    mock_token_manager.key_manager.sign_payload_mldsa.return_value = (
        pqc_signature
    )

    mock_ssl_obj = mock.MagicMock()
    mock_ssl_obj.export_keying_material.return_value = ekm_bytes

    attested_tls_instance = attestation.AttestedTLS(
        token_manager=mock_token_manager
    )
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
        nonce=b"test_nonce",
    )
    expected_payload = attestation_pb2.SessionSignaturePayload(
        ekm_hash=hashlib.sha256(ekm_bytes).digest(),
        token_hash=hashlib.sha256(attestation_token).digest(),
    )

    response = attested_tls_instance.attest_connection(
        request, ssl_obj=mock_ssl_obj
    )

    mock_token_manager.key_manager.sign_payload.assert_called_once()
    mock_token_manager.key_manager.sign_payload_mldsa.assert_called_once()
    call_args = mock_token_manager.key_manager.sign_payload.call_args[0][0]
    actual_payload = attestation_pb2.SessionSignaturePayload.FromString(
        call_args
    )

    with self.subTest(name="EvidencePopulated"):
      self.assertEqual(
          response.evidence[0].gca_bundle.attestation_token.encode("utf-8"),
          attestation_token,
      )
      self.assertEqual(response.session_signature, signature)
      self.assertEqual(response.pqc_session_signature, pqc_signature)

    with self.subTest(name="PublicKeyPopulated"):
      self.assertEqual(response.instance_public_key.key_bytes, public_key)
      self.assertEqual(
          response.pqc_public_key.serialized_public_keyset, pqc_public_key
      )

    with self.subTest(name="EKMSigned"):
      self.assertEqual(expected_payload, actual_payload)

  @mock.patch.object(exporter, "export_keying_material", autospec=True)
  def test_attest_connection_ekm_extraction_fails(
      self, mock_export_keying_material
  ):
    mock_export_keying_material.return_value = None
    mock_ssl_obj = mock.MagicMock()
    mock_ssl_obj.export_keying_material.side_effect = Exception("EKM failed")
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_token_manager.key_manager = mock.create_autospec(
        keys.KeyManager, instance=True
    )
    attested_tls_instance = attestation.AttestedTLS(
        token_manager=mock_token_manager
    )
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
    )

    with self.assertRaisesRegex(
        RuntimeError,
        "EKM extraction failed. The initial attempt using"
        " ssl_obj.export_keying_material failed.",
    ):
      attested_tls_instance.attest_connection(request, ssl_obj=mock_ssl_obj)
    mock_export_keying_material.assert_called_once()

  def test_attest_connection_no_verifier(self):
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    attested_tls_instance = attestation.AttestedTLS(
        token_manager=mock_token_manager
    )
    request = attestation_pb2.AttestConnectionRequest()
    with self.assertRaisesRegex(
        ValueError, "At least one required_verifier_type must be specified."
    ):
      attested_tls_instance.attest_connection(request, ssl_obj=mock.MagicMock())

  def test_attest_connection_unsupported_verifier(self):
    mock_key_manager = mock.create_autospec(keys.KeyManager, instance=True)
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_token_manager.key_manager = mock_key_manager
    mock_token_manager.get_identity_snapshot.return_value = (
        b"pk",
        b"pqc_pk",
        b"token",
    )
    mock_token_manager.key_manager.sign_payload.return_value = b"sig"
    mock_ssl_obj = mock.MagicMock()
    mock_ssl_obj.export_keying_material.return_value = b"ekm"

    attested_tls_instance = attestation.AttestedTLS(
        token_manager=mock_token_manager
    )
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[
            attestation_pb2.VerifierType.VERIFIER_TYPE_UNSPECIFIED
        ]
    )
    with self.assertRaisesRegex(
        ValueError, "Unsupported verifier types requested:"
    ):
      attested_tls_instance.attest_connection(request, ssl_obj=mock_ssl_obj)

  def test_attest_connection_mixed_verifier_types_fails(self):
    mock_key_manager = mock.create_autospec(keys.KeyManager, instance=True)
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_token_manager.key_manager = mock_key_manager
    mock_token_manager.get_identity_snapshot.return_value = (
        b"pk",
        b"pqc_pk",
        b"token",
    )
    mock_token_manager.key_manager.sign_payload.return_value = b"sig"
    mock_ssl_obj = mock.MagicMock()
    mock_ssl_obj.export_keying_material.return_value = b"ekm"

    attested_tls_instance = attestation.AttestedTLS(
        token_manager=mock_token_manager
    )
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[
            attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
            attestation_pb2.VerifierType.VERIFIER_TYPE_UNSPECIFIED,
        ]
    )
    with self.assertRaisesRegex(
        ValueError, "Unsupported verifier types requested:"
    ):
      attested_tls_instance.attest_connection(request, ssl_obj=mock_ssl_obj)


def _mutual_request(**overrides):
  """Builds a well-formed mutual AttestConnectionRequest."""
  fields = dict(
      required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
      protocol_version=(
          attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
      ),
      mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      client_attestation=attestation_pb2.AttestationProof(
          session_signature=b"client-sig"
      ),
  )
  fields.update(overrides)
  return attestation_pb2.AttestConnectionRequest(**fields)


class MutualAttestedTlsTest(absltest.TestCase):
  """Covers the single-round-trip mutual exchange."""

  def setUp(self):
    super().setUp()
    self.ekm = b"session-ekm"
    self.key_manager = mock.create_autospec(keys.KeyManager, instance=True)
    self.token_manager = mock.create_autospec(token.TokenManager, instance=True)
    self.token_manager.key_manager = self.key_manager
    self.token_manager.get_identity_snapshot.return_value = (
        b"server-ecdsa",
        b"server-mldsa",
        b"server-token",
    )
    self.key_manager.sign_payload.return_value = b"server-sig"
    self.key_manager.sign_payload_mldsa.return_value = b"server-pqc-sig"

    self.ssl_obj = mock.MagicMock()
    self.ssl_obj.export_keying_material.return_value = self.ekm

    self.client_validator = mock.MagicMock()
    self.policy = attestation_pb2.AttestationPolicy()

  def _attested_tls(self, **overrides):
    kwargs = dict(
        client_policy=self.policy,
        attestation_validator_cls=lambda policy: self.client_validator,
    )
    kwargs.update(overrides)
    return attestation.AttestedTLS(self.token_manager, **kwargs)

  def test_verifies_client_proof_then_returns_server_proof(self):
    atls = self._attested_tls()
    request = _mutual_request()

    response = atls.attest_connection(request, ssl_obj=self.ssl_obj)

    with self.subTest("ClientProofVerifiedAgainstSessionEkm"):
      self.client_validator.validate_proof.assert_called_once_with(
          request.client_attestation,
          self.ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )
    with self.subTest("EkmExportedWithoutContext"):
      # Both peers must derive the same value straight from the TLS session.
      self.ssl_obj.export_keying_material.assert_called_once_with(
          b"EXPORTER-Prompt-Encryption-SDK", 32, context=None
      )
    with self.subTest("ServerProofBoundToTheSameEkmAsTheServerRole"):
      self.assertEqual(
          self.key_manager.sign_payload.call_args[0][0],
          attestation_protocol.build_signature_payload(
              tls_ekm=self.ekm,
              attestation_token=b"server-token",
              peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
              mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
          ),
      )
    with self.subTest("NegotiationEchoed"):
      self.assertEqual(response.protocol_version, 1)
      self.assertEqual(response.mode, attestation_pb2.ATTESTATION_MODE_MUTUAL)
      self.assertTrue(response.mutual_attestation_complete)
      self.assertEqual(response.session_signature, b"server-sig")
      self.assertEqual(response.pqc_session_signature, b"server-pqc-sig")

  def test_client_proof_is_verified_before_the_server_proves_itself(self):
    """A failed client check must not leak a fresh server proof."""
    self.client_validator.validate_proof.side_effect = (
        exceptions.PolicyViolationError("bad client")
    )
    atls = self._attested_tls()

    with self.assertRaises(exceptions.PolicyViolationError):
      atls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    self.key_manager.sign_payload.assert_not_called()
    self.key_manager.sign_payload_mldsa.assert_not_called()

  def test_rejected_client_can_retry_on_the_same_session(self):
    """Only a *successful* exchange consumes the session."""
    self.client_validator.validate_proof.side_effect = [
        exceptions.PolicyViolationError("bad client"),
        None,
    ]
    atls = self._attested_tls()

    with self.assertRaises(exceptions.PolicyViolationError):
      atls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)
    response = atls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    self.assertTrue(response.mutual_attestation_complete)

  def test_second_attestation_on_an_attested_session_is_refused(self):
    """Re-attesting binds to the same EKM, so it proves nothing new."""
    atls = self._attested_tls()
    atls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    with self.assertRaises(attestation_protocol.AttestationReplayError):
      atls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

  def test_server_only_request_on_an_attested_session_is_refused(self):
    """Replay refusal is not a way to downgrade an attested session."""
    atls = self._attested_tls()
    atls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    with self.assertRaises(attestation_protocol.AttestationReplayError):
      atls.attest_connection(
          attestation_pb2.AttestConnectionRequest(
              required_verifier_type=[
                  attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
              ]
          ),
          ssl_obj=self.ssl_obj,
      )

  def test_a_different_session_is_unaffected_by_an_attested_one(self):
    atls = self._attested_tls()
    atls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    other_ssl_obj = mock.MagicMock()
    other_ssl_obj.export_keying_material.return_value = b"other-ekm"
    response = atls.attest_connection(
        _mutual_request(), ssl_obj=other_ssl_obj
    )

    self.assertTrue(response.mutual_attestation_complete)

  def test_missing_client_proof_is_rejected(self):
    atls = self._attested_tls()
    request = _mutual_request()
    request.ClearField("client_attestation")

    with self.assertRaisesRegex(
        ValueError, "Client attestation proof is missing."
    ):
      atls.attest_connection(request, ssl_obj=self.ssl_obj)

  def test_nonce_is_rejected_in_mutual_mode(self):
    """A caller-chosen EKM context would let the peers derive different keys."""
    atls = self._attested_tls()

    with self.assertRaisesRegex(ValueError, "nonce must be empty"):
      atls.attest_connection(
          _mutual_request(nonce=b"n" * 32), ssl_obj=self.ssl_obj
      )

  def test_unsupported_protocol_version_is_rejected(self):
    atls = self._attested_tls()

    with self.assertRaisesRegex(
        ValueError, "Unsupported mutual attestation protocol version"
    ):
      atls.attest_connection(
          _mutual_request(protocol_version=2), ssl_obj=self.ssl_obj
      )

  def test_mutual_request_to_a_server_without_a_client_policy_is_rejected(self):
    atls = attestation.AttestedTLS(self.token_manager)

    with self.assertRaisesRegex(
        ValueError, "not configured to verify client evidence"
    ):
      atls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

  def test_server_only_request_is_rejected_when_mutual_is_required(self):
    atls = self._attested_tls(require_mutual_attestation=True)

    with self.assertRaisesRegex(
        ValueError, "This server requires mutual attestation."
    ):
      atls.attest_connection(
          attestation_pb2.AttestConnectionRequest(
              required_verifier_type=[
                  attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
              ]
          ),
          ssl_obj=self.ssl_obj,
      )

  def test_server_only_request_is_accepted_when_mutual_is_optional(self):
    atls = self._attested_tls()

    response = atls.attest_connection(
        attestation_pb2.AttestConnectionRequest(
            required_verifier_type=[
                attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
            ],
            nonce=b"n" * 32,
        ),
        ssl_obj=self.ssl_obj,
    )

    self.assertFalse(response.mutual_attestation_complete)
    self.assertEqual(response.mode, attestation_pb2.ATTESTATION_MODE_SERVER_ONLY)
    self.client_validator.validate_proof.assert_not_called()

  def test_server_only_request_may_not_carry_a_client_proof(self):
    atls = self._attested_tls()

    with self.assertRaisesRegex(
        ValueError, "client_attestation is valid only for mutual attestation."
    ):
      atls.attest_connection(
          attestation_pb2.AttestConnectionRequest(
              required_verifier_type=[
                  attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
              ],
              client_attestation=attestation_pb2.AttestationProof(),
          ),
          ssl_obj=self.ssl_obj,
      )

  def test_unknown_mode_is_rejected(self):
    atls = self._attested_tls()

    with self.assertRaisesRegex(ValueError, "Unsupported attestation mode"):
      atls.attest_connection(
          _mutual_request(mode=99), ssl_obj=self.ssl_obj
      )

  def test_requiring_mutual_attestation_without_a_policy_is_rejected(self):
    with self.assertRaisesRegex(
        ValueError, "client_policy is required when mutual attestation"
    ):
      attestation.AttestedTLS(
          self.token_manager, require_mutual_attestation=True
      )

  def test_client_validator_is_built_once_and_reused(self):
    """OIDC discovery is expensive; it must not run per connection."""
    factory = mock.MagicMock(return_value=self.client_validator)
    atls = self._attested_tls(attestation_validator_cls=factory)

    atls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)
    other_ssl_obj = mock.MagicMock()
    other_ssl_obj.export_keying_material.return_value = b"other-ekm"
    atls.attest_connection(_mutual_request(), ssl_obj=other_ssl_obj)

    factory.assert_called_once_with(self.policy)

  def test_client_validator_is_not_built_for_server_only_traffic(self):
    factory = mock.MagicMock(return_value=self.client_validator)
    atls = self._attested_tls(attestation_validator_cls=factory)

    atls.attest_connection(
        attestation_pb2.AttestConnectionRequest(
            required_verifier_type=[
                attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
            ]
        ),
        ssl_obj=self.ssl_obj,
    )

    factory.assert_not_called()


if __name__ == "__main__":
  absltest.main()
