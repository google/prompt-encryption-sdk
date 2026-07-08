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
    attestation_token = b"test_attestation_token"
    signature = b"test_signature"
    ekm_bytes = b"test_ekm"

    mock_token_manager.get_identity_snapshot.return_value = (
        public_key,
        attestation_token,
    )
    mock_token_manager.key_manager.sign_payload.return_value = signature

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

    with self.subTest(name="PublicKeyPopulated"):
      self.assertEqual(response.instance_public_key.key_bytes, public_key)

    with self.subTest(name="EKMSigned"):
      compare.assertProto2Equal(self, expected_payload, actual_payload)

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



if __name__ == "__main__":
  absltest.main()
