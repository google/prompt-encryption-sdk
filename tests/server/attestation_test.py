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
    mock_token_manager.key_manager.sign_payload_mldsa.return_value = pqc_signature

    mock_ssl_obj = mock.MagicMock()
    mock_ssl_obj.export_keying_material.return_value = ekm_bytes

    attested_tls_instance = attestation.AttestedTLS(token_manager=mock_token_manager)
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
        nonce=b"test_nonce",
    )
    expected_payload = attestation_pb2.SessionSignaturePayload(
        ekm_hash=hashlib.sha256(ekm_bytes).digest(),
        token_hash=hashlib.sha256(attestation_token).digest(),
    )

    response = attested_tls_instance.attest_connection(request, ssl_obj=mock_ssl_obj)

    mock_token_manager.key_manager.sign_payload.assert_called_once()
    mock_token_manager.key_manager.sign_payload_mldsa.assert_called_once()
    call_args = mock_token_manager.key_manager.sign_payload.call_args[0][0]
    actual_payload = attestation_pb2.SessionSignaturePayload.FromString(call_args)

    with self.subTest(name="EvidencePopulated"):
      self.assertEqual(
          response.evidence[0].gca_bundle.attestation_token.encode("utf-8"),
          attestation_token,
      )
      self.assertEqual(response.session_signature, signature)
      self.assertEqual(response.pqc_session_signature, pqc_signature)

    with self.subTest(name="PublicKeyPopulated"):
      self.assertEqual(response.instance_public_key.key_bytes, public_key)
      self.assertEqual(response.pqc_public_key.serialized_public_keyset, pqc_public_key)

    with self.subTest(name="EKMSigned"):
      self.assertEqual(expected_payload, actual_payload)

  @mock.patch.object(exporter, "export_keying_material", autospec=True)
  def test_attest_connection_ekm_extraction_fails(self, mock_export_keying_material):
    mock_export_keying_material.return_value = None
    mock_ssl_obj = mock.MagicMock()
    mock_ssl_obj.export_keying_material.side_effect = Exception("EKM failed")
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_token_manager.key_manager = mock.create_autospec(
        keys.KeyManager, instance=True
    )
    attested_tls_instance = attestation.AttestedTLS(token_manager=mock_token_manager)
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
    attested_tls_instance = attestation.AttestedTLS(token_manager=mock_token_manager)
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

    attested_tls_instance = attestation.AttestedTLS(token_manager=mock_token_manager)
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_UNSPECIFIED]
    )
    with self.assertRaisesRegex(ValueError, "Unsupported verifier types requested:"):
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

    attested_tls_instance = attestation.AttestedTLS(token_manager=mock_token_manager)
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[
            attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
            attestation_pb2.VerifierType.VERIFIER_TYPE_UNSPECIFIED,
        ]
    )
    with self.assertRaisesRegex(ValueError, "Unsupported verifier types requested:"):
      attested_tls_instance.attest_connection(request, ssl_obj=mock_ssl_obj)

  def test_mutual_attestation_verifies_client_before_completion(self):
    mock_key_manager = mock.create_autospec(keys.KeyManager, instance=True)
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_token_manager.key_manager = mock_key_manager
    mock_token_manager.get_identity_snapshot.return_value = (
        b"server-ecdsa-public-key",
        b"server-pqc-public-key",
        b"server-token",
    )
    mock_key_manager.sign_payload.return_value = b"server-ecdsa-signature"
    mock_key_manager.sign_payload_mldsa.return_value = b"server-pqc-signature"
    mock_validator_cls = mock.MagicMock()
    ssl_obj = mock.MagicMock()
    ssl_obj.export_keying_material.return_value = b"shared-mutual-ekm"
    client_nonce = b"c" * 32
    server_nonce = b"s" * 32
    handshake_id = b"h" * 32
    nonce_fn = mock.Mock(side_effect=[server_nonce, handshake_id])
    implementation = attestation.AttestedTLS(
        mock_token_manager,
        client_policy=attestation_pb2.AttestationPolicy(),
        attestation_validator_cls=mock_validator_cls,
        nonce_fn=nonce_fn,
    )

    initial_request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
        nonce=client_nonce,
        protocol_version=1,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    initial_response = implementation.attest_connection(
        initial_request, ssl_obj=ssl_obj
    )

    self.assertEqual(initial_response.protocol_version, 1)
    self.assertEqual(initial_response.mode, attestation_pb2.ATTESTATION_MODE_MUTUAL)
    self.assertEqual(initial_response.server_nonce, server_nonce)
    self.assertEqual(initial_response.handshake_id, handshake_id)
    self.assertFalse(initial_response.mutual_attestation_complete)
    self.assertFalse(
        implementation.completes_attestation(initial_request, initial_response)
    )

    client_proof = attestation_pb2.AttestationProof(session_signature=b"client-proof")
    finish_request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
        nonce=client_nonce,
        protocol_version=1,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        phase=attestation_pb2.ATTESTATION_HANDSHAKE_PHASE_CLIENT_FINISH,
        handshake_id=handshake_id,
        client_attestation=client_proof,
    )
    finish_response = implementation.attest_connection(finish_request, ssl_obj=ssl_obj)

    self.assertTrue(finish_response.mutual_attestation_complete)
    self.assertTrue(
        implementation.completes_attestation(finish_request, finish_response)
    )
    mock_validator_cls.assert_called_once()
    mock_validator_cls.return_value.validate_proof.assert_called_once_with(
        client_proof,
        b"shared-mutual-ekm",
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        transcript_hash_bytes=mock.ANY,
    )

  def test_mutual_finish_is_one_time_and_bound_to_tls_socket(self):
    mock_token_manager = mock.MagicMock()
    mock_token_manager.get_identity_snapshot.return_value = (
        b"ecdsa",
        b"pqc",
        b"token",
    )
    mock_token_manager.key_manager.sign_payload.return_value = b"sig"
    mock_token_manager.key_manager.sign_payload_mldsa.return_value = b"pqc-sig"
    ssl_obj = mock.MagicMock()
    ssl_obj.export_keying_material.return_value = b"ekm"
    other_ssl_obj = mock.MagicMock()
    implementation = attestation.AttestedTLS(
        mock_token_manager,
        client_policy=attestation_pb2.AttestationPolicy(),
        attestation_validator_cls=mock.MagicMock(),
        nonce_fn=mock.Mock(side_effect=[b"s" * 32, b"h" * 32]),
    )
    initial_request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
        nonce=b"c" * 32,
        protocol_version=1,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    response = implementation.attest_connection(initial_request, ssl_obj=ssl_obj)
    finish_request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
        nonce=b"c" * 32,
        protocol_version=1,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        phase=attestation_pb2.ATTESTATION_HANDSHAKE_PHASE_CLIENT_FINISH,
        handshake_id=response.handshake_id,
        client_attestation=attestation_pb2.AttestationProof(session_signature=b"proof"),
    )

    with self.assertRaisesRegex(ValueError, "No pending"):
      implementation.attest_connection(finish_request, ssl_obj=other_ssl_obj)
    implementation.attest_connection(finish_request, ssl_obj=ssl_obj)
    with self.assertRaisesRegex(ValueError, "No pending"):
      implementation.attest_connection(finish_request, ssl_obj=ssl_obj)

  def test_required_mutual_mode_rejects_legacy_client(self):
    implementation = attestation.AttestedTLS(
        mock.MagicMock(),
        client_policy=attestation_pb2.AttestationPolicy(),
        require_mutual_attestation=True,
    )
    legacy_request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA]
    )
    with self.assertRaisesRegex(ValueError, "requires mutual"):
      implementation.attest_connection(legacy_request, ssl_obj=mock.MagicMock())

  def test_mutual_request_rejects_legacy_protocol_version(self):
    implementation = attestation.AttestedTLS(
        mock.MagicMock(),
        client_policy=attestation_pb2.AttestationPolicy(),
    )
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    with self.assertRaisesRegex(ValueError, "protocol version"):
      implementation.attest_connection(request, ssl_obj=mock.MagicMock())

  def test_mutual_finish_rejects_expired_pending_state(self):
    mock_token_manager = mock.MagicMock()
    mock_token_manager.get_identity_snapshot.return_value = (
        b"ecdsa",
        b"pqc",
        b"token",
    )
    mock_token_manager.key_manager.sign_payload.return_value = b"sig"
    mock_token_manager.key_manager.sign_payload_mldsa.return_value = b"pqc-sig"
    mock_validator_cls = mock.MagicMock()
    ssl_obj = mock.MagicMock()
    ssl_obj.export_keying_material.return_value = b"ekm"
    implementation = attestation.AttestedTLS(
        mock_token_manager,
        client_policy=attestation_pb2.AttestationPolicy(),
        attestation_validator_cls=mock_validator_cls,
        nonce_fn=mock.Mock(side_effect=[b"s" * 32, b"h" * 32]),
        clock=mock.Mock(side_effect=[0.0, 31.0]),
        handshake_timeout_seconds=30.0,
    )
    initial_request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
        nonce=b"c" * 32,
        protocol_version=1,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    response = implementation.attest_connection(initial_request, ssl_obj=ssl_obj)
    finish_request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
        nonce=b"c" * 32,
        protocol_version=1,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        phase=attestation_pb2.ATTESTATION_HANDSHAKE_PHASE_CLIENT_FINISH,
        handshake_id=response.handshake_id,
        client_attestation=attestation_pb2.AttestationProof(session_signature=b"proof"),
    )

    with self.assertRaisesRegex(ValueError, "expired"):
      implementation.attest_connection(finish_request, ssl_obj=ssl_obj)
    mock_validator_cls.assert_not_called()


if __name__ == "__main__":
  absltest.main()
