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

"""Tests for the shared attestation proof primitives."""

from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.proto import attestation_pb2

_EKM = b"e" * 32
_TOKEN = b"attestation-token"


class ValidateRequiredVerifiersTest(parameterized.TestCase):

  def test_accepts_gca(self):
    attestation_protocol.validate_required_verifiers(
        [attestation_pb2.VERIFIER_TYPE_GCA]
    )

  def test_rejects_empty(self):
    with self.assertRaisesRegex(
        ValueError, "At least one required_verifier_type must be specified."
    ):
      attestation_protocol.validate_required_verifiers([])

  def test_rejects_unsupported(self):
    with self.assertRaisesRegex(ValueError, "Unsupported verifier types"):
      attestation_protocol.validate_required_verifiers(
          [attestation_pb2.VERIFIER_TYPE_UNSPECIFIED]
      )

  def test_rejects_unsupported_mixed_with_supported(self):
    with self.assertRaisesRegex(ValueError, "Unsupported verifier types"):
      attestation_protocol.validate_required_verifiers([
          attestation_pb2.VERIFIER_TYPE_GCA,
          attestation_pb2.VERIFIER_TYPE_UNSPECIFIED,
      ])


class BuildSignaturePayloadTest(parameterized.TestCase):

  def test_ekm_parameters_are_pinned(self):
    self.assertEqual(
        attestation_protocol.EKM_LABEL, b"EXPORTER-Prompt-Encryption-SDK"
    )
    self.assertEqual(attestation_protocol.EKM_LENGTH, 32)

  def test_server_only_payload_is_wire_compatible(self):
    """The pre-mutual-attestation signed bytes must not change."""
    legacy = bytes.fromhex(
        "0a20dfb417454d7432715ecfaa33d89abdaba4457c3b2cbd85a4a20620d0cd806da6"
        "1220617fcb62ce2800030aa6a89e781a46cbadb3c32a233b33af5adaa69441c0bce4"
    )

    self.assertEqual(
        attestation_protocol.build_signature_payload(
            tls_ekm=_EKM, attestation_token=_TOKEN
        ),
        legacy,
    )

  @parameterized.named_parameters(
      (
          "client",
          attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          (
              "0a20dfb417454d7432715ecfaa33d89abdaba4457c3b2cbd85a4a20620d0cd806da6"
              "1220617fcb62ce2800030aa6a89e781a46cbadb3c32a233b33af5adaa69441c0bce4"
              "180220012801"
          ),
      ),
      (
          "server",
          attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
          (
              "0a20dfb417454d7432715ecfaa33d89abdaba4457c3b2cbd85a4a20620d0cd806da6"
              "1220617fcb62ce2800030aa6a89e781a46cbadb3c32a233b33af5adaa69441c0bce4"
              "180120012801"
          ),
      ),
  )
  def test_mutual_payload_carries_role_mode_and_version(
      self, peer_role, expected_hex
  ):
    self.assertEqual(
        attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION, 1
    )
    self.assertEqual(
        attestation_protocol.build_signature_payload(
            tls_ekm=_EKM,
            attestation_token=_TOKEN,
            peer_role=peer_role,
            mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        ),
        bytes.fromhex(expected_hex),
    )

  def test_roles_produce_distinct_payloads_for_the_same_ekm(self):
    """Role separation is the only thing preventing proof reflection."""
    server = attestation_protocol.build_signature_payload(
        tls_ekm=_EKM,
        attestation_token=_TOKEN,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    client = attestation_protocol.build_signature_payload(
        tls_ekm=_EKM,
        attestation_token=_TOKEN,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    self.assertNotEqual(server, client)

  def test_modes_produce_distinct_payloads_for_the_same_ekm(self):
    mutual = attestation_protocol.build_signature_payload(
        tls_ekm=_EKM,
        attestation_token=_TOKEN,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    server_only = attestation_protocol.build_signature_payload(
        tls_ekm=_EKM,
        attestation_token=_TOKEN,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
        mode=attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
    )

    self.assertNotEqual(mutual, server_only)

  @parameterized.named_parameters(
      (
          "mutual_unspecified_role",
          attestation_pb2.ATTESTATION_MODE_MUTUAL,
          attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
      ),
      (
          "server_only_client_role",
          attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
          attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
      ),
      (
          "server_only_server_role",
          attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
          attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
      ),
  )
  def test_rejects_invalid_mode_and_role_combinations(self, mode, peer_role):
    with self.assertRaisesRegex(
        ValueError, r"Invalid \(mode, peer_role\) combination"
    ):
      attestation_protocol.build_signature_payload(
          tls_ekm=_EKM,
          attestation_token=_TOKEN,
          peer_role=peer_role,
          mode=mode,
      )

  def test_payload_is_deterministic(self):
    self.assertEqual(
        attestation_protocol.build_signature_payload(
            tls_ekm=_EKM,
            attestation_token=_TOKEN,
            peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
            mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        ),
        attestation_protocol.build_signature_payload(
            tls_ekm=_EKM,
            attestation_token=_TOKEN,
            peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
            mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        ),
    )


class AttestationProverTest(parameterized.TestCase):

  def _identity(self, token=_TOKEN):
    """Returns a fake identity whose snapshot carries `token`."""
    identity = mock.create_autospec(
        attestation_protocol.IdentitySnapshotProvider, instance=True
    )
    identity.key_manager = mock.create_autospec(
        attestation_protocol.SigningKeyManager, instance=True
    )
    identity.get_identity_snapshot.return_value = (
        b"ecdsa-public",
        b"mldsa-public",
        token,
    )
    identity.key_manager.sign_payload.return_value = b"ecdsa-signature"
    identity.key_manager.sign_payload_mldsa.return_value = b"mldsa-signature"
    return identity

  def test_create_proof_signs_the_canonical_payload_with_both_keys(self):
    identity = self._identity()

    proof = attestation_protocol.AttestationProver(identity).create_proof(
        _EKM,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    expected_payload = attestation_protocol.build_signature_payload(
        tls_ekm=_EKM,
        attestation_token=_TOKEN,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    identity.key_manager.sign_payload.assert_called_once_with(expected_payload)
    identity.key_manager.sign_payload_mldsa.assert_called_once_with(
        expected_payload
    )
    self.assertEqual(proof.session_signature, b"ecdsa-signature")
    self.assertEqual(proof.pqc_session_signature, b"mldsa-signature")
    self.assertEqual(proof.instance_public_key.key_bytes, b"ecdsa-public")
    self.assertEqual(
        proof.pqc_public_key.serialized_public_keyset, b"mldsa-public"
    )
    self.assertEqual(
        proof.evidence[0].verifier_type, attestation_pb2.VERIFIER_TYPE_GCA
    )
    self.assertEqual(
        proof.evidence[0].gca_bundle.attestation_token, _TOKEN.decode("utf-8")
    )

  def test_create_proof_without_token_fails(self):
    with self.assertRaisesRegex(RuntimeError, "no token"):
      attestation_protocol.AttestationProver(
          self._identity(token=b"")
      ).create_proof(_EKM)


class ProofResponseConversionTest(parameterized.TestCase):

  def _proof(self):
    """Returns a proof with every field that a response carries set."""
    return attestation_pb2.AttestationProof(
        evidence=[
            attestation_pb2.AttestationEvidence(
                verifier_type=attestation_pb2.VERIFIER_TYPE_GCA,
                gca_bundle=attestation_pb2.GcaTrustBundle(
                    attestation_token="token"
                ),
            )
        ],
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=b"ecdsa"
        ),
        session_signature=b"sig",
        pqc_public_key=attestation_pb2.MlDsaPublicKey(
            serialized_public_keyset=b"mldsa"
        ),
        pqc_session_signature=b"pqc-sig",
    )

  def test_server_only_response_has_no_mutual_echo(self):
    response = attestation_protocol.response_from_proof(self._proof())

    self.assertEqual(response.protocol_version, 0)
    self.assertEqual(
        response.mode, attestation_pb2.ATTESTATION_MODE_SERVER_ONLY
    )
    self.assertFalse(response.mutual_attestation_complete)

  def test_populates_response_fields_from_proof(self):
    proof = self._proof()

    response = attestation_protocol.response_from_proof(
        proof,
        protocol_version=1,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        mutual_attestation_complete=True,
    )

    self.assertEqual(response.protocol_version, 1)
    self.assertEqual(response.mode, attestation_pb2.ATTESTATION_MODE_MUTUAL)
    self.assertTrue(response.mutual_attestation_complete)
    self.assertEqual(list(response.evidence), list(proof.evidence))
    self.assertEqual(response.instance_public_key, proof.instance_public_key)
    self.assertEqual(response.session_signature, proof.session_signature)
    self.assertEqual(response.pqc_public_key, proof.pqc_public_key)
    self.assertEqual(
        response.pqc_session_signature, proof.pqc_session_signature
    )


if __name__ == "__main__":
  absltest.main()
