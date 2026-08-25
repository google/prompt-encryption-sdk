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

import hashlib
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

  def test_server_only_payload_is_wire_compatible(self):
    """The pre-mutual-attestation signed bytes must not change."""
    legacy = attestation_pb2.SessionSignaturePayload(
        ekm_hash=hashlib.sha256(_EKM).digest(),
        token_hash=hashlib.sha256(_TOKEN).digest(),
    ).SerializeToString()

    self.assertEqual(
        attestation_protocol.build_signature_payload(
            tls_ekm=_EKM, attestation_token=_TOKEN
        ),
        legacy,
    )

  def test_mutual_payload_carries_role_mode_and_version(self):
    payload = attestation_pb2.SessionSignaturePayload.FromString(
        attestation_protocol.build_signature_payload(
            tls_ekm=_EKM,
            attestation_token=_TOKEN,
            peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
            mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        )
    )

    self.assertEqual(
        payload,
        attestation_pb2.SessionSignaturePayload(
            ekm_hash=hashlib.sha256(_EKM).digest(),
            token_hash=hashlib.sha256(_TOKEN).digest(),
            peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
            mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
            protocol_version=(
                attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
            ),
        ),
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
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
        mode=attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
    )

    self.assertNotEqual(mutual, server_only)

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
    identity = mock.MagicMock()
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

  def test_round_trips_through_the_response_shape(self):
    proof = self._proof()

    response = attestation_protocol.response_from_proof(
        proof,
        protocol_version=1,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        mutual_attestation_complete=True,
    )

    self.assertTrue(response.mutual_attestation_complete)
    self.assertEqual(
        attestation_protocol.proof_from_response(response), proof
    )


if __name__ == "__main__":
  absltest.main()
