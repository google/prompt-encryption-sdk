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

"""Tests for shared attestation transcript and proof primitives."""

import hashlib
from unittest import mock

from absl.testing import absltest
from prompt_encryption_sdk import attestation
from prompt_encryption_sdk.proto import attestation_pb2


class AttestationProtocolTest(absltest.TestCase):

  def test_mutual_transcript_hash_commits_to_every_negotiated_field(self):
    transcript = attestation.build_mutual_transcript(
        client_nonce=b"c" * attestation.NONCE_LENGTH,
        server_nonce=b"s" * attestation.NONCE_LENGTH,
        handshake_id=b"h" * attestation.HANDSHAKE_ID_LENGTH,
    )
    original_hash = attestation.transcript_hash(transcript)

    for field_name in ("client_nonce", "server_nonce", "handshake_id"):
      changed = attestation_pb2.MutualAttestationTranscript()
      changed.CopyFrom(transcript)
      setattr(changed, field_name, b"x" * len(getattr(changed, field_name)))
      self.assertNotEqual(attestation.transcript_hash(changed), original_hash)

  def test_prover_signs_role_mode_transcript_and_channel_binding(self):
    identity = mock.MagicMock()
    identity.get_identity_snapshot.return_value = (
        b"ecdsa-public",
        b"pqc-public",
        b"attestation-token",
    )
    identity.key_manager.sign_payload.return_value = b"ecdsa-signature"
    identity.key_manager.sign_payload_mldsa.return_value = b"pqc-signature"
    transcript_hash_bytes = b"t" * 32

    proof = attestation.AttestationProver(identity).create_proof(
        b"tls-ekm",
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        transcript_hash_bytes=transcript_hash_bytes,
    )

    signed_payload = identity.key_manager.sign_payload.call_args.args[0]
    parsed_payload = attestation_pb2.SessionSignaturePayload.FromString(signed_payload)
    self.assertEqual(parsed_payload.ekm_hash, hashlib.sha256(b"tls-ekm").digest())
    self.assertEqual(
        parsed_payload.token_hash,
        hashlib.sha256(b"attestation-token").digest(),
    )
    self.assertEqual(
        parsed_payload.peer_role,
        attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
    )
    self.assertEqual(parsed_payload.mode, attestation_pb2.ATTESTATION_MODE_MUTUAL)
    self.assertEqual(parsed_payload.transcript_hash, transcript_hash_bytes)
    self.assertEqual(proof.session_signature, b"ecdsa-signature")
    self.assertEqual(proof.pqc_session_signature, b"pqc-signature")
    identity.key_manager.sign_payload_mldsa.assert_called_once_with(signed_payload)

  def test_legacy_payload_keeps_new_fields_absent(self):
    payload = attestation.build_signature_payload(
        tls_ekm=b"ekm", attestation_token=b"token"
    )
    expected = attestation_pb2.SessionSignaturePayload(
        ekm_hash=hashlib.sha256(b"ekm").digest(),
        token_hash=hashlib.sha256(b"token").digest(),
    ).SerializeToString(deterministic=True)
    self.assertEqual(payload, expected)
    parsed = attestation_pb2.SessionSignaturePayload.FromString(payload)
    self.assertEqual(
        parsed.peer_role,
        attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
    )
    self.assertEqual(parsed.mode, attestation_pb2.ATTESTATION_MODE_SERVER_ONLY)
    self.assertEmpty(parsed.transcript_hash)

  def test_empty_identity_token_fails_closed(self):
    identity = mock.MagicMock()
    identity.get_identity_snapshot.return_value = (b"ecdsa", b"pqc", b"")
    with self.assertRaisesRegex(RuntimeError, "has no token"):
      attestation.AttestationProver(identity).create_proof(b"ekm")


if __name__ == "__main__":
  absltest.main()
