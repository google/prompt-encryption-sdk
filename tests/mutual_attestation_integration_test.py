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

"""Mock-TEE integration test for the complete mutual attestation exchange."""

import hashlib
import pathlib
import tempfile

from absl.testing import absltest
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation as server_attestation
from prompt_encryption_sdk.server import keys


class _Identity:

  def __init__(self, key_manager: keys.KeyManager, token: bytes):
    self.key_manager = key_manager
    self._token = token

  def get_identity_snapshot(self) -> tuple[bytes, bytes, bytes]:
    return (
        self.key_manager.get_current_public_key(),
        self.key_manager.get_current_pqc_public_key(),
        self._token,
    )


class _FakeOIDCValidator:

  def __init__(self, claims_by_token):
    self._claims_by_token = claims_by_token

  def validate_token(self, token: str):
    return self._claims_by_token[token]

  def close(self):
    pass


class _MockTLSSocket:
  """Models both peers deriving identical EKM from one TLS session."""

  def export_keying_material(self, label, length, *, context):
    return hashlib.sha256(b"mock-tls-master-secret" + label + context).digest()[:length]


def _claims_for(identity: _Identity):
  return {
      "eat_nonce": [
          keys.calculate_fingerprint(identity.key_manager.get_current_public_key()),
          keys.calculate_fingerprint(identity.key_manager.get_current_pqc_public_key()),
      ],
      "submods": {"container": {}, "gce": {}},
  }


class MutualAttestationIntegrationTest(absltest.TestCase):

  def test_both_peers_verify_real_ecdsa_and_mldsa_channel_bindings(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      temp_path = pathlib.Path(temp_dir)
      server_identity = self._make_identity(temp_path / "server", b"server-token")
      client_identity = self._make_identity(temp_path / "client", b"client-token")
      oidc = _FakeOIDCValidator(
          {
              "server-token": _claims_for(server_identity),
              "client-token": _claims_for(client_identity),
          }
      )
      client_validator = validator.AttestationValidator(
          attestation_pb2.AttestationPolicy(), oidc_validator=oidc
      )
      server_nonces = iter([b"s" * 32, b"h" * 32])
      server = server_attestation.AttestedTLS(
          server_identity,
          client_policy=attestation_pb2.AttestationPolicy(),
          attestation_validator_cls=lambda policy: validator.AttestationValidator(
              policy, oidc_validator=oidc
          ),
          nonce_fn=lambda unused_length: next(server_nonces),
      )
      tls_socket = _MockTLSSocket()
      client_nonce = b"c" * 32
      initial_request = attestation_pb2.AttestConnectionRequest(
          required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
          nonce=client_nonce,
          protocol_version=1,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )

      server_response = server.attest_connection(initial_request, ssl_obj=tls_socket)
      transcript = attestation_protocol.build_mutual_transcript(
          client_nonce=client_nonce,
          server_nonce=server_response.server_nonce,
          handshake_id=server_response.handshake_id,
      )
      transcript_hash_bytes = attestation_protocol.transcript_hash(transcript)
      tls_ekm = tls_socket.export_keying_material(
          b"EXPORTER-Prompt-Encryption-SDK",
          32,
          context=transcript_hash_bytes,
      )
      client_validator.validate(
          server_response,
          tls_ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
          transcript_hash_bytes=transcript_hash_bytes,
      )

      client_proof = attestation_protocol.AttestationProver(
          client_identity
      ).create_proof(
          tls_ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
          transcript_hash_bytes=transcript_hash_bytes,
      )
      finish_request = attestation_pb2.AttestConnectionRequest(
          required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
          nonce=client_nonce,
          protocol_version=1,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
          phase=attestation_pb2.ATTESTATION_HANDSHAKE_PHASE_CLIENT_FINISH,
          handshake_id=server_response.handshake_id,
          client_attestation=client_proof,
      )
      completion = server.attest_connection(finish_request, ssl_obj=tls_socket)
      self.assertTrue(completion.mutual_attestation_complete)

      with self.assertRaises(exceptions.AttestationVerificationError):
        # A server proof cannot be reflected and accepted as a client proof.
        client_validator.validate(
            server_response,
            tls_ekm,
            peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
            mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
            transcript_hash_bytes=transcript_hash_bytes,
        )

  def _make_identity(self, path: pathlib.Path, token: bytes) -> _Identity:
    path.mkdir()
    key_manager = keys.KeyManager(
        private_key_path=path / "ecdsa-private.pem",
        public_key_path=path / "ecdsa-public.pem",
        pqc_private_key_path=path / "mldsa-private.bin",
        pqc_public_key_path=path / "mldsa-public.bin",
    )
    key_manager.generate_key_pair()
    return _Identity(key_manager, token)


if __name__ == "__main__":
  absltest.main()
