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

"""Mock-TEE tests for the single-round-trip mutual attestation exchange.

Real ECDSA P-256 and ML-DSA-65 keys are generated and every signature is
genuinely produced and verified. Only the Google Cloud Attestation token
issuance and its OIDC verification are faked, since those require a real
Confidential Space workload.
"""

import hashlib
import pathlib

from absl.testing import absltest
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation as server_attestation
from prompt_encryption_sdk.server import keys


_EKM_LABEL = b"EXPORTER-Prompt-Encryption-SDK"
_EKM_LENGTH = 32


class _Identity:
  """A stand-in TokenManager holding real keys and a fake GCA token."""

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
  """Returns pre-canned claims instead of verifying a real GCA token."""

  def __init__(self, claims_by_token):
    self._claims_by_token = claims_by_token

  def validate_token(self, token: str):
    try:
      return self._claims_by_token[token]
    except KeyError as e:
      raise exceptions.AttestationVerificationError("Unknown token.") from e

  def close(self):
    pass


class _MockTLSSocket:
  """Models both peers deriving identical EKM from one TLS session."""

  def __init__(self, secret: bytes = b"mock-tls-master-secret"):
    self._secret = secret

  def export_keying_material(self, label, length, *, context=None):
    seed = self._secret + label + (b"" if context is None else b"\x01" + context)
    return hashlib.sha256(seed).digest()[:length]


def _claims_for(identity: _Identity):
  """Builds GCA claims that bind both public keys via eat_nonce."""
  return {
      "eat_nonce": [
          keys.calculate_fingerprint(
              identity.key_manager.get_current_public_key()
          ),
          keys.calculate_fingerprint(
              identity.key_manager.get_current_pqc_public_key()
          ),
      ],
      "submods": {"container": {}, "gce": {}},
  }


class MutualAttestationTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    root = pathlib.Path(self.create_tempdir().full_path)
    self.server_identity = self._make_identity(root / "server", b"server-token")
    self.client_identity = self._make_identity(root / "client", b"client-token")
    self.oidc = _FakeOIDCValidator({
        "server-token": _claims_for(self.server_identity),
        "client-token": _claims_for(self.client_identity),
    })
    self.policy = attestation_pb2.AttestationPolicy()
    self.client_validator = validator.AttestationValidator(
        self.policy, oidc_validator=self.oidc
    )
    self.server = server_attestation.AttestedTLS(
        self.server_identity,
        client_policy=self.policy,
        attestation_validator_cls=lambda policy: (
            validator.AttestationValidator(policy, oidc_validator=self.oidc)
        ),
    )
    self.tls_socket = _MockTLSSocket()
    self.tls_ekm = self.tls_socket.export_keying_material(
        _EKM_LABEL, _EKM_LENGTH
    )
    self.client_prover = attestation_protocol.AttestationProver(
        self.client_identity
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

  def _client_request(self, **overrides):
    fields = dict(
        required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
        protocol_version=(
            attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
        ),
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        client_attestation=self.client_prover.create_proof(
            self.tls_ekm,
            peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
            mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        ),
    )
    fields.update(overrides)
    return attestation_pb2.AttestConnectionRequest(**fields)

  def test_one_round_trip_verifies_both_peers(self):
    response = self.server.attest_connection(
        self._client_request(), ssl_obj=self.tls_socket
    )

    self.assertTrue(response.mutual_attestation_complete)
    # The client verifies the server proof against the same session EKM.
    self.client_validator.validate(
        response,
        self.tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

  def test_server_proof_cannot_be_reflected_as_a_client_proof(self):
    """Both proofs bind to the same EKM, so only the role separates them."""
    response = self.server.attest_connection(
        self._client_request(), ssl_obj=self.tls_socket
    )

    with self.assertRaises(exceptions.AttestationVerificationError):
      self.client_validator.validate(
          response,
          self.tls_ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )

  def test_client_proof_cannot_be_replayed_to_the_server_as_a_server_proof(self):
    client_proof = self.client_prover.create_proof(
        self.tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    with self.assertRaises(exceptions.AttestationVerificationError):
      self.client_validator.validate_proof(
          client_proof,
          self.tls_ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )

  def test_a_server_only_proof_is_not_accepted_as_a_mutual_one(self):
    """Mode is signed, so an old-style proof cannot satisfy mutual mode."""
    server_only_proof = self.client_prover.create_proof(self.tls_ekm)

    with self.assertRaises(exceptions.AttestationVerificationError):
      self.client_validator.validate_proof(
          server_only_proof,
          self.tls_ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )

  def test_a_proof_from_another_tls_session_is_rejected(self):
    """The EKM is the freshness challenge, so it must not transfer."""
    other_session_ekm = _MockTLSSocket(
        b"a-different-tls-session"
    ).export_keying_material(_EKM_LABEL, _EKM_LENGTH)
    stolen_proof = attestation_protocol.AttestationProver(
        self.client_identity
    ).create_proof(
        other_session_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    with self.assertRaises(exceptions.AttestationVerificationError):
      self.server.attest_connection(
          self._client_request(client_attestation=stolen_proof),
          ssl_obj=self.tls_socket,
      )

  def test_a_client_outside_the_policy_is_rejected(self):
    strict_policy = attestation_pb2.AttestationPolicy(
        gce_instance=attestation_pb2.GceInstancePolicy(project_id="trusted")
    )
    server = server_attestation.AttestedTLS(
        self.server_identity,
        client_policy=strict_policy,
        require_mutual_attestation=True,
        attestation_validator_cls=lambda policy: (
            validator.AttestationValidator(policy, oidc_validator=self.oidc)
        ),
    )

    with self.assertRaises(exceptions.PolicyViolationError):
      server.attest_connection(self._client_request(), ssl_obj=self.tls_socket)

  def test_a_client_with_an_unverifiable_token_is_rejected(self):
    unknown = _Identity(self.client_identity.key_manager, b"forged-token")
    forged_proof = attestation_protocol.AttestationProver(unknown).create_proof(
        self.tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    with self.assertRaises(exceptions.AttestationVerificationError):
      self.server.attest_connection(
          self._client_request(client_attestation=forged_proof),
          ssl_obj=self.tls_socket,
      )

  def test_a_client_key_not_bound_by_its_token_is_rejected(self):
    """The GCA token's eat_nonce must cover the keys that signed the proof."""
    unbound_root = pathlib.Path(self.create_tempdir().full_path) / "unbound"
    unbound = self._make_identity(unbound_root, b"client-token")
    unbound_proof = attestation_protocol.AttestationProver(
        unbound
    ).create_proof(
        self.tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "Instance Key binding failed"
    ):
      self.server.attest_connection(
          self._client_request(client_attestation=unbound_proof),
          ssl_obj=self.tls_socket,
      )

  def test_a_tampered_pqc_signature_is_rejected(self):
    proof = self.client_prover.create_proof(
        self.tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    proof.pqc_session_signature = bytes(
        [proof.pqc_session_signature[0] ^ 0xFF]
    ) + proof.pqc_session_signature[1:]

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "PQC session signature"
    ):
      self.server.attest_connection(
          self._client_request(client_attestation=proof),
          ssl_obj=self.tls_socket,
      )

  def test_a_tampered_ecdsa_signature_is_rejected(self):
    proof = self.client_prover.create_proof(
        self.tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )
    proof.session_signature = bytes(
        [proof.session_signature[0] ^ 0xFF]
    ) + proof.session_signature[1:]

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "session signature"
    ):
      self.server.attest_connection(
          self._client_request(client_attestation=proof),
          ssl_obj=self.tls_socket,
      )

  def test_the_session_is_attested_exactly_once(self):
    self.server.attest_connection(
        self._client_request(), ssl_obj=self.tls_socket
    )

    with self.assertRaises(attestation_protocol.AttestationReplayError):
      self.server.attest_connection(
          self._client_request(), ssl_obj=self.tls_socket
      )


if __name__ == "__main__":
  absltest.main()
