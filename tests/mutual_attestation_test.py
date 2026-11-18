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

"""Tests for the single-round-trip mutual attestation exchange, without sockets.

Real ECDSA P-256 and ML-DSA-65 keys are generated and every signature is
genuinely produced and verified by the real `AttestedTLS` and
`AttestationValidator`. Only Google Cloud Attestation and the TLS session are
faked; see `mutual_testlib`.
"""

import pathlib
import time

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.proto import attestation_pb2
import mutual_testlib


class MutualAttestationTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    root = pathlib.Path(self.create_tempdir().full_path)
    self.gca = mutual_testlib.FakeGca()
    self.server_identity = mutual_testlib.make_token_manager(
        root / "server", self.gca
    )
    self.client_identity = mutual_testlib.make_token_manager(
        root / "client", self.gca
    )
    self.policy = attestation_pb2.AttestationPolicy()
    self.client_validator = self.gca.validator_factory(self.policy)
    self.server = mutual_testlib.make_attested_tls(
        self.server_identity, self.gca, client_policy=self.policy
    )
    self.tls_session = mutual_testlib.FakeTlsSession()
    self.tls_ekm = self.tls_session.ekm()

  def _attest(self, server=None, **overrides):
    """Sends a mutual request over `self.tls_session`."""
    return (server or self.server).attest_connection(
        mutual_testlib.mutual_request(
            self.client_identity, self.tls_ekm, **overrides
        ),
        ssl_obj=self.tls_session,
    )

  def test_one_round_trip_verifies_both_peers(self):
    """Also catches a server that signs as another role."""
    result = self._attest()

    self.assertTrue(result.response.mutual_attestation_complete)
    # The client verifies the server proof against the same session EKM.
    self.client_validator.validate(
        result.response,
        self.tls_ekm,
        peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

  def test_the_session_inherits_the_client_token_expiry(self):
    """Authorization lasts exactly as long as the evidence behind it."""
    expiry = int(time.time()) + 120
    mutual_testlib.reissue_token(
        self.client_identity, self.gca, expires_at=expiry
    )

    result = self._attest()

    self.assertEqual(result.expires_at, expiry)

  def test_server_proof_cannot_be_reflected_as_a_client_proof(self):
    """Both proofs bind to the same EKM, so only the role separates them."""
    result = self._attest()

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "session signature"
    ):
      self.client_validator.validate(
          result.response,
          self.tls_ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )

  def test_client_proof_cannot_be_replayed_as_a_server_proof(self):
    client_proof = mutual_testlib.client_proof(
        self.client_identity, self.tls_ekm
    )

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "session signature"
    ):
      self.client_validator.validate_proof(
          client_proof,
          self.tls_ekm,
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )

  @parameterized.named_parameters(
      (
          "server_only_proof",
          attestation_pb2.ATTESTATION_PEER_ROLE_UNSPECIFIED,
          attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
      ),
      (
          "server_role",
          attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
          attestation_pb2.ATTESTATION_MODE_MUTUAL,
      ),
      (
          "server_only_mode",
          attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          attestation_pb2.ATTESTATION_MODE_SERVER_ONLY,
      ),
  )
  def test_server_rejects_a_client_proof_signed_for_another_role_or_mode(
      self, peer_role, mode
  ):
    """Role and mode are signed, so a proof for another purpose fails."""
    proof = mutual_testlib.client_proof(
        self.client_identity, self.tls_ekm, peer_role=peer_role, mode=mode
    )

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "session signature"
    ):
      self._attest(client_attestation=proof)

  def test_a_proof_from_another_tls_session_is_rejected(self):
    """The EKM is the freshness challenge, so it must not transfer."""
    other_session_ekm = mutual_testlib.FakeTlsSession(b"another-session").ekm()
    stolen_proof = mutual_testlib.client_proof(
        self.client_identity, other_session_ekm
    )

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "session signature"
    ):
      self._attest(client_attestation=stolen_proof)

  def test_a_client_outside_the_policy_is_rejected(self):
    strict_policy = attestation_pb2.AttestationPolicy(
        gce_instance=attestation_pb2.GceInstancePolicy(project_id="trusted")
    )
    server = mutual_testlib.make_attested_tls(
        self.server_identity,
        self.gca,
        client_policy=strict_policy,
        require_mutual_attestation=True,
    )

    with self.assertRaisesRegex(
        exceptions.PolicyViolationError, "GCE Instance project_id mismatch"
    ):
      self._attest(server)

  def test_client_policy_expected_audience_is_enforced(self):
    audience = "https://custom-peer-audience.example.com"
    server = mutual_testlib.make_attested_tls(
        self.server_identity,
        self.gca,
        client_policy=attestation_pb2.AttestationPolicy(
            expected_audience=audience
        ),
        require_mutual_attestation=True,
    )

    with self.subTest("DefaultAudienceRejected"):
      with self.assertRaisesRegex(
          exceptions.AttestationVerificationError,
          "OIDC Token validation failed",
      ):
        self._attest(server)
    with self.subTest("ExpectedAudienceAccepted"):
      self.client_identity.attestation_token_path.write_bytes(
          self.gca.issue_token(
              self.client_identity.key_manager, audience=audience
          )
      )
      self.assertTrue(self._attest(server).response.mutual_attestation_complete)

  def test_a_client_with_an_expired_token_is_rejected(self):
    mutual_testlib.reissue_token(
        self.client_identity, self.gca, expires_at=time.time() - 1
    )

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "OIDC Token validation failed",
    ):
      self._attest()

  def test_a_client_with_a_token_from_another_issuer_is_rejected(self):
    mutual_testlib.reissue_token(self.client_identity, mutual_testlib.FakeGca())

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "OIDC Token validation failed",
    ):
      self._attest()

  def test_a_client_key_not_bound_by_its_token_is_rejected(self):
    """The GCA token's eat_nonce must cover the keys that signed the proof."""
    unbound = mutual_testlib.make_token_manager(
        pathlib.Path(self.create_tempdir().full_path), self.gca
    )
    # The token vouches for the real client's keys, not for `unbound`'s.
    unbound.attestation_token_path.write_bytes(
        self.client_identity.attestation_token_path.read_bytes()
    )

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "Instance Key binding failed"
    ):
      self._attest(
          client_attestation=mutual_testlib.client_proof(unbound, self.tls_ekm)
      )

  @parameterized.named_parameters(
      ("ecdsa", "session_signature", "session signature"),
      ("ml_dsa", "pqc_session_signature", "PQC session signature"),
  )
  def test_a_tampered_signature_is_rejected(self, field, message):
    proof = mutual_testlib.client_proof(self.client_identity, self.tls_ekm)
    signature = getattr(proof, field)
    setattr(proof, field, bytes([signature[0] ^ 0xFF]) + signature[1:])

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, message
    ):
      self._attest(client_attestation=proof)

  def test_the_session_is_attested_exactly_once(self):
    self._attest()

    with self.assertRaisesRegex(
        attestation_protocol.AttestationReplayError, "already mutually attested"
    ):
      self._attest()

  def test_a_mutual_request_over_tls_1_2_gets_no_server_proof(self):
    self.tls_session = mutual_testlib.FakeTlsSession(
        tls_version=mutual_testlib.TLS_1_2
    )

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError, "requires TLSv1.3"
    ):
      self._attest()


if __name__ == "__main__":
  absltest.main()
