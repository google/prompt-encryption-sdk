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

import functools
import hashlib
import math
import threading
import time
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.ekm import exporter
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token
import mutual_testlib


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
    ).response

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
        attestation_protocol.AttestationRequestError,
        "At least one required_verifier_type must be specified.",
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
        attestation_protocol.AttestationRequestError,
        "Unsupported verifier types requested:",
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
        attestation_protocol.AttestationRequestError,
        "Unsupported verifier types requested:",
    ):
      attested_tls_instance.attest_connection(request, ssl_obj=mock_ssl_obj)

  def test_attest_connection_without_a_token_fails(self):
    """A server that has no token yet sends no proof."""
    mock_key_manager = mock.create_autospec(keys.KeyManager, instance=True)
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_token_manager.key_manager = mock_key_manager
    mock_token_manager.get_identity_snapshot.return_value = (
        b"pk",
        b"pqc_pk",
        b"",
    )
    mock_key_manager.sign_payload.return_value = b"sig"
    mock_key_manager.sign_payload_mldsa.return_value = b"pqc_sig"
    mock_ssl_obj = mock.Mock(spec=["export_keying_material"])
    mock_ssl_obj.export_keying_material.return_value = b"ekm"
    attested_tls_instance = attestation.AttestedTLS(
        token_manager=mock_token_manager
    )
    request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
        nonce=b"test_nonce",
    )

    with self.assertRaisesRegex(RuntimeError, "no token"):
      attested_tls_instance.attest_connection(request, ssl_obj=mock_ssl_obj)

    mock_key_manager.sign_payload.assert_not_called()
    mock_key_manager.sign_payload_mldsa.assert_not_called()


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


class MutualAttestedTlsTest(parameterized.TestCase):
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

    self.ssl_obj = mock.create_autospec(
        mutual_testlib.FakeTlsSession, instance=True
    )
    self.ssl_obj.export_keying_material.return_value = self.ekm
    self.ssl_obj.version.return_value = "TLSv1.3"

    self.client_validator = mock.create_autospec(
        validator.AttestationValidator, instance=True
    )
    self.client_token_exp = time.time() + 3600
    self.client_validator.validate_proof.return_value = {
        "exp": self.client_token_exp
    }
    self.policy = attestation_pb2.AttestationPolicy()

  def _attested_tls(self, **overrides):
    """Returns an `AttestedTLS` that checks clients with `client_validator`."""
    kwargs = dict(
        client_policy=self.policy,
        attestation_validator_cls=lambda policy: self.client_validator,
    )
    kwargs.update(overrides)
    return attestation.AttestedTLS(self.token_manager, **kwargs)

  def test_verifies_client_proof_then_returns_server_proof(self):
    attested_tls = self._attested_tls()
    request = _mutual_request()

    result = attested_tls.attest_connection(request, ssl_obj=self.ssl_obj)
    response = result.response

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
    with self.subTest("SessionInheritsTheClientTokenExpiry"):
      self.assertEqual(result.expires_at, self.client_token_exp)

  def test_client_proof_is_verified_before_the_server_proves_itself(self):
    """A failed client check must not leak a fresh server proof."""
    self.client_validator.validate_proof.side_effect = (
        exceptions.PolicyViolationError("bad client")
    )
    attested_tls = self._attested_tls()

    with self.assertRaisesRegex(exceptions.PolicyViolationError, "bad client"):
      attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    self.key_manager.sign_payload.assert_not_called()
    self.key_manager.sign_payload_mldsa.assert_not_called()

  @parameterized.parameters("TLSv1.2", "TLSv1.1", "TLSv1", None)
  def test_mutual_request_over_a_session_that_is_not_tls_1_3_is_rejected(
      self, tls_version
  ):
    """Without TLS 1.3 the EKM may not be unique to the session."""
    self.ssl_obj.version.return_value = tls_version
    attested_tls = self._attested_tls()

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError, "requires TLSv1.3"
    ):
      attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    with self.subTest("ClientProofNotVerified"):
      self.client_validator.validate_proof.assert_not_called()
    with self.subTest("NoServerProof"):
      self.key_manager.sign_payload.assert_not_called()
      self.key_manager.sign_payload_mldsa.assert_not_called()

  @parameterized.parameters(({},), ({"exp": float("nan")},), ({"exp": True},))
  def test_a_client_token_without_a_usable_expiry_is_rejected(self, claims):
    """Otherwise the session would never expire on the server."""
    self.client_validator.validate_proof.return_value = claims
    attested_tls = self._attested_tls()

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "must be a finite number"
    ):
      attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    self.key_manager.sign_payload.assert_not_called()

  def test_server_only_request_over_tls_1_2_is_still_served(self):
    """The TLS 1.3 rule is for mutual mode only; server-only is unchanged."""
    self.ssl_obj.version.return_value = "TLSv1.2"
    attested_tls = self._attested_tls()

    result = attested_tls.attest_connection(
        attestation_pb2.AttestConnectionRequest(
            required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
            nonce=b"n" * 32,
        ),
        ssl_obj=self.ssl_obj,
    )

    self.assertEqual(result.response.session_signature, b"server-sig")

  def test_rejected_client_can_retry_on_the_same_session(self):
    """Only a *successful* exchange consumes the session."""
    self.client_validator.validate_proof.side_effect = [
        exceptions.PolicyViolationError("bad client"),
        {"exp": self.client_token_exp},
    ]
    attested_tls = self._attested_tls()

    with self.assertRaisesRegex(exceptions.PolicyViolationError, "bad client"):
      attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)
    result = attested_tls.attest_connection(
        _mutual_request(), ssl_obj=self.ssl_obj
    )

    self.assertTrue(result.response.mutual_attestation_complete)

  def test_second_attestation_on_an_attested_session_is_refused(self):
    """Re-attesting binds to the same EKM, so it proves nothing new."""
    attested_tls = self._attested_tls()
    attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    with self.assertRaisesRegex(
        attestation_protocol.AttestationReplayError, "already mutually attested"
    ):
      attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

  def test_server_only_request_on_an_attested_session_is_refused(self):
    """Replay refusal is not a way to downgrade an attested session."""
    attested_tls = self._attested_tls()
    attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    with self.assertRaisesRegex(
        attestation_protocol.AttestationReplayError, "already mutually attested"
    ):
      attested_tls.attest_connection(
          attestation_pb2.AttestConnectionRequest(
              required_verifier_type=[
                  attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
              ]
          ),
          ssl_obj=self.ssl_obj,
      )

  def test_empty_request_on_an_attested_session_raises_replay_error(self):
    """Replay check runs before required_verifier_type validation."""
    attested_tls = self._attested_tls()
    attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    with self.assertRaisesRegex(
        attestation_protocol.AttestationReplayError, "already mutually attested"
    ):
      attested_tls.attest_connection(
          attestation_pb2.AttestConnectionRequest(),
          ssl_obj=self.ssl_obj,
      )

  def test_a_different_session_is_unaffected_by_an_attested_one(self):
    attested_tls = self._attested_tls()
    attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

    other_ssl_obj = mock.create_autospec(
        mutual_testlib.FakeTlsSession, instance=True
    )
    other_ssl_obj.export_keying_material.return_value = b"other-ekm"
    other_ssl_obj.version.return_value = "TLSv1.3"
    result = attested_tls.attest_connection(
        _mutual_request(), ssl_obj=other_ssl_obj
    )

    self.assertTrue(result.response.mutual_attestation_complete)

  def test_missing_client_proof_is_rejected(self):
    attested_tls = self._attested_tls()
    request = _mutual_request()
    request.ClearField("client_attestation")

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError,
        "Client attestation proof is missing.",
    ):
      attested_tls.attest_connection(request, ssl_obj=self.ssl_obj)

  def test_nonce_is_rejected_in_mutual_mode(self):
    """A caller-chosen EKM context would let the peers derive different keys."""
    attested_tls = self._attested_tls()

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError, "nonce must be empty"
    ):
      attested_tls.attest_connection(
          _mutual_request(nonce=b"n" * 32), ssl_obj=self.ssl_obj
      )

  @parameterized.parameters(0, 2)
  def test_unsupported_protocol_version_is_rejected(self, protocol_version):
    attested_tls = self._attested_tls()

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError,
        "Unsupported mutual attestation protocol version",
    ):
      attested_tls.attest_connection(
          _mutual_request(protocol_version=protocol_version),
          ssl_obj=self.ssl_obj,
      )

  @parameterized.parameters(1, 2)
  def test_server_only_request_with_a_protocol_version_is_rejected(
      self, protocol_version
  ):
    """A request from a newer protocol gets no server-only answer."""
    attested_tls = self._attested_tls()

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError,
        "Unsupported server-only protocol version",
    ):
      attested_tls.attest_connection(
          attestation_pb2.AttestConnectionRequest(
              required_verifier_type=[
                  attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
              ],
              nonce=b"n" * 32,
              protocol_version=protocol_version,
          ),
          ssl_obj=self.ssl_obj,
      )

  def _attest_into(
      self, attested_tls, request, outcome, done=None, ssl_obj=None
  ):
    """Attests on `ssl_obj` (default `self.ssl_obj`) and records the outcome."""
    try:
      outcome["result"] = attested_tls.attest_connection(
          request, ssl_obj=ssl_obj or self.ssl_obj
      )
    except attestation_protocol.AttestationReplayError as e:
      outcome["error"] = e
    finally:
      if done is not None:
        done.set()

  def _blocking_validator_factory(self, constructing, unblock, policy):
    del policy  # Unused.
    constructing.set()
    unblock.wait(timeout=10)
    return self.client_validator

  def test_only_one_of_two_concurrent_mutual_attestations_passes(self):
    attested_tls = self._attested_tls()
    both_verifying = threading.Barrier(2, timeout=10)

    def validate_proof(*args, **kwargs):
      del args, kwargs  # Unused.
      # Both requests pass the first replay check before either finishes.
      both_verifying.wait()
      return {"exp": self.client_token_exp}

    self.client_validator.validate_proof.side_effect = validate_proof
    outcomes = [{}, {}]
    threads = [
        threading.Thread(
            target=self._attest_into,
            args=(attested_tls, _mutual_request(), outcome),
        )
        for outcome in outcomes
    ]
    for thread in threads:
      thread.start()
    for thread in threads:
      thread.join(timeout=10)

    self.assertCountEqual(
        [list(outcome) for outcome in outcomes], [["result"], ["error"]]
    )

  def test_a_server_only_attestation_that_races_a_mutual_one_is_refused(self):
    attested_tls = self._attested_tls()
    server_only_signing = threading.Event()
    mutual_done = threading.Event()

    def validate_proof(*args, **kwargs):
      del args, kwargs  # Unused.
      # The server-only request passes its first replay check first.
      server_only_signing.wait(timeout=10)
      return {"exp": self.client_token_exp}

    def sign_payload(payload):
      del payload  # Unused.
      if threading.current_thread().name == "server-only":
        server_only_signing.set()
        mutual_done.wait(timeout=10)
      return b"server-sig"

    self.client_validator.validate_proof.side_effect = validate_proof
    self.key_manager.sign_payload.side_effect = sign_payload
    mutual_outcome = {}
    server_only_outcome = {}
    server_only_request = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
        nonce=b"n" * 32,
    )
    threads = [
        threading.Thread(
            target=self._attest_into,
            args=(attested_tls, _mutual_request(), mutual_outcome, mutual_done),
            name="mutual",
        ),
        threading.Thread(
            target=self._attest_into,
            args=(attested_tls, server_only_request, server_only_outcome),
            name="server-only",
        ),
    ]
    for thread in threads:
      thread.start()
    for thread in threads:
      thread.join(timeout=10)

    self.assertEqual(list(mutual_outcome), ["result"])
    self.assertEqual(list(server_only_outcome), ["error"])

  def test_mutual_request_to_a_server_without_a_client_policy_is_rejected(self):
    attested_tls = attestation.AttestedTLS(self.token_manager)

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError,
        "not configured to verify client evidence",
    ):
      attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)

  def test_server_only_request_is_rejected_when_mutual_is_required(self):
    attested_tls = self._attested_tls(require_mutual_attestation=True)

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError,
        "This server requires mutual attestation.",
    ):
      attested_tls.attest_connection(
          attestation_pb2.AttestConnectionRequest(
              required_verifier_type=[
                  attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
              ]
          ),
          ssl_obj=self.ssl_obj,
      )

  def test_server_only_request_is_accepted_when_mutual_is_optional(self):
    attested_tls = self._attested_tls()

    result = attested_tls.attest_connection(
        attestation_pb2.AttestConnectionRequest(
            required_verifier_type=[
                attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
            ],
            nonce=b"n" * 32,
        ),
        ssl_obj=self.ssl_obj,
    )

    self.assertFalse(result.response.mutual_attestation_complete)
    self.assertEqual(
        result.response.mode, attestation_pb2.ATTESTATION_MODE_SERVER_ONLY
    )
    # The server holds no client evidence in this mode, so nothing expires.
    self.assertEqual(result.expires_at, math.inf)
    self.client_validator.validate_proof.assert_not_called()

  def test_server_only_request_may_not_carry_a_client_proof(self):
    attested_tls = self._attested_tls()

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError,
        "client_attestation is valid only for mutual attestation.",
    ):
      attested_tls.attest_connection(
          attestation_pb2.AttestConnectionRequest(
              required_verifier_type=[
                  attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
              ],
              client_attestation=attestation_pb2.AttestationProof(),
          ),
          ssl_obj=self.ssl_obj,
      )

  def test_unknown_mode_is_rejected(self):
    attested_tls = self._attested_tls()

    with self.assertRaisesRegex(
        attestation_protocol.AttestationRequestError,
        "Unsupported attestation mode",
    ):
      attested_tls.attest_connection(
          _mutual_request(mode=99), ssl_obj=self.ssl_obj
      )

  def test_requiring_mutual_attestation_without_a_policy_is_rejected(self):
    with self.assertRaisesRegex(
        ValueError, "client_policy is required when mutual attestation"
    ):
      attestation.AttestedTLS(
          self.token_manager, require_mutual_attestation=True
      )

  @parameterized.named_parameters(
      ("bare", attestation_pb2.AttestationPolicy()),
      (
          "empty_submessages",
          attestation_pb2.AttestationPolicy(
              workload=attestation_pb2.WorkloadPolicy(),
              gce_instance=attestation_pb2.GceInstancePolicy(),
          ),
      ),
      (
          "zone_and_instance_name_only",
          attestation_pb2.AttestationPolicy(
              gce_instance=attestation_pb2.GceInstancePolicy(
                  zone="us-central1-a",
                  instance_name="shared-name",
              ),
          ),
      ),
  )
  def test_unpinned_client_policy_logs_a_warning(self, policy):
    with self.assertLogs(level="WARNING") as logs:
      self._attested_tls(client_policy=policy)

    self.assertTrue(
        any(
            "neither workload identity nor a GCE project_id or instance_id"
            in msg
            for msg in logs.output
        )
    )

  @parameterized.named_parameters(
      (
          "hw_model_unset",
          attestation_pb2.AttestationPolicy(
              gce_instance=attestation_pb2.GceInstancePolicy(
                  project_id="trusted"
              ),
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  require_debug_disabled=True
              ),
          ),
          "non-confidential VMs can satisfy the policy",
      ),
      (
          "confidential_space_unset",
          attestation_pb2.AttestationPolicy(
              hw_model=attestation_pb2.HARDWARE_MODEL_TDX,
              gce_instance=attestation_pb2.GceInstancePolicy(
                  project_id="trusted"
              ),
          ),
          "debug Confidential Space instances are admitted",
      ),
      (
          "debug_not_disabled",
          attestation_pb2.AttestationPolicy(
              hw_model=attestation_pb2.HARDWARE_MODEL_TDX,
              gce_instance=attestation_pb2.GceInstancePolicy(
                  project_id="trusted"
              ),
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  require_debug_disabled=False,
                  require_secboot=True,
              ),
          ),
          "debug Confidential Space instances are admitted",
      ),
  )
  def test_weak_platform_client_policy_logs_a_warning(
      self, policy, expected_substring
  ):
    with self.assertLogs(level="WARNING") as logs:
      self._attested_tls(client_policy=policy)

    self.assertLen(logs.output, 1)
    self.assertIn(expected_substring, logs.output[0])

  @parameterized.named_parameters(
      (
          "image_hash",
          attestation_pb2.AttestationPolicy(
              hw_model=attestation_pb2.HARDWARE_MODEL_TDX,
              workload=attestation_pb2.WorkloadPolicy(
                  image_hash="sha256:trusted"
              ),
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  require_debug_disabled=True
              ),
          ),
      ),
      (
          "signing_key_id",
          attestation_pb2.AttestationPolicy(
              hw_model=attestation_pb2.HARDWARE_MODEL_TDX,
              workload=attestation_pb2.WorkloadPolicy(
                  signing_key_id=(
                      "projects/p/locations/l/keyRings/r/cryptoKeys/k/"
                      "cryptoKeyVersions/1"
                  )
              ),
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  require_debug_disabled=True
              ),
          ),
      ),
      (
          "image_signatures",
          attestation_pb2.AttestationPolicy(
              hw_model=attestation_pb2.HARDWARE_MODEL_TDX,
              workload=attestation_pb2.WorkloadPolicy(
                  image_signatures=["ECDSA_P256_SHA256:trusted_key"]
              ),
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  require_debug_disabled=True
              ),
          ),
      ),
      (
          "project_id",
          attestation_pb2.AttestationPolicy(
              hw_model=attestation_pb2.HARDWARE_MODEL_TDX,
              gce_instance=attestation_pb2.GceInstancePolicy(
                  project_id="trusted"
              ),
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  require_debug_disabled=True
              ),
          ),
      ),
      (
          "instance_id",
          attestation_pb2.AttestationPolicy(
              hw_model=attestation_pb2.HARDWARE_MODEL_TDX,
              gce_instance=attestation_pb2.GceInstancePolicy(
                  instance_id="12345"
              ),
              confidential_space=attestation_pb2.ConfidentialSpacePolicy(
                  require_debug_disabled=True
              ),
          ),
      ),
      ("no_client_policy", None),
  )
  def test_pinned_or_absent_client_policy_logs_no_warning(self, policy):
    with self.assertNoLogs(level="WARNING"):
      self._attested_tls(client_policy=policy)

  def test_concurrent_cold_start_builds_the_validator_once(self):
    """A second cold-start mutual call waiting on the lock reuses the first."""
    constructing = threading.Event()
    unblock = threading.Event()
    second_waiting = threading.Event()
    factory_calls = 0

    def counting_factory(policy):
      nonlocal factory_calls
      factory_calls += 1
      return self._blocking_validator_factory(constructing, unblock, policy)

    class _CountingLock:

      def __init__(self):
        self._lock = threading.Lock()
        self._entry_lock = threading.Lock()
        self._entries = 0

      def __enter__(self):
        with self._entry_lock:
          self._entries += 1
          if self._entries == 2:
            second_waiting.set()
        self._lock.acquire()
        return self

      def __exit__(self, exc_type, exc_value, traceback):
        del exc_type, exc_value, traceback
        self._lock.release()

    attested_tls = self._attested_tls(
        attestation_validator_cls=counting_factory
    )
    attested_tls._validator_lock = _CountingLock()
    other_ssl_obj = mock.create_autospec(
        mutual_testlib.FakeTlsSession, instance=True
    )
    other_ssl_obj.export_keying_material.return_value = b"other-ekm"
    other_ssl_obj.version.return_value = "TLSv1.3"
    first_outcome = {}
    second_outcome = {}
    first_thread = threading.Thread(
        target=self._attest_into,
        args=(attested_tls, _mutual_request(), first_outcome),
    )
    second_thread = threading.Thread(
        target=self._attest_into,
        args=(attested_tls, _mutual_request(), second_outcome),
        kwargs={"ssl_obj": other_ssl_obj},
    )
    first_thread.start()
    second_started = False
    try:
      self.assertTrue(constructing.wait(timeout=10))
      second_thread.start()
      second_started = True
      self.assertTrue(second_waiting.wait(timeout=10))
    finally:
      unblock.set()
      first_thread.join(timeout=10)
      if second_started:
        second_thread.join(timeout=10)

    self.assertEqual(factory_calls, 1)
    self.assertIn("result", first_outcome)
    self.assertIn("result", second_outcome)

  def test_validator_construction_does_not_block_server_only_attestation(self):
    """Slow OIDC discovery on first mutual call must not stall server-only."""
    constructing = threading.Event()
    unblock = threading.Event()
    attested_tls = self._attested_tls(
        attestation_validator_cls=functools.partial(
            self._blocking_validator_factory, constructing, unblock
        )
    )
    mutual_outcome = {}
    mutual_thread = threading.Thread(
        target=self._attest_into,
        args=(attested_tls, _mutual_request(), mutual_outcome),
    )
    mutual_thread.start()
    try:
      self.assertTrue(constructing.wait(timeout=10))
      other_ssl_obj = mock.create_autospec(
          mutual_testlib.FakeTlsSession, instance=True
      )
      other_ssl_obj.export_keying_material.return_value = b"other-ekm"
      server_only_outcome = {}
      server_only_request = attestation_pb2.AttestConnectionRequest(
          required_verifier_type=[
              attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
          ],
          nonce=b"n" * 32,
      )
      server_only_thread = threading.Thread(
          target=self._attest_into,
          args=(attested_tls, server_only_request, server_only_outcome),
          kwargs={"ssl_obj": other_ssl_obj},
      )
      server_only_thread.start()
      server_only_thread.join(timeout=2)
      self.assertFalse(server_only_thread.is_alive())
      self.assertIn("result", server_only_outcome)
    finally:
      unblock.set()
      mutual_thread.join(timeout=10)

    self.assertIn("result", mutual_outcome)

  def test_client_validator_is_built_once_and_reused(self):
    """OIDC discovery is expensive; it must not run per connection."""
    factory = mock.create_autospec(
        validator.AttestationValidator, return_value=self.client_validator
    )
    attested_tls = self._attested_tls(attestation_validator_cls=factory)

    attested_tls.attest_connection(_mutual_request(), ssl_obj=self.ssl_obj)
    other_ssl_obj = mock.create_autospec(
        mutual_testlib.FakeTlsSession, instance=True
    )
    other_ssl_obj.export_keying_material.return_value = b"other-ekm"
    other_ssl_obj.version.return_value = "TLSv1.3"
    attested_tls.attest_connection(_mutual_request(), ssl_obj=other_ssl_obj)

    factory.assert_called_once_with(self.policy)

  def test_client_validator_is_not_built_for_server_only_traffic(self):
    factory = mock.create_autospec(
        validator.AttestationValidator, return_value=self.client_validator
    )
    attested_tls = self._attested_tls(attestation_validator_cls=factory)

    attested_tls.attest_connection(
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
