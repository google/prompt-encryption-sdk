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

import datetime
import json
import socket
import ssl
import time
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import connection
from prompt_encryption_sdk.client import constants
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.ekm import exporter as ekm_exporter
from prompt_encryption_sdk.proto import attestation_pb2
from google.protobuf import json_format
import urllib3
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool


class AttestedHTTPSConnectionTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.host = "example.com"
    self.port = 443
    self.mock_policy = mock.create_autospec(attestation_pb2.AttestationPolicy)

    # Instantiate the connection
    self.conn = connection.AttestedHTTPSConnection(
        host=self.host,
        port=self.port,
        policy=self.mock_policy,
        revalidation_timeout=datetime.timedelta(seconds=100),
    )

    # Mock the underlying socket
    self.conn.sock = mock.create_autospec(ssl.SSLSocket, instance=True)

  @mock.patch.object(HTTPSConnection, "connect", autospec=True)
  def test_connect_success(self, mock_super_connect):
    """Tests that connect establishes TLS then performs attestation."""
    # Setup mocks for the handshake
    with mock.patch.object(
        self.conn, "_perform_attestation_handshake"
    ) as mock_handshake:
      self.conn.connect()

      # 1. Verify Standard TLS connect was called
      mock_super_connect.assert_called_once_with(self.conn)
      # 2. Verify Handshake was triggered
      mock_handshake.assert_called_once()
      # 3. Verify state update
      self.assertTrue(self.conn.is_attested)

  @mock.patch.object(HTTPSConnection, "connect", autospec=True)
  def test_connect_closes_socket_on_handshake_failure(self, mock_super_connect):
    """Tests that the socket is closed if attestation fails."""
    with (
        mock.patch.object(self.conn, "close", autospec=True) as mock_close,
        mock.patch.object(
            self.conn,
            "_perform_attestation_handshake",
            side_effect=ValueError("Handshake failed"),
        ),
    ):
      with self.assertRaisesRegex(ValueError, "Handshake failed"):
        self.conn.connect()

      # Ensure socket cleanup happens on failure
      mock_close.assert_called_once()
      self.assertFalse(self.conn.is_attested)

  def test_should_revalidate_logic(self):
    """Tests the time-based revalidation logic."""
    with self.subTest("Initial state (0.0)"):
      self.conn._last_attestation_time = 0.0
      self.assertFalse(self.conn._should_revalidate())

    with self.subTest("Fresh session"):
      self.conn._last_attestation_time = time.time()
      self.assertFalse(self.conn._should_revalidate())

    with self.subTest("Expired session"):
      self.conn._last_attestation_time = time.time() - 200  # Timeout is 100
      self.assertTrue(self.conn._should_revalidate())

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_request_triggers_revalidation(self, mock_super_request):
    """Tests that request() calls revalidate_session when timeout is exceeded."""
    self.conn.is_attested = True
    self.conn._last_attestation_time = time.time() - 200  # Expired

    with mock.patch.object(self.conn, "revalidate_session") as mock_reval:
      self.conn.request("GET", "/api/data")

      mock_reval.assert_called_once()
      mock_super_request.assert_called_once()

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_request_does_not_trigger_revalidation_on_fresh_session(
      self, mock_super_request
  ):
    """Tests that request() doesn't revalidate a fresh session."""
    self.conn.is_attested = True
    self.conn._last_attestation_time = time.time()  # Fresh

    with mock.patch.object(self.conn, "revalidate_session") as mock_reval:
      self.conn.request("GET", "/api/data")

      mock_reval.assert_not_called()
      mock_super_request.assert_called_once()

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_request_does_not_trigger_revalidation_if_not_attested(
      self, mock_super_request
  ):
    """Tests that request() doesn't revalidate if connection is not attested."""
    self.conn.is_attested = False
    self.conn._last_attestation_time = time.time() - 200  # Expired

    with mock.patch.object(self.conn, "revalidate_session") as mock_reval:
      self.conn.request("GET", "/api/data")

      mock_reval.assert_not_called()
      mock_super_request.assert_called_once()

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_request_failures_during_revalidation_close_socket(
      self, mock_super_request
  ):
    """Tests that revalidation failure closes socket and raises specific error."""
    self.conn.is_attested = True
    self.conn._last_attestation_time = time.time() - 200

    with (
        mock.patch.object(self.conn, "close", autospec=True) as mock_close,
        mock.patch.object(
            self.conn,
            "revalidate_session",
            side_effect=Exception("internal error"),
        ),
    ):
      with self.assertRaisesRegex(
          exceptions.PromptEncryptionError, "Session revalidation failed"
      ) as cm:
        self.conn.request("GET", "/api/data")
      self.assertEqual(str(cm.exception.__cause__), "internal error")

      mock_close.assert_called_once()
      # Super request should NOT be called if validation fails
      mock_super_request.assert_not_called()

  def test_revalidate_session_raises_if_no_socket(self):
    """Tests check for closed socket before revalidation."""
    self.conn.sock = None
    with self.assertRaisesRegex(
        exceptions.PromptEncryptionError, "Socket is closed"
    ):
      self.conn.revalidate_session()

  def test_revalidate_session_wraps_errors(self):
    """Tests that revalidation wraps underlying errors into AttestationVerificationError."""
    with mock.patch.object(
        self.conn,
        "_perform_attestation_handshake",
        side_effect=socket.error("network_err"),
    ):
      with mock.patch.object(self.conn, "close", autospec=True) as mock_close:
        with self.assertRaisesRegex(
            exceptions.AttestationVerificationError, "Revalidation failed"
        ) as cm:
          self.conn.revalidate_session()
        self.assertEqual(str(cm.exception.__cause__), "network_err")

        mock_close.assert_called_once()

  # --- Handshake Logic Tests ---

  @parameterized.named_parameters(
      (
          "protobuf_response",
          "application/x-protobuf",
          attestation_pb2.AttestConnectionResponse().SerializeToString(),
      ),
      (
          "json_response",
          "application/json",
          json.dumps({"evidence": []}).encode(),
      ),
  )
  @mock.patch.object(connection.secrets, "token_bytes", autospec=True)
  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  @mock.patch.object(ekm_exporter, "export_keying_material", autospec=True)
  @mock.patch.object(validator, "AttestationValidator", autospec=True)
  def test_perform_attestation_handshake_flow(
      self,
      content_type,
      response_body,
      mock_validator_cls,
      mock_export_ekm,
      mock_super_request,
      mock_token_bytes,
  ):
    """Tests the full handshake: Request -> Response -> EKM -> Validate."""
    # 1. Mock HTTP Response
    mock_response = mock.create_autospec(urllib3.HTTPResponse, instance=True)
    mock_response.status = 200
    mock_response.headers = {"Content-Type": content_type}
    mock_response.data = response_body
    self.conn.getresponse = mock.MagicMock(return_value=mock_response)
    mock_response.__enter__.return_value = mock_response

    # Mock secrets.token_bytes to ensure deterministic context
    fixed_random_bytes = b"deterministic_random_context"
    mock_token_bytes.return_value = fixed_random_bytes

    # 2. Mock EKM and Validator
    self.conn._ekm_exporter_fn = mock_export_ekm
    self.conn._attestation_validator_cls = mock_validator_cls
    mock_export_ekm.return_value = b"fake_ekm"
    mock_validator_inst = mock_validator_cls.return_value
    mock_validator_inst.validate.return_value = None

    # Execute
    self.conn._perform_attestation_handshake()

    # Assertions
    # A. Check Request sent to Attestation Endpoint
    mock_super_request.assert_called_once_with(
        self.conn,
        "POST",
        constants.ATTESTATION_ENDPOINT,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, application/x-protobuf",
        },
        body=mock.ANY,
    )

    # B. Check Proto parsing/validation
    mock_export_ekm.assert_called_once_with(
        self.conn.sock,
        constants.EKM_LENGTH,
        constants.EKM_LABEL,
        context=fixed_random_bytes,
    )

    # Verify validate was called with a Proto object and the EKM
    mock_validator_inst.validate.assert_called_once_with(
        mock.ANY, b"fake_ekm"
    )

    # Verify timestamp updated
    self.assertNotEqual(self.conn._last_attestation_time, 0.0)

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_handshake_network_error_sending(self, mock_req):
    """Tests handling of socket errors during request sending."""
    mock_req.side_effect = socket.error("Network down")
    with self.assertRaisesRegex(
        exceptions.AttestationHandshakeError, "Network error"
    ):
      self.conn._perform_attestation_handshake()

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_handshake_bad_status_code(self, mock_req):
    """Tests handling of non-200 HTTP status."""
    mock_response = mock.create_autospec(urllib3.HTTPResponse, instance=True)
    mock_response.status = 500
    mock_response.data = b"Server Error"
    self.conn.getresponse = mock.MagicMock(return_value=mock_response)
    mock_response.__enter__.return_value = mock_response

    with self.assertRaisesRegex(
        exceptions.AttestationHandshakeError,
        "Connection error reading response",
    ):
      self.conn._perform_attestation_handshake()

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_handshake_read_error(self, mock_req):
    """Tests error handling when reading response body fails."""
    mock_response = mock.create_autospec(urllib3.HTTPResponse, instance=True)
    # Accessing .data raises an exception (simulating connection cut during read)
    type(mock_response).data = mock.PropertyMock(
        side_effect=Exception("Read timed out")
    )
    self.conn.getresponse = mock.MagicMock(return_value=mock_response)

    with self.assertRaisesRegex(
        exceptions.AttestationHandshakeError,
        "Connection error reading response",
    ):
      self.conn._perform_attestation_handshake()


class AttestedHTTPSConnectionPoolTest(absltest.TestCase):

  def test_new_conn_creates_attested_connection(self):
    """Tests that the pool factory creates AttestedHTTPSConnection with correct args."""
    policy = mock.create_autospec(
        attestation_pb2.AttestationPolicy, instance=True
    )
    pool = connection.AttestedHTTPSConnectionPool(
        host="example.com",
        port=443,
        policy=policy,
        revalidation_timeout=datetime.timedelta(seconds=500),
        cert_reqs="CERT_REQUIRED",
        ca_certs="/path/to/ca",
    )

    # Trigger connection creation
    conn = pool._new_conn()

    self.assertIsInstance(conn, connection.AttestedHTTPSConnection)
    self.assertEqual(conn.host, "example.com")
    self.assertEqual(conn._policy, policy)
    self.assertEqual(
        conn._revalidation_timeout, datetime.timedelta(seconds=500)
    )
    # Verify SSL kwargs passed through
    self.assertEqual(conn.ca_certs, "/path/to/ca")
    self.assertEqual(conn.cert_reqs, "CERT_REQUIRED")


class AttestedPoolManagerTest(absltest.TestCase):

  def test_new_pool_https_returns_attested_pool(self):
    """Tests that HTTPS requests generate an AttestedPool."""
    policy = mock.create_autospec(
        attestation_pb2.AttestationPolicy, instance=True
    )
    manager = connection.AttestedPoolManager(
        policy=policy, revalidation_timeout=datetime.timedelta(seconds=123)
    )

    pool = manager._new_pool("https", "example.com", 443)

    self.assertIsInstance(pool, connection.AttestedHTTPSConnectionPool)
    self.assertEqual(pool._policy, policy)
    self.assertEqual(
        pool._revalidation_timeout, datetime.timedelta(seconds=123)
    )

  def test_new_pool_http_returns_standard_pool(self):
    """Tests that HTTP requests fallback to standard pools (no attestation)."""
    manager = connection.AttestedPoolManager()

    pool = manager._new_pool("http", "example.com", 80)

    # Should NOT be Attested pool
    self.assertNotIsInstance(pool, connection.AttestedHTTPSConnectionPool)
    self.assertIsInstance(pool, HTTPConnectionPool)


class MutualAttestedHTTPSConnectionTest(parameterized.TestCase):
  """Covers the client half of the single-round-trip mutual exchange."""

  def setUp(self):
    super().setUp()
    self.prover = mock.MagicMock()
    self.client_proof = attestation_pb2.AttestationProof(
        session_signature=b"client-sig"
    )
    self.prover.create_proof.return_value = self.client_proof

    self.validator_cls = mock.MagicMock()
    self.validator_inst = self.validator_cls.return_value

    self.export_ekm = mock.MagicMock(return_value=b"session-ekm")

    self.conn = connection.AttestedHTTPSConnection(
        host="example.com",
        port=443,
        policy=attestation_pb2.AttestationPolicy(),
        mutual_attestation=True,
        attestation_prover=self.prover,
        ekm_exporter_fn=self.export_ekm,
        attestation_validator_cls=self.validator_cls,
    )

  def _stub_response(self, response: attestation_pb2.AttestConnectionResponse):
    mock_response = mock.create_autospec(urllib3.HTTPResponse, instance=True)
    mock_response.status = 200
    mock_response.headers = {"Content-Type": "application/x-protobuf"}
    mock_response.data = response.SerializeToString()
    self.conn.getresponse = mock.MagicMock(return_value=mock_response)
    return mock_response

  def _mutual_response(self, **overrides):
    fields = dict(
        protocol_version=(
            attestation_protocol.MUTUAL_ATTESTATION_PROTOCOL_VERSION
        ),
        mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
        mutual_attestation_complete=True,
    )
    fields.update(overrides)
    return attestation_pb2.AttestConnectionResponse(**fields)

  def test_requires_a_prover_when_mutual_attestation_is_enabled(self):
    with self.assertRaisesRegex(ValueError, "attestation_prover is required"):
      connection.AttestedHTTPSConnection(
          host="example.com", port=443, mutual_attestation=True
      )

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_one_round_trip_carries_the_client_proof(self, mock_super_request):
    self._stub_response(self._mutual_response())

    self.conn._perform_attestation_handshake()

    with self.subTest("EkmExportedWithoutContext"):
      self.export_ekm.assert_called_once_with(
          self.conn.sock, constants.EKM_LENGTH, constants.EKM_LABEL
      )
    with self.subTest("ClientProvesItselfAsTheClientRole"):
      self.prover.create_proof.assert_called_once_with(
          b"session-ekm",
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )
    with self.subTest("ExactlyOneFlight"):
      mock_super_request.assert_called_once()
    with self.subTest("RequestCarriesTheProofAndNoNonce"):
      sent = json_format.Parse(
          mock_super_request.call_args.kwargs["body"],
          attestation_pb2.AttestConnectionRequest(),
      )
      self.assertEqual(sent.client_attestation, self.client_proof)
      self.assertEqual(sent.mode, attestation_pb2.ATTESTATION_MODE_MUTUAL)
      self.assertEqual(sent.protocol_version, 1)
      self.assertEmpty(sent.nonce)
    with self.subTest("ServerProofValidatedAgainstTheSameEkm"):
      self.validator_inst.validate.assert_called_once_with(
          mock.ANY,
          b"session-ekm",
          peer_role=attestation_pb2.ATTESTATION_PEER_ROLE_SERVER,
          mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )
    with self.subTest("ValidatorResourcesReleased"):
      self.validator_inst.close.assert_called_once()

  @parameterized.named_parameters(
      ("server_only_mode", {"mode": attestation_pb2.ATTESTATION_MODE_SERVER_ONLY}),
      ("wrong_protocol_version", {"protocol_version": 2}),
      ("not_complete", {"mutual_attestation_complete": False}),
  )
  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_downgrade_is_refused(self, overrides, mock_super_request):
    del mock_super_request
    self._stub_response(self._mutual_response(**overrides))

    with self.assertRaisesRegex(
        exceptions.AttestationHandshakeError, "refusing server-only downgrade"
    ):
      self.conn._perform_attestation_handshake()

    self.validator_inst.validate.assert_not_called()

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_invalid_server_proof_propagates(self, mock_super_request):
    del mock_super_request
    self._stub_response(self._mutual_response())
    self.validator_inst.validate.side_effect = (
        exceptions.AttestationVerificationError("bad server proof")
    )

    with self.assertRaises(exceptions.AttestationVerificationError):
      self.conn._perform_attestation_handshake()

  def test_mutual_sessions_are_never_revalidated(self):
    self.conn.is_attested = True
    self.conn._last_attestation_time = time.time() - 10_000

    self.assertFalse(self.conn._should_revalidate())

  @mock.patch.object(HTTPSConnection, "request", autospec=True)
  def test_request_does_not_revalidate_a_mutual_session(
      self, mock_super_request
  ):
    self.conn.is_attested = True
    self.conn._last_attestation_time = time.time() - 10_000

    with mock.patch.object(self.conn, "revalidate_session") as mock_reval:
      self.conn.request("GET", "/infer")

    mock_reval.assert_not_called()
    mock_super_request.assert_called_once()

  def test_explicit_revalidation_is_refused(self):
    with self.assertRaisesRegex(
        exceptions.PromptEncryptionError, "cannot be revalidated"
    ):
      self.conn.revalidate_session()


if __name__ == "__main__":
  absltest.main()
