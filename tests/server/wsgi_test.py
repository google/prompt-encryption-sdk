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

"""Tests for server.wsgi."""

import http
import json
import math
import ssl
import time
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token
from prompt_encryption_sdk.server import wsgi
from google.protobuf import json_format
from gunicorn import config as gunicorn_config
from gunicorn.http import wsgi as gunicorn_wsgi
import werkzeug.test


class PromptEncryptionWSGIMiddlewareTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_attested_tls = mock.create_autospec(
        attestation.AttestedTLS, instance=True
    )

    def simple_app(unused_environ, unused_start_response):
      pass

    self.app = mock.create_autospec(simple_app)
    self.mw = wsgi.PromptEncryptionWSGIMiddleware(
        self.app, self.mock_attested_tls
    )
    self.client = werkzeug.test.Client(self.mw)

  def test_call_other_path_attested(self):
    def simple_app(_, start_response):
      start_response("200 OK", [("Content-Type", "text/plain")])
      return [b"ok"]

    self.app.side_effect = simple_app
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    self.mw._attested_sockets[mock_socket] = math.inf
    environ_overrides = {"prompt_encryption.socket": mock_socket}

    response = self.client.get("/other", environ_overrides=environ_overrides)
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.data, b"ok")
    self.app.assert_called_once()

  def test_call_other_path_unattested(self):
    def simple_app(_, start_response):
      start_response("200 OK", [("Content-Type", "text/plain")])
      return [b"ok"]

    self.app.side_effect = simple_app
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    environ_overrides = {"prompt_encryption.socket": mock_socket}

    response = self.client.get("/other", environ_overrides=environ_overrides)
    self.assertEqual(response.status_code, 401)
    self.assertEqual(
        json.loads(response.data),
        {"error": "Unauthorized: Connection must be attested first."},
    )
    self.assertIsNone(response.headers.get("Connection"))
    self.app.assert_not_called()

  def test_call_other_path_missing_socket(self):
    def simple_app(_, start_response):
      start_response("200 OK", [("Content-Type", "text/plain")])
      return [b"ok"]

    self.app.side_effect = simple_app

    response = self.client.get("/other")
    self.assertEqual(response.status_code, 401)
    self.assertEqual(
        json.loads(response.data),
        {"error": "Unauthorized: Connection must be attested first."},
    )
    self.app.assert_not_called()

  def test_handle_attestation_success(self):
    request_proto = attestation_pb2.AttestConnectionRequest()
    request_json = json_format.MessageToJson(request_proto)

    response_proto = attestation_pb2.AttestConnectionResponse(
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=b"test_public_key"
        )
    )
    self.mock_attested_tls.attest_connection.return_value = (
        attestation.AttestationResult(response=response_proto)
    )

    # Mock the socket injection in environ
    environ_overrides = {
        "prompt_encryption.socket": mock.create_autospec(
            ssl.SSLSocket, instance=True
        )
    }

    response = self.client.post(
        "/_attest-connection",
        json=json.loads(request_json),
        environ_overrides=environ_overrides,
    )

    self.mock_attested_tls.attest_connection.assert_called_once_with(
        request_proto,
        ssl_obj=environ_overrides["prompt_encryption.socket"],
    )
    self.assertEqual(response.status_code, http.HTTPStatus.OK)

    response_proto_parsed = json_format.Parse(
        response.data, attestation_pb2.AttestConnectionResponse()
    )
    self.assertEqual(response_proto_parsed, response_proto)
    self.assertIn(
        environ_overrides["prompt_encryption.socket"],
        self.mw._attested_sockets,
    )

  def test_replayed_attestation_drops_the_connection(self):
    """A mutually attested session may not attest again; it is dropped."""
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    self.mw._attested_sockets[mock_socket] = math.inf
    self.mock_attested_tls.attest_connection.side_effect = (
        attestation_protocol.AttestationReplayError("already attested")
    )

    response = self.client.post(
        "/_attest-connection",
        json={},
        environ_overrides={"prompt_encryption.socket": mock_socket},
    )

    with self.subTest("Forbidden"):
      self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
      self.assertIn(b"already attested", response.data)
    with self.subTest("ConnectionClosed"):
      self.assertEqual(response.headers.get("Connection"), "close")
    with self.subTest("AuthorizationRevoked"):
      self.assertNotIn(mock_socket, self.mw._attested_sockets)

  def test_application_traffic_is_refused_after_a_replay_drop(self):
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    self.mw._attested_sockets[mock_socket] = math.inf
    self.mock_attested_tls.attest_connection.side_effect = (
        attestation_protocol.AttestationReplayError("already attested")
    )
    environ_overrides = {"prompt_encryption.socket": mock_socket}
    self.client.post(
        "/_attest-connection", json={}, environ_overrides=environ_overrides
    )

    response = self.client.get("/infer", environ_overrides=environ_overrides)

    self.assertEqual(response.status_code, http.HTTPStatus.UNAUTHORIZED)
    self.app.assert_not_called()

  def _attest(self, mock_socket, expires_at):
    """Runs a successful attestation that yields the given expiry."""
    self.mock_attested_tls.attest_connection.return_value = (
        attestation.AttestationResult(
            response=attestation_pb2.AttestConnectionResponse(),
            expires_at=expires_at,
        )
    )
    return self.client.post(
        "/_attest-connection",
        json={},
        environ_overrides={"prompt_encryption.socket": mock_socket},
    )

  def test_a_mutual_session_inherits_the_client_token_expiry(self):
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    expiry = time.time() + 300

    self._attest(mock_socket, expiry)

    self.assertEqual(self.mw._attested_sockets[mock_socket], expiry)

  def test_mutual_attestation_replaces_server_only_infinite_expiry(self):
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    self._attest(mock_socket, math.inf)
    expiry = time.time() + 300

    self._attest(mock_socket, expiry)

    self.assertEqual(self.mw._attested_sockets[mock_socket], expiry)

  def test_traffic_is_served_before_the_attestation_expires(self):
    def simple_app(_, start_response):
      start_response("200 OK", [("Content-Type", "text/plain")])
      return [b"ok"]

    self.app.side_effect = simple_app
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    self._attest(mock_socket, time.time() + 300)

    response = self.client.get(
        "/infer",
        environ_overrides={"prompt_encryption.socket": mock_socket},
    )

    self.assertEqual(response.status_code, http.HTTPStatus.OK)
    self.app.assert_called_once()

  def test_traffic_is_refused_once_the_attestation_expires(self):
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    expiry = 1_700_000_000.0
    self._attest(mock_socket, expiry)

    # Exactly at the expiry time counts as expired.
    with mock.patch.object(
        wsgi.time, "time", autospec=True, return_value=expiry
    ):
      response = self.client.get(
          "/infer",
          environ_overrides={"prompt_encryption.socket": mock_socket},
      )

    with self.subTest("Unauthorized"):
      self.assertEqual(response.status_code, http.HTTPStatus.UNAUTHORIZED)
      self.assertEqual(
          json.loads(response.data),
          {"error": "Unauthorized: Attestation expired."},
      )
      self.app.assert_not_called()
    with self.subTest("ConnectionClosed"):
      self.assertEqual(response.headers.get("Connection"), "close")
    with self.subTest("AuthorizationDropped"):
      self.assertNotIn(mock_socket, self.mw._attested_sockets)

  def test_a_request_admitted_before_expiry_runs_to_completion(self):
    """Expiry is checked at request entry, so nothing is cut off mid-flight."""
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    expiry = 1_700_000_000.0
    self._attest(mock_socket, expiry)

    with mock.patch.object(
        wsgi.time, "time", autospec=True, return_value=expiry - 1
    ) as mock_time:

      def slow_app(_, start_response):
        # The clock passes the expiry while the request runs.
        mock_time.return_value = expiry + 1
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

      self.app.side_effect = slow_app
      response = self.client.get(
          "/infer",
          environ_overrides={"prompt_encryption.socket": mock_socket},
      )

    self.assertEqual(response.status_code, http.HTTPStatus.OK)
    self.assertIn(mock_socket, self.mw._attested_sockets)

  def test_gunicorn_closes_the_connection_when_the_attestation_expires(self):
    """gunicorn drops a Connection header, so the middleware forces the close."""
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    self._attest(mock_socket, 1_700_000_000.0)
    request = mock.Mock(version=(1, 1), method="GET")
    request.should_close.return_value = False
    gunicorn_response = gunicorn_wsgi.Response(
        request, mock.Mock(), gunicorn_config.Config()
    )

    with mock.patch.object(
        wsgi.time, "time", autospec=True, return_value=1_700_000_001.0
    ):
      self.mw(
          {
              "PATH_INFO": "/infer",
              "prompt_encryption.socket": mock_socket,
              wsgi._FORCE_CLOSE_KEY: gunicorn_response.force_close,
          },
          gunicorn_response.start_response,
      )

    self.assertEqual(gunicorn_response.status_code, 401)
    self.assertTrue(gunicorn_response.should_close())
    self.assertIn("Connection: close\r\n", gunicorn_response.default_headers())

  def test_patched_gunicorn_create_exposes_force_close(self):
    request = mock.Mock(spec=["confidential_socket"])
    gunicorn_response = mock.Mock(spec=["force_close"])
    with mock.patch.object(
        wsgi, "_original_create", return_value=(gunicorn_response, {})
    ):
      _, environ = wsgi._patched_wsgi_create(request)

    self.assertIs(
        environ["prompt_encryption.socket"], request.confidential_socket
    )
    self.assertIs(environ[wsgi._FORCE_CLOSE_KEY], gunicorn_response.force_close)

  @parameterized.named_parameters(
      dict(
          testcase_name="missing_socket",
          json_body={},
          environ_overrides=None,
          mock_error=None,
          expected_status=http.HTTPStatus.INTERNAL_SERVER_ERROR,
          expected_error="Internal server error.",
          forbidden_substring=b"TLS Socket",
      ),
      dict(
          testcase_name="parse_error",
          json_body={"requiredVerifierType": 1},
          environ_overrides=None,
          mock_error=None,
          expected_status=http.HTTPStatus.BAD_REQUEST,
          expected_error="Invalid request",
          forbidden_substring=b"ParseError",
      ),
      dict(
          testcase_name="malformed_json_list",
          json_body=[],
          environ_overrides=None,
          mock_error=None,
          expected_status=http.HTTPStatus.BAD_REQUEST,
          expected_error="Invalid request",
          forbidden_substring=b"Malformed",
      ),
      dict(
          testcase_name="internal_error",
          json_body={},
          environ_overrides={"prompt_encryption.socket": "mock_socket"},
          mock_error=ValueError("secret-value-error"),
          expected_status=http.HTTPStatus.INTERNAL_SERVER_ERROR,
          expected_error="Internal server error.",
          forbidden_substring=b"secret-value-error",
      ),
      dict(
          testcase_name="runtime_error",
          json_body={},
          environ_overrides={"prompt_encryption.socket": "mock_socket"},
          mock_error=RuntimeError("secret-runtime-fault"),
          expected_status=http.HTTPStatus.INTERNAL_SERVER_ERROR,
          expected_error="Internal server error.",
          forbidden_substring=b"secret-runtime-fault",
      ),
      dict(
          testcase_name="permission_error",
          json_body={},
          environ_overrides={"prompt_encryption.socket": "mock_socket"},
          mock_error=PermissionError("secret-token-path"),
          expected_status=http.HTTPStatus.INTERNAL_SERVER_ERROR,
          expected_error="Internal server error.",
          forbidden_substring=b"secret-token-path",
      ),
      dict(
          testcase_name="policy_violation_error",
          json_body={},
          environ_overrides={"prompt_encryption.socket": "mock_socket"},
          mock_error=exceptions.PolicyViolationError("untrusted client"),
          expected_status=http.HTTPStatus.FORBIDDEN,
          expected_error="Client attestation failed.",
          forbidden_substring=b"untrusted client",
      ),
      dict(
          testcase_name="attestation_verification_error",
          json_body={},
          environ_overrides={"prompt_encryption.socket": "mock_socket"},
          mock_error=exceptions.AttestationVerificationError("bad signature"),
          expected_status=http.HTTPStatus.FORBIDDEN,
          expected_error="Client attestation failed.",
          forbidden_substring=b"bad signature",
      ),
  )
  def test_handle_attestation_errors(
      self,
      json_body,
      environ_overrides,
      mock_error,
      expected_status,
      expected_error,
      forbidden_substring,
  ):
    if mock_error:
      self.mock_attested_tls.attest_connection.side_effect = mock_error

    kwargs = {"json": json_body}
    if environ_overrides:
      # If using a mock, instantiate it here instead of in the decorator
      if environ_overrides.get("prompt_encryption.socket") == "mock_socket":
        environ_overrides["prompt_encryption.socket"] = mock.create_autospec(
            ssl.SSLSocket, instance=True
        )
      kwargs["environ_overrides"] = environ_overrides

    response = self.client.post("/_attest-connection", **kwargs)

    self.assertEqual(response.status_code, expected_status)
    self.assertEqual(json.loads(response.data), {"error": expected_error})
    self.assertNotIn(forbidden_substring, response.data)
    self.assertIsNone(response.headers.get("Connection"))

  def test_invalid_utf8_body_returns_bad_request(self):
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)

    response = self.client.post(
        "/_attest-connection",
        data=b"\x80abc",
        content_type="application/json",
        environ_overrides={"prompt_encryption.socket": mock_socket},
    )

    self.mock_attested_tls.attest_connection.assert_not_called()
    self.assertEqual(response.status_code, http.HTTPStatus.BAD_REQUEST)
    self.assertEqual(json.loads(response.data), {"error": "Invalid request"})
    self.assertNotIn(b"UnicodeDecodeError", response.data)
    self.assertIsNone(response.headers.get("Connection"))

  def test_server_only_request_to_require_mutual_server_returns_sanitized_400(
      self,
  ):
    attested_tls = attestation.AttestedTLS(
        mock.create_autospec(token.TokenManager, instance=True),
        client_policy=attestation_pb2.AttestationPolicy(
            gce_instance=attestation_pb2.GceInstancePolicy(project_id="trusted")
        ),
        require_mutual_attestation=True,
    )
    mw = wsgi.PromptEncryptionWSGIMiddleware(self.app, attested_tls)
    client = werkzeug.test.Client(mw)
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    request_proto = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
        nonce=b"n" * 32,
    )

    with self.assertLogs(level="WARNING") as logs:
      response = client.post(
          "/_attest-connection",
          data=json_format.MessageToJson(request_proto),
          content_type="application/json",
          environ_overrides={"prompt_encryption.socket": mock_socket},
      )

    self.assertEqual(response.status_code, http.HTTPStatus.BAD_REQUEST)
    self.assertEqual(
        json.loads(response.data), {"error": "Invalid attestation request."}
    )
    self.assertNotIn(b"requires mutual attestation", response.data)
    self.assertIsNone(response.headers.get("Connection"))
    self.assertNotIn(mock_socket, mw._attested_sockets)
    self.assertTrue(
        any(
            "This server requires mutual attestation." in line
            for line in logs.output
        )
    )

  def test_internal_error_logs_detail_without_leaking_it(self):
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)
    self.mock_attested_tls.attest_connection.side_effect = RuntimeError(
        "secret-runtime-fault"
    )

    with self.assertLogs(level="ERROR") as logs:
      response = self.client.post(
          "/_attest-connection",
          json={},
          environ_overrides={"prompt_encryption.socket": mock_socket},
      )

    self.assertEqual(
        response.status_code, http.HTTPStatus.INTERNAL_SERVER_ERROR
    )
    self.assertEqual(
        json.loads(response.data), {"error": "Internal server error."}
    )
    self.assertNotIn(b"secret-runtime-fault", response.data)
    self.assertTrue(any("secret-runtime-fault" in line for line in logs.output))

  @parameterized.named_parameters(
      dict(
          testcase_name="policy_violation_error",
          error_cls=exceptions.PolicyViolationError,
          secret=b"secret-policy-detail",
      ),
      dict(
          testcase_name="attestation_verification_error",
          error_cls=exceptions.AttestationVerificationError,
          secret=b"secret-verify-detail",
      ),
  )
  def test_client_attestation_failure_logs_detail_without_leaking_it(
      self, error_cls, secret
  ):
    mock_socket = mock.create_autospec(ssl.SSLSocket, instance=True)

    def raise_chained(*unused_args, **unused_kwargs):
      raise error_cls(secret.decode("utf-8")) from RuntimeError(
          "jwks-cause-detail"
      )

    self.mock_attested_tls.attest_connection.side_effect = raise_chained

    with self.assertLogs(level="WARNING") as logs:
      response = self.client.post(
          "/_attest-connection",
          json={},
          environ_overrides={"prompt_encryption.socket": mock_socket},
      )

    self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
    self.assertEqual(
        json.loads(response.data), {"error": "Client attestation failed."}
    )
    self.assertNotIn(secret, response.data)
    self.assertNotIn(b"jwks-cause-detail", response.data)
    self.assertIsNone(response.headers.get("Connection"))
    self.assertNotIn(mock_socket, self.mw._attested_sockets)
    self.assertTrue(any(secret.decode("utf-8") in line for line in logs.output))
    self.assertTrue(any("jwks-cause-detail" in line for line in logs.output))

  def test_run_gunicorn_app(self):
    mock_app = mock.Mock()
    mock_key_manager = mock.create_autospec(keys.KeyManager, instance=True)
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_attested_tls_cls = mock.create_autospec(
        attestation.AttestedTLS, instance=False
    )
    mock_standalone_app_cls = mock.create_autospec(
        wsgi._StandaloneApplication, instance=False
    )
    mock_standalone_app_instance = mock_standalone_app_cls.return_value

    wsgi.run_gunicorn_app(
        mock_app,
        key_manager=mock_key_manager,
        token_manager=mock_token_manager,
        host="localhost",
        port=9000,
        attested_tls_cls=mock_attested_tls_cls,
        standalone_app_cls=mock_standalone_app_cls,
    )

    with self.subTest("AttestedTLS"):
      mock_attested_tls_cls.assert_called_once_with(
          mock_token_manager,
          client_policy=None,
          require_mutual_attestation=False,
      )

    with self.subTest("StandaloneApplication"):
      mock_standalone_app_cls.assert_called_once_with(
          mock.ANY,
          {
              "bind": "localhost:9000",
              "workers": 1,
              "worker_class": wsgi.PromptEncryptionGunicornWorker,
              "certfile": None,
              "keyfile": None,
              "accesslog": "-",
              "errorlog": "-",
          },
      )
      mock_standalone_app_instance.run.assert_called_once()

  def test_run_gunicorn_app_rejects_invalid_mutual_settings_before_start(
      self,
  ):
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_standalone_app_cls = mock.create_autospec(
        wsgi._StandaloneApplication, instance=False
    )

    with self.assertRaisesRegex(ValueError, "client_policy is required"):
      wsgi.run_gunicorn_app(
          mock.Mock(),
          key_manager=mock.create_autospec(keys.KeyManager, instance=True),
          token_manager=mock_token_manager,
          require_mutual_attestation=True,
          standalone_app_cls=mock_standalone_app_cls,
      )

    mock_token_manager.__enter__.assert_not_called()
    mock_standalone_app_cls.assert_not_called()

  def test_run_gunicorn_app_forwards_the_mutual_configuration(self):
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    mock_attested_tls_cls = mock.create_autospec(
        attestation.AttestedTLS, instance=False
    )
    client_policy = attestation_pb2.AttestationPolicy(expected_audience="aud")

    wsgi.run_gunicorn_app(
        mock.Mock(),
        token_manager=mock_token_manager,
        client_policy=client_policy,
        require_mutual_attestation=True,
        attested_tls_cls=mock_attested_tls_cls,
        standalone_app_cls=mock.create_autospec(
            wsgi._StandaloneApplication, instance=False
        ),
    )

    mock_attested_tls_cls.assert_called_once_with(
        mock_token_manager,
        client_policy=client_policy,
        require_mutual_attestation=True,
    )

  def test_middleware_repr(self):
    self.assertEqual(
        repr(self.mw),
        f"<PromptEncryptionWSGIMiddleware app={self.app!r}>",
    )

  def test_patched_wsgi_create(self):
    mock_req = mock.Mock()
    mock_req.confidential_socket = "socket_obj"
    mock_environ = {}

    with mock.patch.object(
        wsgi, "_original_create", return_value=("resp", mock_environ)
    ) as mock_original:
      resp, environ = wsgi._patched_wsgi_create(mock_req)

    self.assertEqual(resp, "resp")
    self.assertEqual(environ["prompt_encryption.socket"], "socket_obj")
    mock_original.assert_called_once_with(mock_req)

  def test_patched_wsgi_create_no_socket(self):
    # spec=[] ensures no extra attributes like confidential_socket exist
    mock_req = mock.Mock(spec=[])
    mock_environ = {}

    with mock.patch.object(
        wsgi, "_original_create", return_value=("resp", mock_environ)
    ) as mock_original:
      resp, environ = wsgi._patched_wsgi_create(mock_req)

    self.assertEqual(resp, "resp")
    self.assertNotIn("prompt_encryption.socket", environ)
    mock_original.assert_called_once_with(mock_req)

  def _create_worker(self):
    # Mock arguments for Worker.__init__
    mock_age = mock.Mock()
    mock_ppid = mock.Mock()
    mock_sockets = mock.Mock()
    mock_app_inst = mock.Mock()
    mock_timeout = mock.Mock()
    mock_cfg = mock.Mock()
    mock_cfg.max_requests = 0
    mock_cfg.umask = 0
    mock_cfg.worker_tmp_dir = None
    mock_cfg.uid = 0
    mock_cfg.gid = 0
    mock_log = mock.Mock()

    # Create the worker instance
    with mock.patch("os.chown"):
      worker = wsgi.PromptEncryptionGunicornWorker(
          mock_age,
          mock_ppid,
          mock_sockets,
          mock_app_inst,
          mock_timeout,
          mock_cfg,
          mock_log,
      )
    return worker

  def test_worker_repr(self):
    worker = self._create_worker()
    # Manually set pid since it's set in __init__ but we want to be sure
    worker.pid = 12345

    self.assertEqual(repr(worker), "<PromptEncryptionGunicornWorker pid=12345>")

  def test_worker_handle_request(self):
    worker = self._create_worker()
    mock_req = mock.Mock()
    mock_client = mock.Mock()

    with mock.patch(
        "gunicorn.workers.sync.SyncWorker.handle_request"
    ) as mock_super_handle:
      worker.handle_request("listener", mock_req, mock_client, "addr")

    self.assertEqual(mock_req.confidential_socket, mock_client)
    mock_super_handle.assert_called_once_with(
        "listener", mock_req, mock_client, "addr"
    )

  def test_worker_handle_request_no_client(self):
    worker = self._create_worker()
    mock_req = mock.Mock(spec=[])
    mock_client = None

    with mock.patch(
        "gunicorn.workers.sync.SyncWorker.handle_request"
    ) as mock_super_handle:
      worker.handle_request("listener", mock_req, mock_client, "addr")

    self.assertFalse(hasattr(mock_req, "confidential_socket"))
    mock_super_handle.assert_called_once_with(
        "listener", mock_req, mock_client, "addr"
    )

  def test_parse_request_error_handling(self):
    # Force _parse_request to hit the except block
    with mock.patch.object(
        wsgi.werkzeug.wrappers,
        "Request",
        side_effect=Exception("Boom"),
    ):
      environ_overrides = {
          "prompt_encryption.socket": mock.create_autospec(
              ssl.SSLSocket, instance=True
          )
      }
      self.mock_attested_tls.attest_connection.return_value = (
          attestation.AttestationResult(
              response=attestation_pb2.AttestConnectionResponse()
          )
      )

      response = self.client.post(
          "/_attest-connection", environ_overrides=environ_overrides
      )

      self.assertEqual(response.status_code, http.HTTPStatus.OK)
      # Verify attest_connection called with empty request (result of fallback)
      args, _ = self.mock_attested_tls.attest_connection.call_args
      self.assertEqual(args[0], attestation_pb2.AttestConnectionRequest())


class StandaloneApplicationTest(absltest.TestCase):

  def test_load_and_config(self):
    app = mock.Mock()
    options = {"bind": "1.2.3.4:5678"}

    # Mock BaseApplication.__init__ to verify load_config separately and avoid side effects
    with mock.patch(
        "gunicorn.app.base.BaseApplication.__init__", return_value=None
    ):
      sa = wsgi._StandaloneApplication(app, options)
      # Manually set attributes normally set by __init__
      sa.application = app
      sa.options = options
      sa.cfg = mock.Mock()
      sa.cfg.settings = {"bind": None}

      # Test load_config
      sa.load_config()
      sa.cfg.set.assert_called_with("bind", "1.2.3.4:5678")

      # Test load
      self.assertEqual(sa.load(), app)


if __name__ == "__main__":
  absltest.main()
