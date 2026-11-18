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

"""Tests for server.asgi."""

import asyncio
import http
import json
import math
import time
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import asgi
from prompt_encryption_sdk.server import attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token
from google.protobuf import json_format
import uvicorn


class MiddlewareTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_attested_tls = mock.create_autospec(
        attestation.AttestedTLS, instance=True
    )
    self.app = mock.AsyncMock()
    self.mw = asgi.PromptEncryptionASGIMiddleware(
        self.app, self.mock_attested_tls
    )
    self.send = mock.AsyncMock()
    self.ssl_obj = mock.MagicMock()

  def _assert_error_response(
      self, expected_status: int, expected_error: str
  ) -> bytes:
    self.send.assert_has_calls([
        mock.call({
            "type": "http.response.start",
            "status": expected_status,
            "headers": mock.ANY,
        }),
        mock.call({"type": "http.response.body", "body": mock.ANY}),
    ])
    _, response_body_call = self.send.call_args_list
    (response_body_arg,) = response_body_call.args
    self.assertEqual(
        json.loads(response_body_arg["body"]), {"error": expected_error}
    )
    return response_body_arg["body"]

  def test_lifespan_scope_passes_through_to_app(self):
    scope = {"type": "lifespan"}
    receive = mock.AsyncMock()

    asyncio.run(self.mw(scope, receive, self.send))

    self.app.assert_called_once_with(scope, receive, self.send)
    self.send.assert_not_called()

  def test_websocket_scope_is_closed_without_calling_app(self):
    scope = {"type": "websocket", "path": "/ws"}
    receive = mock.AsyncMock(return_value={"type": "websocket.connect"})

    asyncio.run(self.mw(scope, receive, self.send))

    receive.assert_awaited_once()
    self.send.assert_awaited_once_with(
        {"type": "websocket.close", "code": 1008}
    )
    self.app.assert_not_called()

  def test_unsupported_scope_type_raises_without_calling_app(self):
    scope = {"type": "custom"}
    receive = mock.AsyncMock()

    with self.assertRaisesRegex(ValueError, "Unsupported ASGI scope type"):
      asyncio.run(self.mw(scope, receive, self.send))

    self.app.assert_not_called()
    self.send.assert_not_called()

  def test_call_other_path_attested(self):
    async def run():
      self.mw._attested_sockets[self.ssl_obj] = math.inf
      scope = {
          "type": "http",
          "path": "/other",
          "extensions": {"tls_socket": self.ssl_obj},
      }
      receive = mock.AsyncMock()
      await self.mw(scope, receive, self.send)

      self.app.assert_called_once_with(scope, receive, self.send)

    asyncio.run(run())

  def test_call_other_path_unattested(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/other",
          "extensions": {"tls_socket": self.ssl_obj},
      }
      receive = mock.AsyncMock()
      await self.mw(scope, receive, self.send)

      self.app.assert_not_called()
      expected_body = (
          b'{"error":"Unauthorized: Connection must be attested first."}'
      )
      self.send.assert_has_calls([
          mock.call({
              "type": "http.response.start",
              "status": 401,
              "headers": [
                  (b"content-length", b"60"),
                  (b"content-type", b"application/json"),
              ],
          }),
          mock.call({"type": "http.response.body", "body": expected_body}),
      ])

    asyncio.run(run())

  def test_call_other_path_missing_socket(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/other",
          "extensions": {},
      }
      receive = mock.AsyncMock()
      await self.mw(scope, receive, self.send)

      self.app.assert_not_called()
      expected_body = (
          b'{"error":"Unauthorized: Connection must be attested first."}'
      )
      self.send.assert_has_calls([
          mock.call({
              "type": "http.response.start",
              "status": 401,
              "headers": [
                  (b"content-length", b"60"),
                  (b"content-type", b"application/json"),
              ],
          }),
          mock.call({"type": "http.response.body", "body": expected_body}),
      ])

    asyncio.run(run())

  def test_handle_attestation_success(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }
      request_proto = attestation_pb2.AttestConnectionRequest(
          required_verifier_type=[
              attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
          ]
      )
      body = json_format.MessageToJson(request_proto).encode("utf-8")

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      response_proto = attestation_pb2.AttestConnectionResponse(
          instance_public_key=attestation_pb2.EcdsaP256PublicKey(
              key_bytes=b"test_public_key"
          )
      )
      self.mock_attested_tls.attest_connection.return_value = (
          attestation.AttestationResult(response=response_proto)
      )

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_called_once_with(
          request_proto,
          ssl_obj=self.ssl_obj,
      )
      response_start_call, response_body_call = self.send.call_args_list
      (response_start_arg,) = response_start_call.args
      (response_body_arg,) = response_body_call.args
      self.assertEqual(response_start_arg["type"], "http.response.start")
      self.assertEqual(response_start_arg["status"], http.HTTPStatus.OK)
      self.assertEqual(response_body_arg["type"], "http.response.body")
      response_dict = json_format.MessageToDict(response_proto)
      self.assertEqual(
          json.loads(response_body_arg["body"]),
          response_dict,
      )
      self.assertIn(self.ssl_obj, self.mw._attested_sockets)

    asyncio.run(run())

  def test_replayed_attestation_drops_the_connection(self):
    """A mutually attested session may not attest again; it is dropped."""

    async def run():
      self.mw._attested_sockets[self.ssl_obj] = math.inf
      self.mock_attested_tls.attest_connection.side_effect = (
          attestation_protocol.AttestationReplayError("already attested")
      )
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }

      async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

      await self.mw(scope, receive, self.send)

      (response_start_arg,) = self.send.call_args_list[0].args
      with self.subTest("Forbidden"):
        self.assertEqual(
            response_start_arg["status"], http.HTTPStatus.FORBIDDEN
        )
      with self.subTest("ConnectionClosed"):
        self.assertIn((b"connection", b"close"), response_start_arg["headers"])
      with self.subTest("AuthorizationRevoked"):
        self.assertNotIn(self.ssl_obj, self.mw._attested_sockets)

      # Application traffic on the dropped session is refused.
      self.send.reset_mock()
      await self.mw(
          {
              "type": "http",
              "path": "/infer",
              "method": "GET",
              "headers": [],
              "extensions": {"tls_socket": self.ssl_obj},
          },
          receive,
          self.send,
      )
      (unauthorized_start,) = self.send.call_args_list[0].args
      with self.subTest("SubsequentTrafficUnauthorized"):
        self.assertEqual(
            unauthorized_start["status"], http.HTTPStatus.UNAUTHORIZED
        )
        self.app.assert_not_called()

    asyncio.run(run())

  def _attest(self, expires_at):
    """Runs a successful attestation that yields the given expiry."""
    self.mock_attested_tls.attest_connection.return_value = (
        attestation.AttestationResult(
            response=attestation_pb2.AttestConnectionResponse(),
            expires_at=expires_at,
        )
    )

    async def receive():
      return {"type": "http.request", "body": b"{}", "more_body": False}

    return self.mw(
        {
            "type": "http",
            "path": "/_attest-connection",
            "method": "POST",
            "headers": [],
            "extensions": {"tls_socket": self.ssl_obj},
        },
        receive,
        self.send,
    )

  def _application_request(self):
    """Sends an application request on `self.ssl_obj`'s session."""
    return self.mw(
        {
            "type": "http",
            "path": "/infer",
            "method": "GET",
            "headers": [],
            "extensions": {"tls_socket": self.ssl_obj},
        },
        mock.AsyncMock(),
        self.send,
    )

  def test_a_mutual_session_inherits_the_client_token_expiry(self):
    async def run():
      expiry = time.time() + 300
      await self._attest(expiry)

      self.assertEqual(self.mw._attested_sockets[self.ssl_obj], expiry)

    asyncio.run(run())

  def test_mutual_attestation_replaces_server_only_infinite_expiry(self):
    asyncio.run(self._attest(math.inf))
    expiry = time.time() + 300
    asyncio.run(self._attest(expiry))

    self.assertEqual(self.mw._attested_sockets[self.ssl_obj], expiry)

  def test_traffic_is_served_before_the_attestation_expires(self):
    async def run():
      await self._attest(time.time() + 300)
      self.send.reset_mock()

      await self._application_request()

      self.app.assert_called_once()

    asyncio.run(run())

  def test_traffic_is_refused_once_the_attestation_expires(self):
    async def run():
      expiry = 1_700_000_000.0
      await self._attest(expiry)
      self.send.reset_mock()

      # Exactly at the expiry time counts as expired.
      with mock.patch.object(asgi.time, "time", autospec=True) as mock_time:
        mock_time.return_value = expiry
        await self._application_request()

      (response_start,) = self.send.call_args_list[0].args
      with self.subTest("Unauthorized"):
        self.assertEqual(response_start["status"], http.HTTPStatus.UNAUTHORIZED)
        self.app.assert_not_called()
      with self.subTest("ConnectionClosed"):
        self.assertIn((b"connection", b"close"), response_start["headers"])
      with self.subTest("AuthorizationDropped"):
        self.assertNotIn(self.ssl_obj, self.mw._attested_sockets)

    asyncio.run(run())

  def test_a_request_admitted_before_expiry_runs_to_completion(self):
    """Expiry is checked at request entry, so nothing is cut off mid-flight."""

    async def run():
      expiry = 1_700_000_000.0
      await self._attest(expiry)
      self.send.reset_mock()

      with mock.patch.object(asgi.time, "time", autospec=True) as mock_time:
        mock_time.return_value = expiry - 1

        async def slow_app(scope, receive, send):
          del scope, receive, send  # Unused.
          # The clock passes the expiry while the request runs.
          mock_time.return_value = expiry + 1

        self.app.side_effect = slow_app
        await self._application_request()

      self.app.assert_called_once()
      self.assertIn(self.ssl_obj, self.mw._attested_sockets)

    asyncio.run(run())

  def test_handle_attestation_success_with_label(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }
      request_dict = {
          "requiredVerifierType": ["VERIFIER_TYPE_GCA"],
          "label": "my-custom-label",
      }
      body = json.dumps(request_dict).encode("utf-8")

      request_proto = attestation_pb2.AttestConnectionRequest(
          required_verifier_type=[
              attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
          ]
      )

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      response_proto = attestation_pb2.AttestConnectionResponse(
          instance_public_key=attestation_pb2.EcdsaP256PublicKey(
              key_bytes=b"test_public_key"
          )
      )
      self.mock_attested_tls.attest_connection.return_value = (
          attestation.AttestationResult(response=response_proto)
      )

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_called_once_with(
          request_proto,
          ssl_obj=self.ssl_obj,
      )
      response_start_call, response_body_call = self.send.call_args_list
      (response_start_arg,) = response_start_call.args
      (response_body_arg,) = response_body_call.args
      self.assertEqual(response_start_arg["type"], "http.response.start")
      self.assertEqual(response_start_arg["status"], http.HTTPStatus.OK)
      self.assertEqual(response_body_arg["type"], "http.response.body")
      response_dict = json_format.MessageToDict(response_proto)
      self.assertEqual(
          json.loads(response_body_arg["body"]),
          response_dict,
      )
      self.assertIn(self.ssl_obj, self.mw._attested_sockets)

    asyncio.run(run())

  def test_handle_attestation_no_ssl_obj(self):
    scope = {
        "type": "http",
        "path": "/_attest-connection",
        "method": "POST",
        "headers": [],
        "extensions": {},
    }
    request_proto = attestation_pb2.AttestConnectionRequest()
    body = json_format.MessageToJson(request_proto).encode("utf-8")
    receive = mock.AsyncMock(
        return_value={"type": "http.request", "body": body, "more_body": False}
    )

    with self.assertLogs(level="ERROR") as logs:
      asyncio.run(self.mw(scope, receive, self.send))

    self.mock_attested_tls.attest_connection.assert_not_called()
    raw_body = self._assert_error_response(
        http.HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error."
    )
    self.assertNotIn(b"TLS Socket", raw_body)
    self.assertTrue(
        any("TLS Socket not found." in line for line in logs.output)
    )

  @parameterized.named_parameters(
      dict(
          testcase_name="invalid_json_body",
          body=b"invalid json",
      ),
      dict(
          testcase_name="malformed_json_list",
          body=b"[]",
      ),
      dict(
          testcase_name="undecodable_body",
          body=b"\x80abc",
      ),
      dict(
          testcase_name="proto_parse_error",
          body=b'{"requiredVerifierType": 1}',
      ),
  )
  def test_handle_attestation_bad_requests(self, body: bytes):
    scope = {
        "type": "http",
        "path": "/_attest-connection",
        "method": "POST",
        "headers": [],
        "extensions": {"tls_socket": self.ssl_obj},
    }
    receive = mock.AsyncMock(
        return_value={"type": "http.request", "body": body, "more_body": False}
    )

    asyncio.run(self.mw(scope, receive, self.send))

    self.mock_attested_tls.attest_connection.assert_not_called()
    self._assert_error_response(http.HTTPStatus.BAD_REQUEST, "Invalid request")

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
    mw = asgi.PromptEncryptionASGIMiddleware(self.app, attested_tls)
    request_proto = attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[attestation_pb2.VerifierType.VERIFIER_TYPE_GCA],
        nonce=b"n" * 32,
    )
    body = json_format.MessageToJson(request_proto).encode("utf-8")
    scope = {
        "type": "http",
        "path": "/_attest-connection",
        "method": "POST",
        "headers": [],
        "extensions": {"tls_socket": self.ssl_obj},
    }
    receive = mock.AsyncMock(
        return_value={"type": "http.request", "body": body, "more_body": False}
    )

    with self.assertLogs(level="WARNING") as logs:
      asyncio.run(mw(scope, receive, self.send))

    response_start_call, response_body_call = self.send.call_args_list
    (response_start_arg,) = response_start_call.args
    (response_body_arg,) = response_body_call.args
    self.assertEqual(response_start_arg["status"], http.HTTPStatus.BAD_REQUEST)
    self.assertNotIn((b"connection", b"close"), response_start_arg["headers"])
    self.assertEqual(
        json.loads(response_body_arg["body"]),
        {"error": "Invalid attestation request."},
    )
    self.assertNotIn(b"requires mutual attestation", response_body_arg["body"])
    self.assertNotIn(self.ssl_obj, mw._attested_sockets)
    self.assertTrue(
        any(
            "This server requires mutual attestation." in line
            for line in logs.output
        )
    )

  @parameterized.named_parameters(
      dict(
          testcase_name="policy_violation_error",
          error_cls=exceptions.PolicyViolationError,
          secret="secret-policy-detail",
      ),
      dict(
          testcase_name="attestation_verification_error",
          error_cls=exceptions.AttestationVerificationError,
          secret="secret-verify-detail",
      ),
  )
  def test_client_attestation_failure_logs_detail_without_leaking_it(
      self, error_cls, secret
  ):
    scope = {
        "type": "http",
        "path": "/_attest-connection",
        "method": "POST",
        "headers": [],
        "extensions": {"tls_socket": self.ssl_obj},
    }
    receive = mock.AsyncMock(
        return_value={
            "type": "http.request",
            "body": b"{}",
            "more_body": False,
        }
    )

    def raise_chained(*unused_args, **unused_kwargs):
      raise error_cls(secret) from RuntimeError("jwks-cause-detail")

    self.mock_attested_tls.attest_connection.side_effect = raise_chained

    with self.assertLogs(level="WARNING") as logs:
      asyncio.run(self.mw(scope, receive, self.send))

    response_start_call, response_body_call = self.send.call_args_list
    (response_start_arg,) = response_start_call.args
    (response_body_arg,) = response_body_call.args
    self.assertEqual(response_start_arg["status"], http.HTTPStatus.FORBIDDEN)
    self.assertNotIn((b"connection", b"close"), response_start_arg["headers"])
    self.assertEqual(
        json.loads(response_body_arg["body"]),
        {"error": "Client attestation failed."},
    )
    self.assertNotIn(secret.encode("utf-8"), response_body_arg["body"])
    self.assertNotIn(b"jwks-cause-detail", response_body_arg["body"])
    self.assertNotIn(self.ssl_obj, self.mw._attested_sockets)
    self.assertTrue(any(secret in line for line in logs.output))
    self.assertTrue(any("jwks-cause-detail" in line for line in logs.output))

  @parameterized.named_parameters(
      dict(
          testcase_name="value_error",
          error=ValueError("secret-value-error"),
          secret="secret-value-error",
      ),
      dict(
          testcase_name="runtime_error",
          error=RuntimeError("secret-runtime-fault"),
          secret="secret-runtime-fault",
      ),
  )
  def test_attest_connection_internal_error(self, error, secret):
    scope = {
        "type": "http",
        "path": "/_attest-connection",
        "method": "POST",
        "headers": [],
        "extensions": {"tls_socket": self.ssl_obj},
    }
    request_proto = attestation_pb2.AttestConnectionRequest()
    body = json_format.MessageToJson(request_proto).encode("utf-8")
    receive = mock.AsyncMock(
        return_value={"type": "http.request", "body": body, "more_body": False}
    )
    self.mock_attested_tls.attest_connection.side_effect = error

    with self.assertLogs(level="ERROR") as logs:
      asyncio.run(self.mw(scope, receive, self.send))

    self.mock_attested_tls.attest_connection.assert_called_once()
    raw_body = self._assert_error_response(
        http.HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error."
    )
    self.assertNotIn(secret.encode("utf-8"), raw_body)
    self.assertTrue(any(secret in line for line in logs.output))

  @mock.patch.object(asgi.uvicorn, "run", autospec=True)
  @mock.patch.object(keys, "KeyManager", autospec=True)
  @mock.patch.object(token, "TokenManager", autospec=True)
  @mock.patch.object(attestation, "AttestedTLS", autospec=True)
  def test_run_uvicorn_app_defaults(
      self,
      mock_attested_tls_cls,
      mock_token_manager_cls,
      mock_key_manager_cls,
      mock_uvicorn_run,
  ):
    mock_app = mock.MagicMock()
    asgi.run_uvicorn_app(mock_app, host="localhost", port=8000)

    mock_key_manager_cls.assert_called_once()
    mock_token_manager_cls.assert_called_once_with(
        key_manager=mock_key_manager_cls.return_value
    )
    mock_token_manager_cls.return_value.__enter__.assert_called_once()
    mock_attested_tls_cls.assert_called_once_with(
        mock_token_manager_cls.return_value,
        client_policy=None,
        require_mutual_attestation=False,
    )
    mock_uvicorn_run.assert_called_once()
    self.assertIsInstance(
        mock_uvicorn_run.call_args[0][0], asgi.PromptEncryptionASGIMiddleware
    )
    self.assertEqual(
        mock_uvicorn_run.call_args[1],
        {
            "host": "localhost",
            "port": 8000,
            "http": asgi.TlsInjectorProtocol,
            "log_level": "info",
        },
    )
    mock_token_manager_cls.return_value.__exit__.assert_called_once()

  @mock.patch.object(asgi.uvicorn, "run", autospec=True)
  def test_run_uvicorn_app_rejects_invalid_mutual_settings_before_start(
      self, mock_uvicorn_run
  ):
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)

    with self.assertRaisesRegex(ValueError, "client_policy is required"):
      asgi.run_uvicorn_app(
          mock.MagicMock(),
          key_manager=mock.create_autospec(keys.KeyManager, instance=True),
          token_manager=mock_token_manager,
          require_mutual_attestation=True,
      )

    mock_token_manager.__enter__.assert_not_called()
    mock_uvicorn_run.assert_not_called()

  @mock.patch.object(asgi.uvicorn, "run", autospec=True)
  @mock.patch.object(attestation, "AttestedTLS", autospec=True)
  def test_run_uvicorn_app_with_managers(
      self,
      mock_attested_tls_cls,
      mock_uvicorn_run,
  ):
    mock_app = mock.MagicMock()
    mock_key_manager = mock.MagicMock()
    mock_token_manager = mock.MagicMock()
    asgi.run_uvicorn_app(
        mock_app,
        key_manager=mock_key_manager,
        token_manager=mock_token_manager,
        host="localhost",
        port=8000,
    )

    mock_token_manager.__enter__.assert_called_once()
    mock_attested_tls_cls.assert_called_once_with(
        mock_token_manager,
        client_policy=None,
        require_mutual_attestation=False,
    )
    mock_uvicorn_run.assert_called_once()
    self.assertIsInstance(
        mock_uvicorn_run.call_args[0][0], asgi.PromptEncryptionASGIMiddleware
    )
    self.assertEqual(
        mock_uvicorn_run.call_args[1],
        {
            "host": "localhost",
            "port": 8000,
            "http": asgi.TlsInjectorProtocol,
            "log_level": "info",
        },
    )
    mock_token_manager.__exit__.assert_called_once()

  @mock.patch.object(asgi.uvicorn, "run", autospec=True)
  @mock.patch.object(attestation, "AttestedTLS", autospec=True)
  def test_run_uvicorn_app_forwards_the_mutual_configuration(
      self, mock_attested_tls_cls, mock_uvicorn_run
  ):
    del mock_uvicorn_run
    mock_token_manager = mock.create_autospec(token.TokenManager, instance=True)
    client_policy = attestation_pb2.AttestationPolicy(expected_audience="aud")

    asgi.run_uvicorn_app(
        mock.MagicMock(),
        token_manager=mock_token_manager,
        client_policy=client_policy,
        require_mutual_attestation=True,
    )

    mock_attested_tls_cls.assert_called_once_with(
        mock_token_manager,
        client_policy=client_policy,
        require_mutual_attestation=True,
    )

  @mock.patch.object(asgi.uvicorn, "run", autospec=True)
  @mock.patch.object(keys, "KeyManager", autospec=True)
  @mock.patch.object(token, "TokenManager", autospec=True)
  @mock.patch.object(attestation, "AttestedTLS", autospec=True)
  def test_run_uvicorn_app_with_log_config(
      self,
      mock_attested_tls_cls,
      mock_token_manager_cls,
      mock_key_manager_cls,
      mock_uvicorn_run,
  ):
    mock_app = mock.MagicMock()
    asgi.run_uvicorn_app(mock_app, host="localhost", port=8000, log_config={})

    mock_key_manager_cls.assert_called_once()
    mock_token_manager_cls.assert_called_once_with(
        key_manager=mock_key_manager_cls.return_value
    )
    mock_token_manager_cls.return_value.__enter__.assert_called_once()
    mock_attested_tls_cls.assert_called_once_with(
        mock_token_manager_cls.return_value,
        client_policy=None,
        require_mutual_attestation=False,
    )
    mock_uvicorn_run.assert_called_once()
    self.assertIsInstance(
        mock_uvicorn_run.call_args[0][0], asgi.PromptEncryptionASGIMiddleware
    )
    self.assertEqual(
        mock_uvicorn_run.call_args[1],
        {
            "host": "localhost",
            "port": 8000,
            "http": asgi.TlsInjectorProtocol,
            "log_config": {},
        },
    )
    mock_token_manager_cls.return_value.__exit__.assert_called_once()


class TlsInjectorProtocolTest(absltest.TestCase):

  def test_tls_injector_protocol_injects_ssl_object(self):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.interface = "asgi3"
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = mock.MagicMock()
      ssl_object = mock.MagicMock()
      protocol.transport.get_extra_info.return_value = ssl_object

      scope = {"type": "http"}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertEqual(scope["extensions"]["tls_socket"], ssl_object)
      original_app.assert_called_once_with(scope, receive, send)
      protocol.transport.get_extra_info.assert_called_once_with("ssl_object")

    asyncio.run(run())

  def test_tls_injector_protocol_no_transport(self):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.interface = "asgi3"
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = None

      scope = {"type": "http"}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertNotIn("extensions", scope)
      original_app.assert_called_once_with(scope, receive, send)

    asyncio.run(run())

  def test_tls_injector_protocol_no_ssl_object(self):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.interface = "asgi3"
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = mock.MagicMock()
      protocol.transport.get_extra_info.return_value = None

      scope = {"type": "http"}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertNotIn("extensions", scope)
      original_app.assert_called_once_with(scope, receive, send)
      protocol.transport.get_extra_info.assert_called_once_with("ssl_object")

    asyncio.run(run())

  def test_tls_injector_protocol_not_http(self):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.interface = "asgi3"
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = mock.MagicMock()
      protocol.transport.get_extra_info.return_value = mock.MagicMock()

      scope = {"type": "not-http"}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertNotIn("extensions", scope)
      original_app.assert_called_once_with(scope, receive, send)
      protocol.transport.get_extra_info.assert_not_called()

    asyncio.run(run())

  def test_tls_injector_protocol_injects_ssl_object_with_existing_extensions(
      self,
  ):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.interface = "asgi3"
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = mock.MagicMock()
      ssl_object = mock.MagicMock()
      protocol.transport.get_extra_info.return_value = ssl_object

      scope = {"type": "http", "extensions": {"other": 1}}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertEqual(scope["extensions"]["tls_socket"], ssl_object)
      self.assertEqual(scope["extensions"]["other"], 1)
      original_app.assert_called_once_with(scope, receive, send)
      protocol.transport.get_extra_info.assert_called_once_with("ssl_object")

    asyncio.run(run())


if __name__ == "__main__":
  absltest.main()
