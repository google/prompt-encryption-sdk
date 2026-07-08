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
from collections.abc import Sequence
import http
import json
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
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
    self.mw = asgi.PromptEncryptionASGIMiddleware(self.app, self.mock_attested_tls)
    self.send = mock.AsyncMock()
    self.ssl_obj = mock.MagicMock()

  def _assert_error_response(
      self, expected_status: int, expected_error_substrings: Sequence[str]
  ):
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
    body_dict = json.loads(response_body_arg["body"])
    for substring in expected_error_substrings:
      self.assertIn(substring, body_dict["error"])

  def test_call_other_path_attested(self):
    async def run():
      self.mw._attested_sockets.add(self.ssl_obj)
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
      self.mock_attested_tls.attest_connection.return_value = response_proto

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
      self.mock_attested_tls.attest_connection.return_value = response_proto

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
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {},
      }
      request_proto = attestation_pb2.AttestConnectionRequest()
      body = json_format.MessageToJson(request_proto).encode("utf-8")

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_not_called()
      self._assert_error_response(
          http.HTTPStatus.INTERNAL_SERVER_ERROR,
          [
              "An internal server error occurred: RuntimeError('TLS Socket"
              " not found.')"
          ],
      )

    asyncio.run(run())

  @parameterized.named_parameters(
      dict(
          testcase_name="invalid_json_body",
          body=b"invalid json",
          expected_status=http.HTTPStatus.BAD_REQUEST,
          expected_error_substrings=["An internal server error occurred"],
      ),
      dict(
          testcase_name="malformed_json_list",
          body=b"[]",
          expected_status=http.HTTPStatus.BAD_REQUEST,
          expected_error_substrings=[
              "An internal server error occurred",
              "Malformed JSON structure",
          ],
      ),
      dict(
          testcase_name="undecodable_body",
          body=b"\x80abc",
          expected_status=http.HTTPStatus.INTERNAL_SERVER_ERROR,
          expected_error_substrings=["An internal server error occurred"],
      ),
      dict(
          testcase_name="proto_parse_error",
          body=b'{"requiredVerifierType": 1}',
          expected_status=http.HTTPStatus.BAD_REQUEST,
          expected_error_substrings=["An internal server error occurred"],
      ),
  )
  def test_handle_attestation_bad_requests(
      self,
      body: bytes,
      expected_status: int,
      expected_error_substrings: Sequence[str],
  ):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_not_called()
      self._assert_error_response(expected_status, expected_error_substrings)

    asyncio.run(run())

  def test_attest_connection_internal_error(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }
      request_proto = attestation_pb2.AttestConnectionRequest()
      body = json_format.MessageToJson(request_proto).encode("utf-8")

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      self.mock_attested_tls.attest_connection.side_effect = ValueError(
          "test error"
      )

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_called_once()
      self._assert_error_response(
          http.HTTPStatus.INTERNAL_SERVER_ERROR,
          ["An internal server error occurred: ValueError('test error')"],
      )

    asyncio.run(run())

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
        mock_token_manager_cls.return_value
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
    mock_attested_tls_cls.assert_called_once_with(mock_token_manager)
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
        mock_token_manager_cls.return_value
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
