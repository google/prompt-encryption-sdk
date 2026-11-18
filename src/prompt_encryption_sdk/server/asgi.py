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

"""ASGI middleware for handling attested TLS connections."""

import http
import json
import logging
import time
from typing import Any
import weakref

from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token
from google.protobuf import json_format
from starlette import requests
from starlette import responses
import uvicorn
from uvicorn.config import Config
from uvicorn.protocols.http.h11_impl import H11Protocol


class TlsInjectorProtocol(H11Protocol):

  def __init__(
      self,
      config: Config,
      server_state,
      app_state,
      _loop=None,
      **kwargs,
  ):
    super().__init__(config, server_state, app_state, _loop, **kwargs)
    self.original_app = self.app

    async def app_wrapper(scope, receive, send):
      if scope["type"] == "http":
        transport = self.transport
        if transport:
          ssl_obj = transport.get_extra_info("ssl_object")
          if ssl_obj:
            if "extensions" not in scope:
              scope["extensions"] = {}
            scope["extensions"]["tls_socket"] = ssl_obj
      await self.original_app(scope, receive, send)

    self.app = app_wrapper


class PromptEncryptionASGIMiddleware:
  """ASGI middleware for handling attested TLS connections.

  Attributes:
    app: The ASGI application to wrap.
    attested_tls: An instance of `attestation.AttestedTLS` used for handling
      attestation.
  """

  def __init__(self, app, attested_tls: attestation.AttestedTLS):
    self.app = app
    self.attested_tls = attested_tls
    # Maps an attested TLS socket to the time its authorization lapses; see
    # attestation.AttestationResult.expires_at.
    self._attested_sockets: weakref.WeakKeyDictionary[Any, float] = (
        weakref.WeakKeyDictionary()
    )

  async def __call__(self, scope, receive, send):
    scope_type = scope["type"]
    if scope_type == "lifespan":
      await self.app(scope, receive, send)
      return
    if scope_type == "websocket":
      await receive()
      await send({"type": "websocket.close", "code": 1008})
      return
    if scope_type != "http":
      raise ValueError(f"Unsupported ASGI scope type: {scope_type!r}")

    if scope["path"] == "/_attest-connection":
      try:
        await self.handle_attestation(scope, receive, send)
      except attestation_protocol.AttestationReplayError as e:
        # The session already proved itself against an EKM that cannot change.
        # Revoke it and close the connection rather than re-attesting it.
        logging.warning("Dropping re-attestation on an attested session: %r", e)
        replayed_socket = scope.get("extensions", {}).get("tls_socket")
        if replayed_socket is not None:
          self._attested_sockets.pop(replayed_socket, None)
        error_response = responses.JSONResponse(
            {"error": str(e)},
            status_code=http.HTTPStatus.FORBIDDEN,
            # Tells the ASGI server to tear down this TLS session.
            headers={"Connection": "close"},
        )
        await error_response(scope, receive, send)
      except (
          exceptions.AttestationVerificationError,
          exceptions.PolicyViolationError,
      ) as e:
        logging.warning("Client attestation failed: %r", e, exc_info=True)
        error_response = responses.JSONResponse(
            {"error": "Client attestation failed."},
            status_code=http.HTTPStatus.FORBIDDEN,
        )
        await error_response(scope, receive, send)
      except attestation_protocol.AttestationRequestError as e:
        logging.warning("Invalid attestation request: %r", e)
        error_response = responses.JSONResponse(
            {"error": "Invalid attestation request."},
            status_code=http.HTTPStatus.BAD_REQUEST,
        )
        await error_response(scope, receive, send)
      except json_format.ParseError as e:
        logging.warning("Error parsing AttestConnectionRequest: %r", e)
        error_response = responses.JSONResponse(
            {"error": "Invalid request"},
            status_code=http.HTTPStatus.BAD_REQUEST,
        )
        await error_response(scope, receive, send)
      except Exception as e:  # pylint: disable=broad-except
        logging.exception(
            "Error during handling attest connection request: %r", e
        )
        error_response = responses.JSONResponse(
            {"error": "Internal server error."},
            status_code=http.HTTPStatus.INTERNAL_SERVER_ERROR,
        )
        await error_response(scope, receive, send)
      return

    extensions = scope.get("extensions", {})
    ssl_obj = extensions.get("tls_socket")
    expires_at = self._attested_sockets.get(ssl_obj) if ssl_obj else None
    if expires_at is None:
      error_response = responses.JSONResponse(
          {"error": "Unauthorized: Connection must be attested first."},
          status_code=http.HTTPStatus.UNAUTHORIZED,
      )
      await error_response(scope, receive, send)
      return

    if time.time() >= expires_at:
      # The peer's attestation token has expired, so its evidence no longer
      # says anything about the peer's current state. Retire the connection;
      # the peer reconnects and attests again over a fresh TLS session.
      logging.warning("Attestation expired on this session; closing it.")
      self._attested_sockets.pop(ssl_obj, None)
      error_response = responses.JSONResponse(
          {"error": "Unauthorized: Attestation expired."},
          status_code=http.HTTPStatus.UNAUTHORIZED,
          # Tells the ASGI server to tear down this TLS session.
          headers={"Connection": "close"},
      )
      await error_response(scope, receive, send)
      return

    await self.app(scope, receive, send)

  async def handle_attestation(self, scope, receive, send):
    """Handles the requests to /_attest-connection.

    Args:
      scope: The ASGI scope.
      receive: The ASGI receive function.
      send: The ASGI send function.
    """
    request = requests.Request(scope, receive)
    raw_body = await request.body()

    try:
      parsed_json = json.loads(raw_body.decode("utf-8") if raw_body else "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
      raise json_format.ParseError("Invalid JSON") from e

    if not isinstance(parsed_json, dict):
      raise json_format.ParseError(
          "Malformed JSON structure: Expected a dictionary"
      )

    req = json_format.ParseDict(
        parsed_json,
        attestation_pb2.AttestConnectionRequest(),
        ignore_unknown_fields=True,
    )

    extensions = scope.get("extensions", {})
    ssl_obj = extensions.get("tls_socket")

    if not ssl_obj:
      raise RuntimeError("TLS Socket not found.")

    result = self.attested_tls.attest_connection(req, ssl_obj=ssl_obj)
    self._attested_sockets[ssl_obj] = result.expires_at
    attestation_response_dict = json_format.MessageToDict(result.response)
    response = responses.JSONResponse(attestation_response_dict)
    await response(scope, receive, send)


def run_uvicorn_app(
    app: Any,
    *,
    key_manager: keys.KeyManager | None = None,
    token_manager: token.TokenManager | None = None,
    client_policy: attestation_pb2.AttestationPolicy | None = None,
    require_mutual_attestation: bool = False,
    **kwargs: Any,
) -> None:
  """Runs a uvicorn app with PromptEncryptionASGIMiddleware.

  Args:
    app: The ASGI application to run.
    key_manager: An optional keys.KeyManager instance. If not provided, a new
      one will be created.
    token_manager: An optional token.TokenManager instance. If not provided, a
      new one will be created using the key_manager.
    client_policy: Policy used to verify confidential clients. Providing it
      enables mutual attestation. None means the server serves only server-only
      clients.
    require_mutual_attestation: Reject server-only clients.
    **kwargs: Additional keyword arguments to pass to uvicorn.run.

  Raises:
    ValueError: If `require_mutual_attestation` is true without a
      `client_policy`.
  """
  if key_manager is None:
    key_manager = keys.KeyManager()
  if token_manager is None:
    token_manager = token.TokenManager(key_manager=key_manager)
  kwargs["http"] = TlsInjectorProtocol
  if "log_config" not in kwargs:
    kwargs["log_level"] = kwargs.get("log_level", "info")
  # Built before the token manager starts, so that invalid mutual settings
  # fail before any key or token is created.
  attested_tls = attestation.AttestedTLS(
      token_manager,
      client_policy=client_policy,
      require_mutual_attestation=require_mutual_attestation,
  )
  protected_app = PromptEncryptionASGIMiddleware(app, attested_tls)
  with token_manager:
    uvicorn.run(protected_app, **kwargs)
