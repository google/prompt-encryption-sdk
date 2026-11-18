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

"""WSGI middleware for handling attested TLS connections."""

from collections.abc import Callable, Iterable
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
import gunicorn.app.base
from gunicorn.http import wsgi as gunicorn_wsgi
from gunicorn.workers import sync
import werkzeug.wrappers

# Patch gunicorn to inject the socket into the environ.
# This allows the middleware to access the raw SSL socket for EKM extraction.
_original_create = gunicorn_wsgi.create

# PEP 3333 does not let an application send hop-by-hop headers, so gunicorn
# drops a "Connection: close" header. The middleware closes the connection
# through this callback instead.
_FORCE_CLOSE_KEY = "prompt_encryption.force_close"


def _patched_wsgi_create(req, *args, **kwargs):
  resp, environ = _original_create(req, *args, **kwargs)
  # Check if our Custom Worker attached the socket
  if hasattr(req, "confidential_socket"):
    environ["prompt_encryption.socket"] = req.confidential_socket
  if hasattr(resp, "force_close"):
    environ[_FORCE_CLOSE_KEY] = resp.force_close
  return resp, environ


gunicorn_wsgi.create = _patched_wsgi_create


class PromptEncryptionGunicornWorker(sync.SyncWorker):
  """Captures the raw SSLSocket immediately after the handshake."""

  def handle_request(self, listener, req, client, addr):
    if client:
      # Attach raw socket to the Gunicorn request object
      req.confidential_socket = client
    super().handle_request(listener, req, client, addr)

  def __repr__(self):
    return f"<{self.__class__.__name__} pid={self.pid}>"


def _json_error(
    environ: dict[str, Any],
    start_response: Callable[..., Any],
    status: str,
    error: str,
    *,
    close: bool = False,
) -> list[bytes]:
  """Starts a JSON error response, tearing down the TLS session if close.

  Under gunicorn, the connection is closed through `resp.force_close`, because
  gunicorn drops a `Connection` header from the application. Other servers get
  a `Connection: close` header.

  Args:
    environ: The WSGI environment of the request.
    start_response: The WSGI `start_response` callable.
    status: The HTTP status line.
    error: The error message for the JSON body.
    close: Whether the server must close the connection after the response.

  Returns:
    The response body.
  """
  body = json.dumps({"error": error}).encode("utf-8")
  headers = [
      ("Content-Type", "application/json"),
      ("Content-Length", str(len(body))),
  ]
  if close:
    force_close = environ.get(_FORCE_CLOSE_KEY)
    if callable(force_close):
      force_close()
    else:
      headers.append(("Connection", "close"))
  start_response(status, headers)
  return [body]


class PromptEncryptionWSGIMiddleware:
  """WSGI middleware for handling attested TLS connections.

  Attributes:
    app: The WSGI application to wrap.
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

  def __repr__(self):
    return f"<{self.__class__.__name__} app={self.app!r}>"

  def __call__(
      self, environ: dict[str, Any], start_response
  ) -> Iterable[bytes]:
    path = environ.get("PATH_INFO", "")

    if path == "/_attest-connection":
      return self.handle_attestation(environ, start_response)

    ssl_obj = environ.get("prompt_encryption.socket")
    expires_at = self._attested_sockets.get(ssl_obj) if ssl_obj else None
    if expires_at is None:
      return _json_error(
          environ,
          start_response,
          "401 Unauthorized",
          "Unauthorized: Connection must be attested first.",
      )

    if time.time() >= expires_at:
      # The peer's attestation token has expired, so its evidence no longer
      # says anything about the peer's current state. Retire the connection;
      # the peer reconnects and attests again over a fresh TLS session.
      logging.warning("Attestation expired on this session; closing it.")
      self._attested_sockets.pop(ssl_obj, None)
      return _json_error(
          environ,
          start_response,
          "401 Unauthorized",
          "Unauthorized: Attestation expired.",
          close=True,
      )

    return self.app(environ, start_response)

  def _parse_request(self, environ: dict[str, Any]) -> bytes:
    """Parses the request body and returns the raw bytes."""
    try:
      request = werkzeug.wrappers.Request(environ)
      return request.get_data()
    except Exception:  # pylint: disable=broad-except
      return b"{}"

  def handle_attestation(
      self, environ: dict[str, Any], start_response
  ) -> Iterable[bytes]:
    """Handles the requests to /_attest-connection.

    Args:
      environ: The WSGI environment.
      start_response: The WSGI start_response callable.

    Returns:
      An iterable of bytes representing the response body.
    """
    ssl_obj = environ.get("prompt_encryption.socket")
    try:
      body = self._parse_request(environ)

      try:
        parsed_json = json.loads(body.decode("utf-8") if body else "{}")
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

      # Socket comes from environ (injected by our patched gunicorn/worker).
      if not ssl_obj:
        raise RuntimeError(
            "TLS Socket not found. Server must be started via"
            " run_gunicorn_app()"
        )

      result = self.attested_tls.attest_connection(req, ssl_obj=ssl_obj)
      self._attested_sockets[ssl_obj] = result.expires_at
      attestation_response_dict = json_format.MessageToDict(result.response)

      response_data = json.dumps(attestation_response_dict).encode("utf-8")

      start_response(
          "200 OK",
          [
              ("Content-Type", "application/json"),
              ("Content-Length", str(len(response_data))),
          ],
      )
      return [response_data]

    except attestation_protocol.AttestationReplayError as e:
      # The session already proved itself against an EKM that cannot change.
      # Revoke it and close the connection rather than re-attesting it.
      logging.warning("Dropping re-attestation on an attested session: %r", e)
      if ssl_obj is not None:
        self._attested_sockets.pop(ssl_obj, None)
      return _json_error(
          environ, start_response, "403 Forbidden", str(e), close=True
      )

    except (
        exceptions.AttestationVerificationError,
        exceptions.PolicyViolationError,
    ) as e:
      logging.warning("Client attestation failed: %r", e, exc_info=True)
      return _json_error(
          environ,
          start_response,
          "403 Forbidden",
          "Client attestation failed.",
      )

    except attestation_protocol.AttestationRequestError as e:
      logging.warning("Invalid attestation request: %r", e)
      return _json_error(
          environ,
          start_response,
          "400 Bad Request",
          "Invalid attestation request.",
      )

    except json_format.ParseError:
      logging.exception("Error parsing AttestConnectionRequest")
      return _json_error(
          environ, start_response, "400 Bad Request", "Invalid request"
      )

    except Exception:  # pylint: disable=broad-except
      logging.exception("Error during handling attest connection request")
      return _json_error(
          environ,
          start_response,
          "500 Internal Server Error",
          "Internal server error.",
      )


class _StandaloneApplication(gunicorn.app.base.BaseApplication):
  """Standalone Gunicorn application wrapper for programmatically running WSGI apps."""

  def __init__(self, app, options=None):
    self.application = app
    self.options = options or {}
    super().__init__()

  def load_config(self):
    for key, value in self.options.items():
      if key in self.cfg.settings and value is not None:
        self.cfg.set(key, value)

  def load(self):
    return self.application


def run_gunicorn_app(
    app: Any,
    *,
    key_manager: keys.KeyManager | None = None,
    token_manager: token.TokenManager | None = None,
    host: str = "0.0.0.0",
    port: int = 8443,
    workers: int = 1,
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
    client_policy: attestation_pb2.AttestationPolicy | None = None,
    require_mutual_attestation: bool = False,
    attested_tls_cls: type[attestation.AttestedTLS] = attestation.AttestedTLS,
    standalone_app_cls: type[gunicorn.app.base.BaseApplication] = (
        _StandaloneApplication
    ),
    **kwargs: Any,
) -> None:
  """Runs a WSGI app with PromptEncryptionWSGIMiddleware using Gunicorn.

  Args:
    app: The WSGI application to run.
    key_manager: An optional keys.KeyManager instance.
    token_manager: An optional token.TokenManager instance.
    host: Host to bind to.
    port: Port to bind to.
    workers: Number of workers.
    ssl_certfile: Path to SSL certificate file.
    ssl_keyfile: Path to SSL key file.
    client_policy: Policy used to verify confidential clients. Providing it
      enables mutual attestation. None means the server serves only server-only
      clients.
    require_mutual_attestation: Reject server-only clients.
    attested_tls_cls: Dependency injection for AttestedTLS class.
    standalone_app_cls: Dependency injection for StandaloneApplication class.
    **kwargs: Additional keyword arguments to pass to Gunicorn options.

  Raises:
    ValueError: If `require_mutual_attestation` is true without a
      `client_policy`.
  """
  if key_manager is None:
    key_manager = keys.KeyManager()
  if token_manager is None:
    token_manager = token.TokenManager(key_manager=key_manager)

  # Built before the token manager starts, so that invalid mutual settings
  # fail before any key or token is created.
  attested_tls = attested_tls_cls(
      token_manager,
      client_policy=client_policy,
      require_mutual_attestation=require_mutual_attestation,
  )
  middleware_app = PromptEncryptionWSGIMiddleware(app, attested_tls)
  with token_manager:
    options = {
        "bind": f"{host}:{port}",
        "workers": workers,
        # Use our Custom Worker to capture sockets.
        "worker_class": PromptEncryptionGunicornWorker,
        "certfile": ssl_certfile,
        "keyfile": ssl_keyfile,
        "accesslog": "-",
        "errorlog": "-",
    }
    options.update(kwargs)

    standalone_app_cls(middleware_app, options).run()
