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

import json
import logging
from typing import Any, Iterable
import weakref

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


def _patched_wsgi_create(req, *args, **kwargs):
  resp, environ = _original_create(req, *args, **kwargs)
  # Check if our Custom Worker attached the socket
  if hasattr(req, "confidential_socket"):
    environ["prompt_encryption.socket"] = req.confidential_socket
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
    self._attested_sockets = weakref.WeakSet()

  def __repr__(self):
    return f"<{self.__class__.__name__} app={self.app!r}>"

  def __call__(
      self, environ: dict[str, Any], start_response
  ) -> Iterable[bytes]:
    path = environ.get("PATH_INFO", "")

    if path == "/_attest-connection":
      return self.handle_attestation(environ, start_response)

    ssl_obj = environ.get("prompt_encryption.socket")
    # NOMUTANTS -- Equivalent mutation: None not in WeakSet evaluates to True.
    if not ssl_obj or ssl_obj not in self._attested_sockets:
      error_json = json.dumps(
          {"error": "Unauthorized: Connection must be attested first."}
      ).encode("utf-8")
      start_response(
          "401 Unauthorized",
          [
              ("Content-Type", "application/json"),
              ("Content-Length", str(len(error_json))),
          ],
      )
      return [error_json]

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
    try:
      body = self._parse_request(environ)

      try:
        parsed_json = json.loads(body.decode("utf-8") if body else "{}")
      except json.JSONDecodeError as e:
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

      # Get socket from environ (injected by our patched gunicorn/worker)
      ssl_obj = environ.get("prompt_encryption.socket")

      if not ssl_obj:
        raise RuntimeError(
            "TLS Socket not found. Server must be started via"
            " run_gunicorn_app()"
        )

      attestation_response_proto = self.attested_tls.attest_connection(
          req, ssl_obj=ssl_obj
      )
      self._attested_sockets.add(ssl_obj)
      attestation_response_dict = json_format.MessageToDict(
          attestation_response_proto
      )

      response_data = json.dumps(attestation_response_dict).encode("utf-8")

      start_response(
          "200 OK",
          [
              ("Content-Type", "application/json"),
              ("Content-Length", str(len(response_data))),
          ],
      )
      return [response_data]

    except json_format.ParseError:
      logging.exception("Error parsing AttestConnectionRequest")
      error_json = json.dumps({"error": "Invalid request"}).encode("utf-8")
      start_response(
          "400 Bad Request",
          [
              ("Content-Type", "application/json"),
              ("Content-Length", str(len(error_json))),
          ],
      )
      return [error_json]

    except (ValueError, TypeError, RuntimeError) as e:
      logging.exception("Error during handling attest connection request")
      error_json = json.dumps(
          {"error": f"An internal server error occurred: {repr(e)}"}
      ).encode("utf-8")
      start_response(
          "500 Internal Server Error",
          [
              ("Content-Type", "application/json"),
              ("Content-Length", str(len(error_json))),
          ],
      )
      return [error_json]


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
    app,
    *,
    key_manager: keys.KeyManager | None = None,
    token_manager: token.TokenManager | None = None,
    host: str = "0.0.0.0",
    port: int = 8443,
    workers: int = 1,
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
    attested_tls_cls: type[attestation.AttestedTLS] = attestation.AttestedTLS,
    standalone_app_cls: type[gunicorn.app.base.BaseApplication] = (
        _StandaloneApplication
    ),
    **kwargs,
):
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
    attested_tls_cls: Dependency injection for AttestedTLS class.
    standalone_app_cls: Dependency injection for StandaloneApplication class.
    **kwargs: Additional keyword arguments to pass to Gunicorn options.
  """
  if key_manager is None:
    key_manager = keys.KeyManager()
  if token_manager is None:
    token_manager = token.TokenManager(key_manager=key_manager)

  with token_manager:
    atls = attested_tls_cls(token_manager)
    middleware_app = PromptEncryptionWSGIMiddleware(app, atls)

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
