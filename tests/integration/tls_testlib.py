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

"""Hermetic test servers for the integration tests.

A hermetic test server is a real TLS server with the real Prompt Encryption
middleware in front of a small application. It runs in the test process and
uses only localhost, temporary files, and a fake GCA. Tests talk to it with the
real client over a real TLS 1.3 session.

Google Cloud Attestation (GCA) is the only fake, because a real token needs a
live Confidential Space workload.

The SDK has no public API that gives the TLS socket to the middleware. So the
test servers use the same keys as the SDK servers:
- WSGI: `environ["prompt_encryption.socket"]`, which the Gunicorn worker sets.
- ASGI: `scope["extensions"]["tls_socket"]`, which `asgi.TlsInjectorProtocol`
  sets. The test server also reads it to record the TLS session of each
  request.
"""

import abc
import asyncio
from collections.abc import Callable
import dataclasses
import datetime
import http.client
import http.server
import io
import pathlib
import secrets
import socket
import ssl
import sys
import threading
import time
import types
from typing import Any, cast
import urllib.parse

from prompt_encryption_sdk.client import constants
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.ekm import exporter
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import asgi
from prompt_encryption_sdk.server import attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token
from prompt_encryption_sdk.server import wsgi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf import json_format
import jwt
import uvicorn

HOST = "localhost"
APP_PATH = "/infer"
APP_BODY = b'{"result": "ok"}'
ATTESTATION_PATH = constants.ATTESTATION_ENDPOINT

_CERT_VALIDITY = datetime.timedelta(days=1)
_CERT_CLOCK_SKEW = datetime.timedelta(minutes=5)
_FAKE_GCA_ALGORITHM = "HS256"
_TOKEN_LIFETIME_SECONDS = 3600
_TOKEN_FILENAME = "attestation_token.txt"
_TIMEOUT_SECONDS = 10.0
_POLL_INTERVAL_SECONDS = 0.01


def _wait_until(condition: Callable[[], bool], what: str) -> None:
  """Polls `condition` until it is true, or raises TimeoutError."""
  deadline = time.monotonic() + _TIMEOUT_SECONDS
  while not condition():
    if time.monotonic() > deadline:
      raise TimeoutError(f"Timed out waiting for {what}.")
    time.sleep(_POLL_INTERVAL_SECONDS)


class FakeGca:
  """Stands in for Google Cloud Attestation (GCA).

  It plays both GCA roles. For the server, it issues the token that the
  TokenManager would get from the TEE server. For the client, it is the OIDC
  validator that `validator.AttestationValidator` accepts in its constructor.
  Tokens are real JWTs that a per-instance secret signs, so the client still
  rejects a token that this fake did not issue, a token for another audience,
  and an expired token.
  """

  def __init__(self):
    self._secret = secrets.token_bytes(32)

  def __repr__(self) -> str:
    return "FakeGca()"

  def issue_token(
      self,
      key_manager: keys.KeyManager,
      *,
      audience: str = constants.DEFAULT_AUDIENCE,
  ) -> bytes:
    """Issues a token that binds the current keys of `key_manager`.

    Args:
      key_manager: Holds the ECDSA and ML-DSA public keys to bind.
      audience: The `aud` claim.

    Returns:
      The token, in the same form that the TEE server returns it.
    """
    now = int(time.time())
    claims = {
        "iss": constants.CS_DEFAULT_ISSUER,
        "aud": audience,
        "iat": now,
        "exp": now + _TOKEN_LIFETIME_SECONDS,
        "eat_nonce": [
            keys.calculate_fingerprint(key_manager.get_current_public_key()),
            keys.calculate_fingerprint(
                key_manager.get_current_pqc_public_key()
            ),
        ],
        "swname": "CONFIDENTIAL_SPACE",
        "submods": {"container": {}, "gce": {}, "confidential_space": {}},
    }
    encoded = jwt.encode(
        claims,
        self._secret,
        algorithm=_FAKE_GCA_ALGORITHM,
        headers={"typ": "JWT"},
    )
    return encoded.encode("utf-8")

  # The parameter is `token_str`, not `token` as in OIDCTokenValidator, so that
  # it does not shadow the `token` module. AttestationValidator passes the token
  # by position.
  def validate_token(
      self,
      token_str: str,
      *,
      expected_audience: str = constants.DEFAULT_AUDIENCE,
  ) -> dict[str, Any]:
    """Verifies a token like `validator.OIDCTokenValidator.validate_token`.

    Args:
      token_str: The raw JWT.
      expected_audience: The `aud` claim that the token must have.

    Returns:
      The verified claims.

    Raises:
      exceptions.AttestationVerificationError: If this fake did not issue the
        token, or if the token is expired, is for another audience or issuer,
        or does not have the `typ: JWT` header.
    """
    try:
      if jwt.get_unverified_header(token_str).get("typ") != "JWT":
        raise jwt.InvalidTokenError("The typ header is not JWT.")
      return jwt.decode(
          token_str,
          self._secret,
          algorithms=[_FAKE_GCA_ALGORITHM],
          audience=expected_audience,
          issuer=constants.CS_DEFAULT_ISSUER,
      )
    except jwt.InvalidTokenError as e:
      raise exceptions.AttestationVerificationError(
          "OIDC Token validation failed."
      ) from e

  def close(self) -> None:
    """Matches `validator.OIDCTokenValidator.close`."""

  def validator_factory(
      self, policy: attestation_pb2.AttestationPolicy
  ) -> validator.AttestationValidator:
    """Use as `attestation_validator_cls` on the client connection classes."""
    oidc_validator = cast(validator.OIDCTokenValidator, self)
    return validator.AttestationValidator(policy, oidc_validator=oidc_validator)


def make_token_manager(
    directory: pathlib.Path, gca: FakeGca
) -> token.TokenManager:
  """Makes a real TokenManager with real keys and a token from `gca`.

  The test never enters the TokenManager, so it never calls the TEE server.
  Instead, this function writes the token file that `TokenManager.refresh()`
  writes after it gets a token.

  Args:
    directory: An empty directory for the key and token files.
    gca: Issues the attestation token.

  Returns:
    A TokenManager that can serve attestation requests.
  """
  directory.mkdir(parents=True, exist_ok=True)
  key_manager = _make_key_manager(directory)
  key_manager.generate_key_pair()
  token_path = directory / _TOKEN_FILENAME
  token_manager = token.TokenManager(
      key_manager=key_manager, attestation_token_path=token_path
  )
  token_path.write_bytes(
      gca.issue_token(key_manager, audience=token_manager.audience)
  )
  return token_manager


def make_token_manager_without_keys(
    directory: pathlib.Path,
) -> token.TokenManager:
  """Makes a real TokenManager whose key files do not exist.

  The server fails with an internal error when it tries to read the keys to
  answer an attestation request.

  Args:
    directory: An empty directory. The key files are never created in it.

  Returns:
    A TokenManager that cannot serve attestation requests.
  """
  directory.mkdir(parents=True, exist_ok=True)
  return token.TokenManager(
      key_manager=_make_key_manager(directory),
      attestation_token_path=directory / _TOKEN_FILENAME,
  )


def _make_key_manager(directory: pathlib.Path) -> keys.KeyManager:
  return keys.KeyManager(
      private_key_path=directory / "ecdsa_private.pem",
      public_key_path=directory / "ecdsa_public.pem",
      pqc_private_key_path=directory / "mldsa_private.bin",
      pqc_public_key_path=directory / "mldsa_public.bin",
  )


@dataclasses.dataclass(frozen=True)
class TlsFiles:
  """Paths of a self-signed server certificate and its private key.

  Attributes:
    certfile: The PEM certificate for `HOST`.
    keyfile: The PEM private key of the certificate.
  """

  certfile: str
  keyfile: str


def make_tls_files(directory: pathlib.Path) -> TlsFiles:
  """Writes a self-signed certificate for `HOST` and its key to `directory`."""
  directory.mkdir(parents=True, exist_ok=True)
  key = ec.generate_private_key(ec.SECP256R1())
  name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, HOST)])
  now = datetime.datetime.now(datetime.timezone.utc)
  cert = (
      x509.CertificateBuilder()
      .subject_name(name)
      .issuer_name(name)
      .public_key(key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(now - _CERT_CLOCK_SKEW)
      .not_valid_after(now + _CERT_VALIDITY)
      .add_extension(
          x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False
      )
      .sign(key, hashes.SHA256())
  )
  certfile = directory / "server.crt"
  keyfile = directory / "server.key"
  certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
  keyfile.write_bytes(
      key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.PKCS8,
          encryption_algorithm=serialization.NoEncryption(),
      )
  )
  return TlsFiles(certfile=str(certfile), keyfile=str(keyfile))


@dataclasses.dataclass(frozen=True)
class Exchange:
  """One request that reached the server and the response that it sent.

  Attributes:
    method: The HTTP method.
    path: The request path.
    body: The request body.
    tls_socket: The server-side TLS object of the connection. Two exchanges came
      over the same TLS session if and only if they have the same object.
    status: The response status code.
    headers: The response headers, with lowercase names, in order. A header that
      appears more than once has more than one entry.
  """

  method: str
  path: str
  body: bytes
  tls_socket: Any
  status: int
  headers: tuple[tuple[str, str], ...]

  @property
  def is_attestation(self) -> bool:
    """Whether this exchange is an attestation request."""
    return self.path == ATTESTATION_PATH

  @property
  def closes_connection(self) -> bool:
    """Whether any `Connection` response header has the `close` token."""
    for name, value in self.headers:
      if name == "connection" and "close" in (
          t.strip().lower() for t in value.split(",")
      ):
        return True
    return False

  def attestation_request(self) -> attestation_pb2.AttestConnectionRequest:
    """Parses the body of an attestation request."""
    return json_format.Parse(
        self.body.decode("utf-8"), attestation_pb2.AttestConnectionRequest()
    )


class ExchangeRecorder:
  """Thread-safe log of every exchange that reached the server."""

  def __init__(self):
    self._lock = threading.Lock()
    self._exchanges: list[Exchange] = []

  def __repr__(self) -> str:
    return f"ExchangeRecorder(exchanges={len(self.exchanges())})"

  def add(self, exchange: Exchange) -> None:
    """Appends `exchange` to the log."""
    with self._lock:
      self._exchanges.append(exchange)

  def exchanges(self) -> list[Exchange]:
    """Returns a snapshot of all exchanges, oldest first."""
    with self._lock:
      return list(self._exchanges)

  def attestations(self) -> list[Exchange]:
    """Returns a snapshot of the attestation exchanges, oldest first."""
    return [e for e in self.exchanges() if e.is_attestation]

  def app_requests(self) -> list[Exchange]:
    """Returns a snapshot of the other exchanges, oldest first."""
    return [e for e in self.exchanges() if not e.is_attestation]


class TlsServer(abc.ABC):
  """A real TLS server with the real middleware, run in a background thread.

  Use it as a context manager. The middleware wraps an application that
  answers every request with 200 and `APP_BODY`.

  Attributes:
    attested_tls: The real `attestation.AttestedTLS` behind the middleware.
    tls_files: The server certificate and key.
    port: The port that the server listens on.
    recorder: Records each exchange as it reaches the middleware.
  """

  def __init__(self, token_manager: token.TokenManager, tls_files: TlsFiles):
    self.attested_tls = attestation.AttestedTLS(token_manager)
    self.tls_files = tls_files
    self.recorder = ExchangeRecorder()
    self.port = 0

  def __repr__(self) -> str:
    return f"{type(self).__name__}(port={self.port})"

  def __enter__(self) -> "TlsServer":
    self.start()
    return self

  def __exit__(
      self,
      exc_type: type[BaseException] | None,
      exc_val: BaseException | None,
      exc_tb: types.TracebackType | None,
  ) -> None:
    self.stop()

  @abc.abstractmethod
  def start(self) -> None:
    """Starts the server and returns when it accepts connections."""

  @abc.abstractmethod
  def stop(self) -> None:
    """Stops the server."""

  @abc.abstractmethod
  def close_client_connections(self) -> None:
    """Closes every open client connection from the server side.

    Returns after the server has closed each connection.
    """


def _wsgi_app(environ, start_response):
  """Answers every request with 200 and `APP_BODY`."""
  del environ
  start_response(
      "200 OK",
      [
          ("Content-Type", "application/json"),
          ("Content-Length", str(len(APP_BODY))),
      ],
  )
  return [APP_BODY]


class _WsgiBridgeHandler(http.server.BaseHTTPRequestHandler):
  """Minimal keep-alive WSGI bridge that exposes the raw TLS socket.

  `wsgiref` closes the connection after every request, which would defeat the
  whole point of post-handshake attestation, so this hand-rolled handler is
  used instead. It mirrors what the Gunicorn worker patch does in production:
  put the live SSL socket into the WSGI environ.
  """

  protocol_version = "HTTP/1.1"
  server: "_TlsWsgiHttpServer"

  def log_message(self, format, *args):  # pylint: disable=redefined-builtin
    del format, args  # Keep the test output clean.

  def setup(self):
    super().setup()
    self.server.track_connection(self.connection)

  def finish(self):
    try:
      super().finish()
    finally:
      self.server.untrack_connection(self.connection)

  def do_GET(self):  # pylint: disable=invalid-name
    self._run_wsgi_app()

  def do_POST(self):  # pylint: disable=invalid-name
    self._run_wsgi_app()

  def _environ(self, url: urllib.parse.ParseResult, body: bytes):
    """Builds a PEP 3333 environ, as Gunicorn does."""
    server_name, server_port = self.server.server_address[:2]
    environ = {
        "REQUEST_METHOD": self.command,
        "SCRIPT_NAME": "",
        "PATH_INFO": url.path,
        "QUERY_STRING": url.query,
        "SERVER_NAME": server_name,
        "SERVER_PORT": str(server_port),
        "SERVER_PROTOCOL": self.request_version,
        "REMOTE_ADDR": self.client_address[0],
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": self.headers.get("Content-Type", ""),
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "https",
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": sys.stderr,
        "wsgi.multithread": True,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "prompt_encryption.socket": self.connection,
    }
    for name, value in self.headers.items():
      key = name.upper().replace("-", "_")
      if key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
        continue
      key = "HTTP_" + key
      environ[key] = f"{environ[key]},{value}" if key in environ else value
    return environ

  def _run_wsgi_app(self):
    """Runs one request through the WSGI app and records the exchange."""
    content_length = int(self.headers.get("Content-Length") or 0)
    body = self.rfile.read(content_length) if content_length else b""
    url = urllib.parse.urlparse(self.path)

    captured = []

    def start_response(status, headers, exc_info=None):
      del exc_info  # The bridge buffers the body, so it can always restart.
      captured.append((status, headers))
      return lambda data: None

    chunks = self.server.wsgi_app(self._environ(url, body), start_response)
    try:
      response_body = b"".join(chunks)
    finally:
      close = getattr(chunks, "close", None)
      if close is not None:
        close()
    status, headers = captured[-1]
    code, _, reason = status.partition(" ")
    # Record before the response goes out, so the exchange is visible as soon
    # as the client has the response.
    self.server.recorder.add(
        Exchange(
            method=self.command,
            path=url.path,
            body=body,
            tls_socket=self.connection,
            status=int(code),
            headers=tuple((name.lower(), value) for name, value in headers),
        )
    )
    self.send_response_only(int(code), reason)
    for name, value in headers:
      # send_header sets close_connection when it sees "Connection: close".
      self.send_header(name, value)
    self.end_headers()
    self.wfile.write(response_body)


class _TlsWsgiHttpServer(http.server.ThreadingHTTPServer):
  """Threaded HTTP server that tracks its open connections."""

  daemon_threads = True

  def __init__(self, address, handler_cls, *, wsgi_app, recorder):
    self.wsgi_app = wsgi_app
    self.recorder = recorder
    self._connections_lock = threading.Lock()
    self._connections = set()
    super().__init__(address, handler_cls)

  def handle_error(self, request, client_address):
    # A client or a test can close a connection at any time, so connection
    # errors are expected. Report anything else, such as a bug in the bridge.
    if not isinstance(sys.exc_info()[1], OSError):
      super().handle_error(request, client_address)

  def track_connection(self, conn) -> None:
    with self._connections_lock:
      self._connections.add(conn)

  def untrack_connection(self, conn) -> None:
    with self._connections_lock:
      self._connections.discard(conn)

  def open_connections(self) -> list[Any]:
    with self._connections_lock:
      return list(self._connections)


class WsgiTlsServer(TlsServer):
  """Real `PromptEncryptionWSGIMiddleware` behind an `http.server` bridge.

  The bridge stands in for Gunicorn. It does not test
  `PromptEncryptionGunicornWorker`; the e2e tests cover that path.
  """

  def __init__(self, token_manager: token.TokenManager, tls_files: TlsFiles):
    super().__init__(token_manager, tls_files)
    self.middleware = wsgi.PromptEncryptionWSGIMiddleware(
        _wsgi_app, self.attested_tls
    )
    self._server: _TlsWsgiHttpServer | None = None
    self._thread: threading.Thread | None = None

  def start(self) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=self.tls_files.certfile, keyfile=self.tls_files.keyfile
    )
    self._server = _TlsWsgiHttpServer(
        (HOST, 0),
        _WsgiBridgeHandler,
        wsgi_app=self.middleware,
        recorder=self.recorder,
    )
    # Each accepted connection does the TLS handshake before it is handled.
    self._server.socket = ssl_context.wrap_socket(
        self._server.socket, server_side=True
    )
    self.port = self._server.server_address[1]
    self._thread = threading.Thread(
        target=self._server.serve_forever, daemon=True
    )
    self._thread.start()

  def stop(self) -> None:
    if self._server is None or self._thread is None:
      return
    self._server.shutdown()
    self._server.server_close()
    self._thread.join(_TIMEOUT_SECONDS)

  def close_client_connections(self) -> None:
    assert self._server is not None
    server = self._server
    for conn in server.open_connections():
      # Shut down the TCP socket under the TLS layer. The handler thread then
      # reads EOF and closes the connection, as it does for an idle timeout.
      # This calls socket.socket.shutdown because SSLSocket.shutdown also sets
      # the SSL object to None, which races with the handler thread that is
      # reading from it.
      try:
        socket.socket.shutdown(conn, socket.SHUT_RDWR)
      except OSError:
        pass  # The connection closed on its own already.
    _wait_until(
        lambda: not server.open_connections(), "the server to close connections"
    )


class _RecordingAsgiApp:
  """Records each exchange as it passes into the ASGI middleware."""

  def __init__(self, inner, recorder: ExchangeRecorder):
    self._inner = inner
    self._recorder = recorder

  async def __call__(self, scope, receive, send):
    if scope["type"] != "http":
      await self._inner(scope, receive, send)
      return

    body_parts = []

    async def recording_receive():
      message = await receive()
      if message["type"] == "http.request":
        body_parts.append(message.get("body", b""))
      return message

    async def recording_send(message):
      if message["type"] == "http.response.start":
        # Record before the response goes out, so the exchange is visible as
        # soon as the client has the response.
        self._recorder.add(
            Exchange(
                method=scope["method"],
                path=scope["path"],
                body=b"".join(body_parts),
                tls_socket=scope.get("extensions", {}).get("tls_socket"),
                status=message["status"],
                headers=tuple(
                    (name.decode("latin-1").lower(), value.decode("latin-1"))
                    for name, value in message.get("headers", [])
                ),
            )
        )
      await send(message)

    await self._inner(scope, recording_receive, recording_send)


async def _asgi_app(scope, receive, send):
  """Answers every HTTP request with 200 and `APP_BODY`."""
  del receive
  assert scope["type"] == "http"
  await send({
      "type": "http.response.start",
      "status": 200,
      "headers": [
          (b"content-type", b"application/json"),
          (b"content-length", str(len(APP_BODY)).encode("ascii")),
      ],
  })
  await send({"type": "http.response.body", "body": APP_BODY})


class AsgiTlsServer(TlsServer):
  """Real `PromptEncryptionASGIMiddleware` served by uvicorn.

  Uses `asgi.TlsInjectorProtocol`, as `run_uvicorn_app` does.
  """

  def __init__(self, token_manager: token.TokenManager, tls_files: TlsFiles):
    super().__init__(token_manager, tls_files)
    self.middleware = asgi.PromptEncryptionASGIMiddleware(
        _asgi_app, self.attested_tls
    )
    self._server: uvicorn.Server | None = None
    self._loop: asyncio.AbstractEventLoop | None = None
    self._thread: threading.Thread | None = None

  def start(self) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    self.port = sock.getsockname()[1]
    config = uvicorn.Config(
        _RecordingAsgiApp(self.middleware, self.recorder),
        http=asgi.TlsInjectorProtocol,
        interface="asgi3",
        lifespan="off",
        log_config=None,
        access_log=False,
        ssl_certfile=self.tls_files.certfile,
        ssl_keyfile=self.tls_files.keyfile,
        timeout_graceful_shutdown=int(_TIMEOUT_SECONDS),
    )
    server = uvicorn.Server(config)
    loop = asyncio.new_event_loop()
    self._server = server
    self._loop = loop

    def serve():
      asyncio.set_event_loop(loop)
      try:
        loop.run_until_complete(server.serve(sockets=[sock]))
      finally:
        sock.close()
        loop.close()

    self._thread = threading.Thread(target=serve, daemon=True)
    self._thread.start()
    _wait_until(
        lambda: server.started or not self._thread.is_alive(),
        "uvicorn to start",
    )
    if not server.started:
      raise RuntimeError("uvicorn failed to start.")

  def stop(self) -> None:
    if self._server is None or self._thread is None:
      return
    self._server.should_exit = True
    self._thread.join(_TIMEOUT_SECONDS)
    if self._thread.is_alive():
      self._server.force_exit = True
      self._thread.join(_TIMEOUT_SECONDS)

  def close_client_connections(self) -> None:
    assert self._server is not None and self._loop is not None
    server_state = self._server.server_state

    async def abort_all():
      for conn in list(server_state.connections):
        # abort() closes the TCP socket at once. close() would first wait up
        # to 30 seconds for the client to answer the TLS close_notify.
        conn.transport.abort()
      while server_state.connections:
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)

    asyncio.run_coroutine_threadsafe(abort_all(), self._loop).result(
        _TIMEOUT_SECONDS
    )


class RecordingEkmExporter:
  """Real EKM exporter for the client that records each export.

  Pass it to the client connection classes as `ekm_exporter_fn`.

  This class is not thread-safe, so use each instance from one thread only.
  The client calls it during the attestation handshake, on the thread that
  calls `connect()` or `request()`, and these tests make every request from
  the test thread. `ExchangeRecorder` has a lock because server threads write
  to it while the test thread reads it.

  Attributes:
    calls: One `EkmExport` for each export, in order.
  """

  @dataclasses.dataclass(frozen=True)
  class EkmExport:
    sock: Any
    context: bytes | None
    ekm: bytes

  def __init__(self):
    self.calls: list[RecordingEkmExporter.EkmExport] = []

  def __repr__(self) -> str:
    return f"RecordingEkmExporter(calls={len(self.calls)})"

  def __call__(
      self,
      sock: ssl.SSLSocket,
      length: int,
      label: bytes,
      context: bytes | None = None,
  ) -> bytes:
    ekm = exporter.export_keying_material(sock, length, label, context=context)
    self.calls.append(self.EkmExport(sock=sock, context=context, ekm=ekm))
    return ekm


def raw_https_connection(port: int) -> http.client.HTTPSConnection:
  """Returns a plain TLS connection that never sends an attestation request."""
  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  return http.client.HTTPSConnection(
      HOST, port, context=context, timeout=_TIMEOUT_SECONDS
  )


def attestation_request_json() -> str:
  """Returns a valid server-only attestation request, as the client sends it."""
  return json_format.MessageToJson(
      attestation_pb2.AttestConnectionRequest(
          required_verifier_type=[
              attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
          ],
          nonce=secrets.token_bytes(constants.NONCE_LENGTH),
      )
  )
