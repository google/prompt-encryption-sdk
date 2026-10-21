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

"""End-to-end mutual attestation over a real TLS session.

This drives the real client connection class against the real WSGI middleware
across a genuine TLS socket, so the Exported Keying Material both peers bind
to is produced by OpenSSL rather than a stub. Every ECDSA and ML-DSA signature
is really produced and really verified.

Only Google Cloud Attestation is faked: token issuance and its OIDC
verification require a live Confidential Space workload.
"""

import http.server
import io
import socket
import ssl
import sys
import threading
import urllib.parse

from absl.testing import absltest
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import connection
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation as server_attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import wsgi
from OpenSSL import crypto


_HOST = "localhost"
_RSA_KEY_SIZE = 2048
_CERT_SERIAL_NUMBER = 1000
_CERT_VALIDITY_SECONDS = 10 * 365 * 24 * 60 * 60
_APP_BODY = b'{"result": "ok"}'


class _Identity:
  """A stand-in TokenManager holding real keys and a fake GCA token."""

  def __init__(self, key_manager: keys.KeyManager, token: bytes):
    self.key_manager = key_manager
    self._token = token

  def get_identity_snapshot(self) -> tuple[bytes, bytes, bytes]:
    return (
        self.key_manager.get_current_public_key(),
        self.key_manager.get_current_pqc_public_key(),
        self._token,
    )


class _FakeOIDCValidator:
  """Returns pre-canned claims instead of verifying a real GCA token."""

  def __init__(self, claims_by_token):
    self._claims_by_token = claims_by_token

  def validate_token(self, token: str):
    try:
      return self._claims_by_token[token]
    except KeyError as e:
      raise exceptions.AttestationVerificationError("Unknown token.") from e

  def close(self):
    pass


def _claims_for(identity: _Identity):
  """Builds GCA claims that bind both public keys via eat_nonce."""
  return {
      "eat_nonce": [
          keys.calculate_fingerprint(
              identity.key_manager.get_current_public_key()
          ),
          keys.calculate_fingerprint(
              identity.key_manager.get_current_pqc_public_key()
          ),
      ],
      "submods": {"container": {}, "gce": {}},
  }


class _WSGIBridgeHandler(http.server.BaseHTTPRequestHandler):
  """Minimal keep-alive WSGI bridge that exposes the raw TLS socket.

  `wsgiref` closes the connection after every request, which would defeat the
  whole point of post-handshake attestation, so this hand-rolled handler is
  used instead. It mirrors what the Gunicorn worker patch does in production:
  put the live SSL socket into the WSGI environ.
  """

  protocol_version = "HTTP/1.1"

  def log_message(self, format, *args):  # pylint: disable=redefined-builtin
    del format, args  # Keep the test output clean.

  def do_GET(self):
    self._run_wsgi_app()

  def do_POST(self):
    self._run_wsgi_app()

  def _run_wsgi_app(self):
    content_length = int(self.headers.get("Content-Length") or 0)
    body = self.rfile.read(content_length) if content_length else b""
    environ = {
        "REQUEST_METHOD": self.command,
        "PATH_INFO": urllib.parse.urlparse(self.path).path,
        "QUERY_STRING": urllib.parse.urlparse(self.path).query,
        "SERVER_PROTOCOL": self.request_version,
        "CONTENT_LENGTH": str(content_length),
        "CONTENT_TYPE": self.headers.get("Content-Type", ""),
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": sys.stderr,
        "wsgi.url_scheme": "https",
        # The production Gunicorn worker injects this same key.
        "prompt_encryption.socket": self.connection,
    }

    captured = []

    def start_response(status, headers, exc_info=None):
      del exc_info
      captured.append((status, headers))
      return lambda data: None

    chunks = self.server.wsgi_app(environ, start_response)
    response_body = b"".join(chunks)
    status, headers = captured[0]
    code, _, reason = status.partition(" ")
    self.send_response_only(int(code), reason)
    for name, value in headers:
      # send_header sets close_connection when it sees "Connection: close".
      self.send_header(name, value)
    self.end_headers()
    self.wfile.write(response_body)


class _TLSWSGIServer(http.server.ThreadingHTTPServer):
  """Wraps every accepted connection in TLS before handling it."""

  daemon_threads = True

  def __init__(self, address, handler_cls, *, ssl_context, wsgi_app):
    self.ssl_context = ssl_context
    self.wsgi_app = wsgi_app
    super().__init__(address, handler_cls)

  def get_request(self):
    raw_sock, addr = super().get_request()
    return self.ssl_context.wrap_socket(raw_sock, server_side=True), addr

  def handle_error(self, request, client_address):
    del request, client_address  # Client-side teardown races are expected.


class MutualAttestationOverRealTlsTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.server_identity = self._make_identity("server", b"server-token")
    self.client_identity = self._make_identity("client", b"client-token")
    oidc = _FakeOIDCValidator({
        "server-token": _claims_for(self.server_identity),
        "client-token": _claims_for(self.client_identity),
    })
    self.validator_factory = lambda policy: validator.AttestationValidator(
        policy, oidc_validator=oidc
    )
    self.policy = attestation_pb2.AttestationPolicy()

    self.attested_tls = server_attestation.AttestedTLS(
        self.server_identity,
        client_policy=self.policy,
        require_mutual_attestation=True,
        attestation_validator_cls=self.validator_factory,
    )
    self.middleware = wsgi.PromptEncryptionWSGIMiddleware(
        self._app, self.attested_tls
    )
    self.port = self._start_server(self.middleware)

  def _app(self, unused_environ, start_response):
    start_response(
        "200 OK",
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(_APP_BODY))),
        ],
    )
    return [_APP_BODY]

  def _make_identity(self, name: str, token: bytes) -> _Identity:
    temp_dir = self.create_tempdir(name).full_path
    key_manager = keys.KeyManager(
        private_key_path=f"{temp_dir}/ecdsa-private.pem",
        public_key_path=f"{temp_dir}/ecdsa-public.pem",
        pqc_private_key_path=f"{temp_dir}/mldsa-private.bin",
        pqc_public_key_path=f"{temp_dir}/mldsa-public.bin",
    )
    key_manager.generate_key_pair()
    return _Identity(key_manager, token)

  def _start_server(self, wsgi_app) -> int:
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, _RSA_KEY_SIZE)
    cert = crypto.X509()
    cert.get_subject().CN = _HOST
    cert.set_serial_number(_CERT_SERIAL_NUMBER)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(_CERT_VALIDITY_SECONDS)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(pkey)
    cert.sign(pkey, "sha256")
    cert_file = self.create_tempfile(
        "server.crt", content=crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    )
    key_file = self.create_tempfile(
        "server.key", content=crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    )

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=cert_file.full_path, keyfile=key_file.full_path
    )

    server = _TLSWSGIServer(
        (_HOST, 0),
        _WSGIBridgeHandler,
        ssl_context=ssl_context,
        wsgi_app=wsgi_app,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    self.addCleanup(thread.join, 5.0)
    self.addCleanup(server.server_close)
    self.addCleanup(server.shutdown)
    return server.server_address[1]

  def _make_connection(self, **overrides):
    kwargs = dict(
        host=_HOST,
        port=self.port,
        policy=self.policy,
        mutual_attestation=True,
        attestation_prover=attestation_protocol.AttestationProver(
            self.client_identity
        ),
        attestation_validator_cls=self.validator_factory,
        cert_reqs="CERT_NONE",
        assert_hostname=False,
    )
    kwargs.update(overrides)
    conn = connection.AttestedHTTPSConnection(**kwargs)
    self.addCleanup(conn.close)
    return conn

  def test_one_round_trip_attests_both_peers_and_authorizes_traffic(self):
    conn = self._make_connection()

    conn.connect()

    with self.subTest("BothPeersAttested"):
      self.assertTrue(conn.is_attested)
    with self.subTest("ApplicationTrafficAuthorized"):
      conn.request("GET", "/infer")
      response = conn.getresponse()
      self.assertEqual(response.status, 200)
      self.assertEqual(response.data, _APP_BODY)

  def test_a_client_the_server_does_not_trust_is_rejected(self):
    """A real policy mismatch must fail the connection, not downgrade it."""
    self.attested_tls._client_policy = attestation_pb2.AttestationPolicy(
        gce_instance=attestation_pb2.GceInstancePolicy(project_id="trusted")
    )
    conn = self._make_connection()

    with self.assertRaises(exceptions.AttestationHandshakeError):
      conn.connect()

    self.assertFalse(conn.is_attested)

  def test_a_server_only_client_is_rejected_when_mutual_is_required(self):
    conn = self._make_connection(
        mutual_attestation=False, attestation_prover=None
    )

    with self.assertRaises(exceptions.AttestationHandshakeError):
      conn.connect()

  def test_re_attesting_the_same_session_drops_the_connection(self):
    conn = self._make_connection()
    conn.connect()
    conn.request("GET", "/infer")
    self.assertEqual(conn.getresponse().status, 200)

    # A client that ignores the no-revalidation rule and re-attests anyway.
    with self.assertRaises(exceptions.AttestationHandshakeError) as ctx:
      conn._perform_mutual_attestation()
    # _process_attestation_response re-wraps the status error, so the server's
    # refusal shows up as the chained cause.
    self.assertIn("403", str(ctx.exception.__cause__))

    with self.subTest("SessionNoLongerServesApplicationTraffic"):
      self.assertFalse(self._application_request_succeeds(conn))

  def test_client_side_revalidation_is_refused_before_it_reaches_the_wire(self):
    conn = self._make_connection()
    conn.connect()

    with self.assertRaisesRegex(
        exceptions.PromptEncryptionError, "cannot be revalidated"
    ):
      conn.revalidate_session()

    with self.subTest("SessionStillUsable"):
      self.assertTrue(self._application_request_succeeds(conn))

  def test_a_fresh_connection_re_attests_successfully(self):
    """Re-attestation is done by reconnecting, not by revalidating."""
    first = self._make_connection()
    first.connect()
    first.close()

    second = self._make_connection()
    second.connect()

    self.assertTrue(second.is_attested)
    self.assertTrue(self._application_request_succeeds(second))

  def _application_request_succeeds(self, conn) -> bool:
    """Returns whether an application request is served over this session."""
    try:
      conn.request("GET", "/infer")
      return conn.getresponse().status == 200
    except (
        exceptions.PromptEncryptionError,
        OSError,
        socket.error,
        ssl.SSLError,
        http.client.HTTPException,
    ):
      return False


if __name__ == "__main__":
  absltest.main()
