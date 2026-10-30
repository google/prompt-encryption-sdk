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

"""Integration tests for the existing server-only mode over a real TLS session.

These tests run the real client against the WSGI and ASGI middleware, through
the hermetic test servers in `tls_testlib`.
"""

import pathlib
import time

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk.client import connection
from prompt_encryption_sdk.client import constants
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.proto import attestation_pb2
import tls_testlib

_SHORT_REVALIDATION_SECONDS = 1.0
_REVALIDATION_MARGIN_SECONDS = 0.2
_LONG_REVALIDATION_SECONDS = 3600


@absltest.skipThisClass("Shared tests. Subclasses set server_cls.")
class ServerOnlyTlsTestBase(parameterized.TestCase):
  """Tests that run against both the WSGI server and the ASGI server."""

  server_cls: type[tls_testlib.TlsServer]

  def setUp(self):
    super().setUp()
    self.root = pathlib.Path(self.create_tempdir().full_path)
    self.gca = tls_testlib.FakeGca()
    self.tls_files = tls_testlib.make_tls_files(self.root / "tls")
    self.server = self._start_server(
        tls_testlib.make_token_manager(self.root / "server", self.gca)
    )

  def _start_server(self, token_manager):
    return self.enter_context(self.server_cls(token_manager, self.tls_files))

  def _connection(self, server=None, **overrides):
    """Returns an unconnected real client connection to `server`."""
    server = server or self.server
    kwargs = dict(
        host=tls_testlib.HOST,
        port=server.port,
        policy=attestation_pb2.AttestationPolicy(),
        attestation_validator_cls=self.gca.validator_factory,
        revalidation_timeout=_LONG_REVALIDATION_SECONDS,
        cert_reqs="CERT_NONE",
        assert_hostname=False,
    )
    kwargs.update(overrides)
    conn = connection.AttestedHTTPSConnection(**kwargs)
    self.addCleanup(conn.close)
    return conn

  def _raw_connection(self, server=None):
    """Returns a plain TLS connection that never attests."""
    conn = tls_testlib.raw_https_connection((server or self.server).port)
    self.addCleanup(conn.close)
    return conn

  def _get_app(self, conn) -> int:
    conn.request("GET", tls_testlib.APP_PATH)
    response = conn.getresponse()
    self.assertEqual(response.data, tls_testlib.APP_BODY)
    return response.status

  def _raw_request(self, conn, method, path, body=None):
    """Sends one request and asserts that the server keeps the socket open."""
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    response.read()
    # For HTTP/1.1, will_close is set if any Connection header has "close".
    self.assertFalse(response.will_close)
    return response.status

  def _assert_no_recorded_response_closes_the_connection(self, server=None):
    for exchange in (server or self.server).recorder.exchanges():
      with self.subTest("NoConnectionClose", path=exchange.path):
        self.assertFalse(exchange.closes_connection, exchange.headers)

  def test_revalidation_attests_again_on_the_same_socket(self):
    ekm = tls_testlib.RecordingEkmExporter()
    conn = self._connection(
        ekm_exporter_fn=ekm, revalidation_timeout=_SHORT_REVALIDATION_SECONDS
    )
    conn.connect()
    client_socket = conn.sock
    self.assertEqual(self._get_app(conn), 200)

    time.sleep(_SHORT_REVALIDATION_SECONDS + _REVALIDATION_MARGIN_SECONDS)
    # The session is older than the revalidation time, so this request first
    # attests again on the same socket.
    self.assertEqual(self._get_app(conn), 200)
    self.assertEqual(self._get_app(conn), 200)

    attestations = self.server.recorder.attestations()
    self.assertLen(attestations, 2)
    first, second = attestations
    self.assertIsNotNone(first.tls_socket)
    self.assertIsNotNone(client_socket)
    nonces = [a.attestation_request().nonce for a in attestations]
    with self.subTest("SameServerSocket"):
      self.assertIs(second.tls_socket, first.tls_socket)
    with self.subTest("SameClientSocket"):
      self.assertIs(conn.sock, client_socket)
      self.assertLen(ekm.calls, 2)
      self.assertIs(ekm.calls[0].sock, client_socket)
      self.assertIs(ekm.calls[1].sock, client_socket)
    with self.subTest("ServerReturns200"):
      self.assertEqual([a.status for a in attestations], [200, 200])
    with self.subTest("ClientSendsNewNonce"):
      self.assertLen(nonces[0], constants.NONCE_LENGTH)
      self.assertLen(nonces[1], constants.NONCE_LENGTH)
      self.assertNotEqual(nonces[0], nonces[1])
    with self.subTest("ClientBindsEkmToTheNonceItSent"):
      self.assertEqual([c.context for c in ekm.calls], nonces)
    with self.subTest("EkmChanges"):
      self.assertNotEqual(ekm.calls[0].ekm, ekm.calls[1].ekm)
    with self.subTest("ApplicationRequestsContinueToWork"):
      app_requests = self.server.recorder.app_requests()
      self.assertEqual([r.status for r in app_requests], [200, 200, 200])
      for request in app_requests:
        self.assertIs(request.tls_socket, first.tls_socket)

  def test_pooled_connection_closed_by_server_reconnects_and_attests(self):
    ekm = tls_testlib.RecordingEkmExporter()
    pool = connection.AttestedPoolManager(
        policy=attestation_pb2.AttestationPolicy(),
        revalidation_timeout=_LONG_REVALIDATION_SECONDS,
        ekm_exporter_fn=ekm,
        attestation_validator_cls=self.gca.validator_factory,
        cert_reqs="CERT_NONE",
        assert_hostname=False,
    )
    self.addCleanup(pool.clear)
    url = f"https://{tls_testlib.HOST}:{self.server.port}{tls_testlib.APP_PATH}"

    first = pool.request("GET", url, retries=False)
    self.server.close_client_connections()
    # retries=False: the pool must notice the closed connection and open a
    # new one before it sends, not recover from a failed send.
    second = pool.request("GET", url, retries=False)

    with self.subTest("BothRequestsSucceed"):
      self.assertEqual((first.status, second.status), (200, 200))
      self.assertEqual(second.data, tls_testlib.APP_BODY)
    attestations = self.server.recorder.attestations()
    app_requests = self.server.recorder.app_requests()
    with self.subTest("AttestsAgain"):
      self.assertLen(attestations, 2)
      self.assertEqual([a.status for a in attestations], [200, 200])
    with self.subTest("NewServerConnection"):
      self.assertIsNotNone(attestations[0].tls_socket)
      self.assertIsNot(attestations[1].tls_socket, attestations[0].tls_socket)
    with self.subTest("NewClientConnection"):
      self.assertLen(ekm.calls, 2)
      self.assertIsNot(ekm.calls[1].sock, ekm.calls[0].sock)
      self.assertNotEqual(ekm.calls[1].ekm, ekm.calls[0].ekm)
    with self.subTest("EachRequestUsesItsAttestedConnection"):
      self.assertLen(app_requests, 2)
      self.assertIs(app_requests[0].tls_socket, attestations[0].tls_socket)
      self.assertIs(app_requests[1].tls_socket, attestations[1].tls_socket)

  def test_application_request_without_attestation_gets_401(self):
    conn = self._raw_connection()

    with self.subTest("FirstRequest"):
      self.assertEqual(
          self._raw_request(conn, "GET", tls_testlib.APP_PATH), 401
      )
    tls_socket = conn.sock
    with self.subTest("SameSocketStaysOpenAndUnauthorized"):
      self.assertEqual(
          self._raw_request(conn, "GET", tls_testlib.APP_PATH), 401
      )
      self.assertIs(conn.sock, tls_socket)
    with self.subTest("ApplicationNeverCalled"):
      self.assertEqual(
          [r.status for r in self.server.recorder.app_requests()], [401, 401]
      )

  @parameterized.named_parameters(
      ("NotJson", b"{not json"),
      ("JsonArray", b"[]"),
      ("WrongFieldType", b'{"nonce": 123}'),
  )
  def test_attestation_request_with_bad_json_gets_400(self, body):
    conn = self._raw_connection()

    self.assertEqual(
        self._raw_request(
            conn, "POST", tls_testlib.ATTESTATION_PATH, body=body
        ),
        400,
    )
    # The socket stays open and is still not attested.
    tls_socket = conn.sock
    self.assertEqual(self._raw_request(conn, "GET", tls_testlib.APP_PATH), 401)
    self.assertIs(conn.sock, tls_socket)

  def test_internal_error_during_attestation_gets_500(self):
    broken_server = self._start_server(
        tls_testlib.make_token_manager_without_keys(self.root / "broken")
    )

    with self.subTest("RawRequest"):
      conn = self._raw_connection(broken_server)
      self.assertEqual(
          self._raw_request(
              conn,
              "POST",
              tls_testlib.ATTESTATION_PATH,
              body=tls_testlib.attestation_request_json(),
          ),
          500,
      )
      # The socket stays open and is still not attested.
      tls_socket = conn.sock
      self.assertEqual(
          self._raw_request(conn, "GET", tls_testlib.APP_PATH), 401
      )
      self.assertIs(conn.sock, tls_socket)
    with self.subTest("ClientFailsTheHandshake"):
      attestations_before = len(broken_server.recorder.attestations())
      client = self._connection(broken_server)
      with self.assertRaises(exceptions.AttestationHandshakeError):
        client.connect()
      self.assertFalse(client.is_attested)
      new_attestations = broken_server.recorder.attestations()[
          attestations_before:
      ]
      self.assertEqual([a.status for a in new_attestations], [500])
    # The client path above does not go through _raw_request.
    self._assert_no_recorded_response_closes_the_connection(broken_server)

  def test_no_server_only_response_closes_the_connection(self):
    conn = self._connection(revalidation_timeout=_SHORT_REVALIDATION_SECONDS)
    conn.connect()
    self.assertEqual(self._get_app(conn), 200)
    time.sleep(_SHORT_REVALIDATION_SECONDS + _REVALIDATION_MARGIN_SECONDS)
    self.assertEqual(self._get_app(conn), 200)
    raw = self._raw_connection()
    self.assertEqual(self._raw_request(raw, "GET", tls_testlib.APP_PATH), 401)
    self.assertEqual(
        self._raw_request(
            raw, "POST", tls_testlib.ATTESTATION_PATH, body=b"{not json"
        ),
        400,
    )

    exchanges = self.server.recorder.exchanges()
    with self.subTest("AllStatusesSeen"):
      self.assertEqual(
          sorted({(e.is_attestation, e.status) for e in exchanges}),
          [(False, 200), (False, 401), (True, 200), (True, 400)],
      )
    self._assert_no_recorded_response_closes_the_connection()


class WsgiServerOnlyTlsTest(ServerOnlyTlsTestBase):
  server_cls = tls_testlib.WsgiTlsServer


class AsgiServerOnlyTlsTest(ServerOnlyTlsTestBase):
  server_cls = tls_testlib.AsgiTlsServer


if __name__ == "__main__":
  absltest.main()
