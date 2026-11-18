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

"""Mutual attestation over a real TLS session, on the WSGI and ASGI servers.

The real client connection talks to the real middleware over a real TLS socket,
so the keying material that both peers bind is produced by OpenSSL. Every ECDSA
and ML-DSA signature is really produced and verified. Google Cloud Attestation
is the only fake; see `mutual_testlib.FakeGca`.
"""

import http.client
import json
import math
import pathlib
import ssl
import time
from typing import Any
from unittest import mock

from absl.testing import absltest
from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.client import client as client_lib
from prompt_encryption_sdk.client import connection
from prompt_encryption_sdk.client import constants
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.ekm import exporter
from prompt_encryption_sdk.proto import attestation_pb2
import mutual_testlib
import tls_testlib
from google.protobuf import json_format
import requests


class _FakeOidcView:
  """Per-handshake FakeGca view that fails if reused after close()."""

  def __init__(
      self, gca: mutual_testlib.FakeGca, created: list["_FakeOidcView"]
  ):
    self._gca = gca
    self.closed = False
    created.append(self)

  def validate_token(
      self,
      token: str,
      *,
      expected_audience: str = constants.DEFAULT_AUDIENCE,
  ) -> dict[str, Any]:
    if self.closed:
      raise AssertionError("OIDCTokenValidator used after close().")
    return self._gca.validate_token(token, expected_audience=expected_audience)

  def close(self) -> None:
    self.closed = True


@absltest.skipThisClass("Shared tests. Subclasses set server_cls.")
class MutualAttestationTlsTestBase(absltest.TestCase):
  """Tests that run against both the WSGI server and the ASGI server."""

  server_cls: type[tls_testlib.WsgiTlsServer] | type[tls_testlib.AsgiTlsServer]

  def setUp(self):
    super().setUp()
    root = pathlib.Path(self.create_tempdir().full_path)
    self.gca = mutual_testlib.FakeGca()
    self.client_identity = mutual_testlib.make_token_manager(
        root / "client", self.gca
    )
    self.server = self.server_cls(
        mutual_testlib.make_token_manager(root / "server", self.gca),
        tls_testlib.make_tls_files(root / "tls"),
    )
    mutual_testlib.enable_mutual(
        self.server,
        self.gca,
        client_policy=attestation_pb2.AttestationPolicy(),
        require_mutual_attestation=True,
    )
    self.enter_context(self.server)

  def _connection(self, **overrides: Any) -> connection.AttestedHTTPSConnection:
    """Returns an unconnected real mutual client connection to the server."""
    kwargs: dict[str, Any] = {
        "host": tls_testlib.HOST,
        "port": self.server.port,
        "policy": attestation_pb2.AttestationPolicy(),
        "mutual_attestation": True,
        "attestation_prover": attestation_protocol.AttestationProver(
            self.client_identity
        ),
        "attestation_validator_cls": self.gca.validator_factory,
        "cert_reqs": "CERT_NONE",
        "assert_hostname": False,
        **overrides,
    }
    conn = connection.AttestedHTTPSConnection(**kwargs)
    self.addCleanup(conn.close)
    return conn

  def _assert_app_request_succeeds(
      self, conn: connection.AttestedHTTPSConnection
  ) -> None:
    """Sends an application request on `conn` and checks the response.

    A closed connection connects and attests again before the request.

    Args:
      conn: The client connection.
    """
    conn.request("GET", tls_testlib.APP_PATH)
    response = conn.getresponse()
    self.assertEqual(response.status, 200)
    self.assertEqual(response.data, tls_testlib.APP_BODY)

  def test_one_round_trip_attests_both_peers_and_authorizes_traffic(self):
    conn = self._connection()

    conn.connect()

    with self.subTest("BothPeersAttested"):
      self.assertTrue(conn.is_attested)
    with self.subTest("ExactlyOneAttestationExchange"):
      self.assertEqual(
          [exchange.status for exchange in self.server.recorder.attestations()],
          [200],
      )
    with self.subTest("ApplicationTrafficAuthorized"):
      conn.request("GET", tls_testlib.APP_PATH)
      response = conn.getresponse()
      self.assertEqual(response.status, 200)
      self.assertEqual(response.data, tls_testlib.APP_BODY)

  def test_a_client_the_server_does_not_trust_is_rejected(self):
    """A real policy mismatch must fail the connection, not downgrade it."""
    mutual_testlib.enable_mutual(
        self.server,
        self.gca,
        client_policy=attestation_pb2.AttestationPolicy(
            gce_instance=attestation_pb2.GceInstancePolicy(project_id="trusted")
        ),
        require_mutual_attestation=True,
    )
    conn = self._connection()

    with self.assertRaisesRegex(
        exceptions.AttestationHandshakeError,
        "Connection error reading response",
    ) as ctx:
      conn.connect()

    # The server returns a generic 403 without leaking expected policy values.
    cause = str(ctx.exception.__cause__)
    self.assertIn("403", cause)
    self.assertIn("Client attestation failed.", cause)
    self.assertNotIn("trusted", cause)
    self.assertFalse(conn.is_attested)

  def test_a_server_only_client_is_rejected_when_mutual_is_required(self):
    conn = self._connection(mutual_attestation=False, attestation_prover=None)

    with self.assertRaisesRegex(
        exceptions.AttestationHandshakeError,
        "Connection error reading response",
    ) as ctx:
      conn.connect()

    # The server returns a generic 400 without leaking exception text.
    cause = str(ctx.exception.__cause__)
    self.assertIn("400", cause)
    self.assertIn("Invalid attestation request.", cause)
    self.assertNotIn("requires mutual attestation", cause)
    self.assertFalse(conn.is_attested)

  def test_re_attesting_the_same_session_drops_the_connection(self):
    conn = self._connection()
    conn.connect()
    self._assert_app_request_succeeds(conn)

    # A client that ignores the no-revalidation rule and re-attests anyway.
    with self.assertRaisesRegex(
        exceptions.AttestationHandshakeError,
        "Connection error reading response",
    ) as ctx:
      conn._perform_mutual_attestation()
    # _process_attestation_response re-wraps the status error, so the server's
    # refusal shows up as the chained cause.
    self.assertIn("403", str(ctx.exception.__cause__))

    replayed = self.server.recorder.attestations()[-1]
    with self.subTest("ServerClosesTheConnection"):
      self.assertTrue(replayed.closes_connection)
    with self.subTest("TheNextRequestAttestsOnANewSession"):
      self._assert_app_request_succeeds(conn)
      self.assertIsNot(
          self.server.recorder.attestations()[-1].tls_socket,
          replayed.tls_socket,
      )
      self.assertIsNot(
          self.server.recorder.app_requests()[-1].tls_socket,
          replayed.tls_socket,
      )

  def test_client_side_revalidation_is_refused_before_it_reaches_the_wire(self):
    conn = self._connection()
    conn.connect()

    with self.assertRaisesRegex(
        exceptions.PromptEncryptionError, "cannot be revalidated"
    ):
      conn.revalidate_session()

    with self.subTest("NothingSent"):
      self.assertLen(self.server.recorder.attestations(), 1)
    with self.subTest("SessionStillUsable"):
      self._assert_app_request_succeeds(conn)

  def test_a_fresh_connection_re_attests_successfully(self):
    """Re-attestation is done by reconnecting, not by revalidating."""
    first = self._connection()
    first.connect()
    first.close()

    second = self._connection()
    second.connect()

    self.assertTrue(second.is_attested)
    self._assert_app_request_succeeds(second)

  def test_traffic_is_refused_once_the_client_token_expires(self):
    """The session lives exactly as long as the evidence that authorized it."""
    expires_at = math.ceil(time.time()) + 4
    mutual_testlib.reissue_token(
        self.client_identity, self.gca, expires_at=expires_at
    )
    conn = self._connection()
    conn.connect()

    with self.subTest("ServedWhileTheTokenIsValid"):
      self._assert_app_request_succeeds(conn)

    # The server compares time.time() with the expiry, so wait on that clock.
    deadline = time.monotonic() + 10
    while (remaining := expires_at - time.time()) > 0:
      self.assertLess(time.monotonic(), deadline)
      time.sleep(min(remaining + 0.02, 0.2))

    conn.request("GET", tls_testlib.APP_PATH)
    response = conn.getresponse()
    expired = self.server.recorder.app_requests()[-1]
    with self.subTest("RefusedAfterExpiry"):
      self.assertEqual(response.status, 401)
      self.assertIn("expired", response.data.decode("utf-8").lower())
    with self.subTest("ConnectionClosed"):
      self.assertTrue(expired.closes_connection)
      self.assertEqual(response.headers.get("Connection", "").lower(), "close")
      self.assertIsNone(conn.sock)

    with self.subTest("TheConnectionReconnectsWithAFreshToken"):
      mutual_testlib.reissue_token(self.client_identity, self.gca)
      self._assert_app_request_succeeds(conn)
      self.assertIsNot(
          self.server.recorder.app_requests()[-1].tls_socket,
          expired.tls_socket,
      )

  def test_a_pool_attests_mutually_and_retires_connections_near_expiry(self):
    """The pool keeps mutual mode, and never reuses a connection near expiry.

    The server accepts server-only clients too, so a pool that silently fell
    back to server-only attestation would still get 200 responses.
    """
    mutual_testlib.enable_mutual(
        self.server,
        self.gca,
        client_policy=attestation_pb2.AttestationPolicy(),
        require_mutual_attestation=False,
    )
    pool = connection.AttestedPoolManager(
        policy=attestation_pb2.AttestationPolicy(),
        mutual_attestation=True,
        attestation_prover=attestation_protocol.AttestationProver(
            self.client_identity
        ),
        attestation_validator_cls=self.gca.validator_factory,
        cert_reqs="CERT_NONE",
        assert_hostname=False,
    )
    self.addCleanup(pool.clear)
    url = f"https://{tls_testlib.HOST}:{self.server.port}{tls_testlib.APP_PATH}"

    def get_twice() -> list[int]:
      return [pool.request("GET", url, retries=False).status for _ in range(2)]

    with self.subTest("ReusesOneMutuallyAttestedConnection"):
      self.assertEqual(get_twice(), [200, 200])
      attestations = self.server.recorder.attestations()
      self.assertLen(attestations, 1)
      self.assertEqual(
          attestations[0].attestation_request().mode,
          attestation_pb2.ATTESTATION_MODE_MUTUAL,
      )

    with self.subTest("RetiresAConnectionInsideTheExpiryMargin"):
      pool.clear()
      # Valid for the server, but inside the client's 60 second margin.
      mutual_testlib.reissue_token(
          self.client_identity, self.gca, expires_at=time.time() + 30
      )
      self.assertEqual(get_twice(), [200, 200])
      new_attestations = self.server.recorder.attestations()[1:]
      self.assertLen(new_attestations, 2)
      self.assertIsNot(
          new_attestations[0].tls_socket, new_attestations[1].tls_socket
      )

  def test_client_session_attests_mutually_and_verifies_server_certificate(
      self,
  ):
    """PromptEncryptionClient.session() verifies the TLS cert and attests once."""
    views: list[_FakeOidcView] = []
    url = f"https://{tls_testlib.HOST}:{self.server.port}{tls_testlib.APP_PATH}"
    enc_client = client_lib.PromptEncryptionClient(
        attestation_pb2.AttestationPolicy(),
        mutual_attestation=True,
        client_token_manager=self.client_identity,
    )
    with mock.patch.object(
        validator,
        "OIDCTokenValidator",
        autospec=True,
        side_effect=lambda session=None: _FakeOidcView(self.gca, views),
    ):
      with enc_client.session() as session:
        with self.assertRaises(requests.exceptions.SSLError):
          session.post(url, json={"prompt": "hi"})
        self.assertEmpty(self.server.recorder.attestations())
        first = session.post(
            url, json={"prompt": "hi"}, verify=self.server.tls_files.certfile
        )
        second = session.post(
            url, json={"prompt": "hi"}, verify=self.server.tls_files.certfile
        )

    self.assertEqual((first.status_code, second.status_code), (200, 200))
    self.assertEqual(first.content, tls_testlib.APP_BODY)
    self.assertEqual(second.content, tls_testlib.APP_BODY)
    self.assertLen(views, 1)
    self.assertTrue(views[0].closed)
    attestations = self.server.recorder.attestations()
    self.assertLen(attestations, 1)
    self.assertEqual(
        attestations[0].attestation_request().mode,
        attestation_pb2.ATTESTATION_MODE_MUTUAL,
    )

  def test_the_client_refuses_tls_1_2_before_it_proves_itself(self):
    conn = self._connection(ssl_maximum_version=ssl.TLSVersion.TLSv1_2)

    with self.assertRaisesRegex(
        exceptions.AttestationHandshakeError, "requires TLSv1.3"
    ):
      conn.connect()

    with self.subTest("NothingSent"):
      self.assertEmpty(self.server.recorder.attestations())

  def test_the_server_refuses_a_mutual_request_over_tls_1_2(self):
    """A client without the TLS 1.3 check still gets no server proof."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    conn = http.client.HTTPSConnection(
        tls_testlib.HOST, self.server.port, context=context, timeout=10
    )
    self.addCleanup(conn.close)
    conn.connect()
    self.assertIsInstance(conn.sock, ssl.SSLSocket)
    self.assertEqual(conn.sock.version(), mutual_testlib.TLS_1_2)
    tls_ekm = exporter.export_keying_material(
        conn.sock,
        attestation_protocol.EKM_LENGTH,
        attestation_protocol.EKM_LABEL,
    )

    conn.request(
        "POST",
        tls_testlib.ATTESTATION_PATH,
        body=json_format.MessageToJson(
            mutual_testlib.mutual_request(self.client_identity, tls_ekm)
        ),
        headers={"Content-Type": "application/json"},
    )
    response = conn.getresponse()

    with self.subTest("Rejected"):
      self.assertEqual(response.status, 400)
    with self.subTest("NoServerProof"):
      body = json.loads(response.read())
      self.assertEqual(body, {"error": "Invalid attestation request."})


class WsgiMutualAttestationTlsTest(MutualAttestationTlsTestBase):
  server_cls = tls_testlib.WsgiTlsServer


class AsgiMutualAttestationTlsTest(MutualAttestationTlsTestBase):
  server_cls = tls_testlib.AsgiTlsServer


if __name__ == "__main__":
  absltest.main()
