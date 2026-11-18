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

"""Integration tests for reusing a closed client connection over real TLS.

These tests run the real client against the WSGI and ASGI middleware, through
the hermetic test servers in `tls_testlib`.
"""

import pathlib
import time

from absl.testing import absltest
from prompt_encryption_sdk.client import connection
from prompt_encryption_sdk.proto import attestation_pb2
import tls_testlib

_SHORT_REVALIDATION_SECONDS = 1.0
_REVALIDATION_MARGIN_SECONDS = 0.2


@absltest.skipThisClass("Shared tests. Subclasses set server_cls.")
class ClosedConnectionTlsTestBase(absltest.TestCase):
  """Tests that run against both the WSGI server and the ASGI server."""

  server_cls: type[tls_testlib.TlsServer]

  def setUp(self):
    super().setUp()
    root = pathlib.Path(self.create_tempdir().full_path)
    self.gca = tls_testlib.FakeGca()
    self.server = self.enter_context(
        self.server_cls(
            tls_testlib.make_token_manager(root / "server", self.gca),
            tls_testlib.make_tls_files(root / "tls"),
        )
    )

  def _get_app(self, conn: connection.AttestedHTTPSConnection) -> int:
    conn.request("GET", tls_testlib.APP_PATH)
    response = conn.getresponse()
    self.assertEqual(response.data, tls_testlib.APP_BODY)
    return response.status

  def test_closed_connection_reconnects_after_the_revalidation_time(self):
    ekm = tls_testlib.RecordingEkmExporter()
    conn = connection.AttestedHTTPSConnection(
        host=tls_testlib.HOST,
        port=self.server.port,
        policy=attestation_pb2.AttestationPolicy(),
        attestation_validator_cls=self.gca.validator_factory,
        ekm_exporter_fn=ekm,
        revalidation_timeout=_SHORT_REVALIDATION_SECONDS,
        cert_reqs="CERT_NONE",
        assert_hostname=False,
    )
    self.addCleanup(conn.close)
    conn.connect()
    self.assertEqual(self._get_app(conn), 200)

    # http.client closes a connection in the same way after a response with
    # `Connection: close`. The next request must reconnect and attest on the
    # new socket, not revalidate the closed one.
    conn.close()
    time.sleep(_SHORT_REVALIDATION_SECONDS + _REVALIDATION_MARGIN_SECONDS)

    self.assertEqual(self._get_app(conn), 200)
    attestations = self.server.recorder.attestations()
    self.assertLen(attestations, 2)
    with self.subTest("AttestsAgain"):
      self.assertEqual(
          [exchange.status for exchange in attestations], [200, 200]
      )
    with self.subTest("OnANewConnection"):
      self.assertIsNot(attestations[1].tls_socket, attestations[0].tls_socket)
      self.assertLen(ekm.calls, 2)
      self.assertIsNot(ekm.calls[1].sock, ekm.calls[0].sock)


class WsgiClosedConnectionTlsTest(ClosedConnectionTlsTestBase):
  server_cls = tls_testlib.WsgiTlsServer


class AsgiClosedConnectionTlsTest(ClosedConnectionTlsTestBase):
  server_cls = tls_testlib.AsgiTlsServer


if __name__ == "__main__":
  absltest.main()
