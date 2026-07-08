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

"""Integration tests exercising the full C extension stack with real TLS."""

import socket
import ssl
import threading

from prompt_encryption_sdk.ekm import exporter
from OpenSSL import crypto

from absl.testing import absltest as googletest


_HOST = "localhost"
_LABEL = b"experimental-test-label"
_EKM_LENGTH = 32
_HANDSHAKE_TRIGGER = b"x"
_READ_BUFFER_SIZE = 1024
_RSA_KEY_SIZE = 2048
_CERT_SERIAL_NUMBER = 1000
_CERT_VALIDITY_SECONDS = 10 * 365 * 24 * 60 * 60


class EKMIntegrationTest(googletest.TestCase):

  def setUp(self) -> None:
    """Sets up a hermetic TLS server and client for each test."""
    super().setUp()

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

    self._cert_file = self.create_tempfile(
        content=crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    )
    self._key_file = self.create_tempfile(
        content=crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    )

    self.server_ready = threading.Event()
    self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.server_sock.bind((_HOST, 0))
    _, self.server_port = self.server_sock.getsockname()
    self.server_sock.listen(1)

    self.server_thread = threading.Thread(target=self._run_server, daemon=True)
    self.server_thread.start()
    self.assertTrue(
        self.server_ready.wait(timeout=5.0), "Server failed to start"
    )

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw_sock = socket.create_connection((_HOST, self.server_port))
    self.client_ssl = context.wrap_socket(
        raw_sock, server_hostname=_HOST
    )
    self.addCleanup(self.client_ssl.close)
    self.client_ssl.write(_HANDSHAKE_TRIGGER)  # Trigger handshake & server processing
    self.server_ekm = self.client_ssl.read(_EKM_LENGTH)  # Read EKM sent by server

  def tearDown(self) -> None:
    """Tears down the server."""
    super().tearDown()
    if self.server_sock:
      self.server_sock.close()
    if self.server_thread:
      self.server_thread.join(timeout=1.0)

  def _run_server(self) -> None:
    """Simple TLS server that sends EKM."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=self._cert_file.full_path, keyfile=self._key_file.full_path
    )

    self.server_ready.set()
    try:
      raw_conn, _ = self.server_sock.accept()
    except OSError:
      # Teardown might cause accept to fail, which is fine
      pass
    else:
      with context.wrap_socket(raw_conn, server_side=True) as ssl_conn:
        ssl_conn.read(1)  # Wait for client 'x'
        server_ekm = exporter.export_keying_material(
            ssl_conn, _EKM_LENGTH, _LABEL
        )
        ssl_conn.write(server_ekm)
        # Keep connection open until client disconnects via tearDown->addCleanup
        ssl_conn.settimeout(5.0)
        while ssl_conn.read(_READ_BUFFER_SIZE):
          pass

  def test_export_keying_material_returns_correct_length_and_type(self) -> None:
    """Tests that EKM has the correct length and type."""
    ekm = exporter.export_keying_material(self.client_ssl, _EKM_LENGTH, _LABEL)
    self.assertIsNotNone(ekm)
    with self.subTest("EKM length"):
      self.assertLen(ekm, _EKM_LENGTH)
    with self.subTest("EKM type"):
      self.assertIsInstance(ekm, bytes)

  def test_export_keying_material_is_deterministic(self) -> None:
    """Tests that EKM is the same for the same session and label."""
    ekm1 = exporter.export_keying_material(self.client_ssl, _EKM_LENGTH, _LABEL)
    ekm2 = exporter.export_keying_material(self.client_ssl, _EKM_LENGTH, _LABEL)
    self.assertEqual(ekm1, ekm2)

  def test_export_keying_material_with_context_is_different(self) -> None:
    """Tests that EKM differs when a context is provided."""
    ekm_no_context = exporter.export_keying_material(
        self.client_ssl, _EKM_LENGTH, _LABEL
    )
    ekm_with_context = exporter.export_keying_material(
        self.client_ssl, _EKM_LENGTH, _LABEL, context=b"123"
    )
    self.assertNotEqual(ekm_no_context, ekm_with_context)

  def test_client_and_server_export_same_keying_material(self) -> None:
    """Tests that client and server generate identical EKM."""
    client_ekm = exporter.export_keying_material(
        self.client_ssl, _EKM_LENGTH, _LABEL
    )
    self.assertEqual(client_ekm, self.server_ekm)


if __name__ == "__main__":
  googletest.main()
