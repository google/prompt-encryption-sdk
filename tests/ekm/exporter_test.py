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

"""Unit tests for exporter.py."""

import socket
import ssl
from unittest import mock

from prompt_encryption_sdk.ekm import _ekm
from prompt_encryption_sdk.ekm import exporter

from absl.testing import absltest as googletest
from absl.testing import parameterized


class ExporterUnitTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_ekm_export = self.enter_context(
        mock.patch.object(
            _ekm,
            "export_keying_material",
            autospec=True,
        )
    )
    self.mock_ekm_export.return_value = b"exported_key_material"

  def test_export_keying_material_calls_c_extension(self):
    """Tests that a valid socket object is passed to the C extension."""
    # Create a mock SSLSocket that passes type check and has no _sslobj.
    mock_socket = mock.Mock(spec=ssl.SSLSocket)
    # Explicitly delete _sslobj in case Mock adds it by default.
    del mock_socket._sslobj

    # Patch module to pass type check in export_keying_material
    with mock.patch.object(type(mock_socket), "__module__", "_ssl"):
      result = exporter.export_keying_material(
          mock_socket, 32, b"LABEL", b"CONTEXT"
      )

    self.assertEqual(result, b"exported_key_material")
    self.mock_ekm_export.assert_called_once_with(
        mock_socket, 32, b"LABEL", b"CONTEXT"
    )

  @parameterized.named_parameters(
      dict(
          testcase_name="single_layer",
          layers=1,
      ),
      dict(
          testcase_name="double_layer",
          layers=2,
      ),
      dict(
          testcase_name="no_wrapping",
          layers=0,
      ),
  )
  def test_socket_unwrapping(self, layers):
    """Tests that a single-wrapped _sslobj is unwrapped."""
    inner_socket = mock.Mock(spec=ssl.SSLSocket)
    del inner_socket._sslobj

    outer_socket = inner_socket
    for _ in range(layers):
      new_outer_socket = mock.Mock()
      new_outer_socket._sslobj = outer_socket
      outer_socket = new_outer_socket

    with mock.patch.object(type(inner_socket), "__module__", "_ssl"):
      exporter.export_keying_material(outer_socket, 16, b"L", None)

    self.mock_ekm_export.assert_called_once_with(inner_socket, 16, b"L", None)

  def test_export_rejects_none_socket(self):
    """Ensures None is rejected with a clear TypeError."""
    with self.assertRaisesRegex(TypeError, "Socket cannot be None"):
      exporter.export_keying_material(None, 32, b"LABEL")  # pytype: disable=wrong-arg-types
    self.mock_ekm_export.assert_not_called()

  def test_export_rejects_non_ssl_objects(self):
    """Ensures standard (non-SSL) sockets are rejected."""
    non_ssl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.addCleanup(non_ssl_sock.close)

    with self.assertRaisesRegex(
        TypeError, "does not appear to be a valid SSL socket object"
    ):
      exporter.export_keying_material(non_ssl_sock, 32, b"LABEL")  # pytype: disable=wrong-arg-types
    self.mock_ekm_export.assert_not_called()

  def test_export_rejects_arbitrary_objects(self):
    """Ensures completely random objects are rejected."""
    with self.assertRaisesRegex(
        TypeError, "does not appear to be a valid SSL socket object"
    ):
      exporter.export_keying_material("i am not a socket", 32, b"LABEL")  # pytype: disable=wrong-arg-types
    self.mock_ekm_export.assert_not_called()


if __name__ == "__main__":
  googletest.main()
