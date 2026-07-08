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

"""Tests for server.keys."""

import hashlib
import os
import pathlib
from unittest import mock

from absl.testing import absltest
from prompt_encryption_sdk.server import common
from prompt_encryption_sdk.server import keys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class KeysTest(absltest.TestCase):

  @mock.patch.object(os, "replace", autospec=True)
  @mock.patch.object(os, "fdopen")
  @mock.patch.object(os, "open", autospec=True)
  @mock.patch.object(keys.ec, "generate_private_key", autospec=True)
  def test_key_manager_generate_key_pair(
      self,
      mock_generate_private_key,
      mock_os_open,
      mock_os_fdopen,
      mock_os_replace,
  ):
    mock_private_key = mock.create_autospec(
        ec.EllipticCurvePrivateKey, instance=True, spec_set=True
    )
    mock_public_key = mock.create_autospec(
        ec.EllipticCurvePublicKey, instance=True, spec_set=True
    )
    mock_private_key.public_key.return_value = mock_public_key
    mock_generate_private_key.return_value = mock_private_key

    pem_public_bytes = b"pem_public_bytes"
    mock_public_key.public_bytes.return_value = pem_public_bytes
    pem_private_bytes = b"pem_private_bytes"
    mock_private_key.private_bytes.return_value = pem_private_bytes

    temp_dir = self.create_tempdir()
    private_key_path = pathlib.Path(temp_dir.full_path, "private.pem")
    public_key_path = pathlib.Path(temp_dir.full_path, "public.pem")

    mock_private_key_fd = 123
    mock_public_key_fd = 456
    mock_os_open.side_effect = [mock_private_key_fd, mock_public_key_fd]

    mock_private_key_file = mock.mock_open()()
    mock_public_key_file = mock.mock_open()()
    mock_os_fdopen.side_effect = [mock_private_key_file, mock_public_key_file]

    key_manager = keys.KeyManager(
        private_key_path=private_key_path, public_key_path=public_key_path
    )
    public_key = key_manager.generate_key_pair()

    with self.subTest(name="PublicKeyReturned"):
      self.assertEqual(public_key, pem_public_bytes)

    with self.subTest(name="PrivateKeyGenerated"):
      mock_generate_private_key.assert_called_once()

    with self.subTest(name="KeysWritten"):
      private_key_temp_path = private_key_path.with_name(
          private_key_path.name + ".tmp"
      )
      public_key_temp_path = public_key_path.with_name(
          public_key_path.name + ".tmp"
      )
      mock_os_open.assert_has_calls([
          mock.call(
              private_key_temp_path,
              os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
              0o600,
          ),
          mock.call(
              public_key_temp_path,
              os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
              0o644,
          ),
      ])
      mock_os_replace.assert_has_calls([
          mock.call(private_key_temp_path, private_key_path),
          mock.call(public_key_temp_path, public_key_path),
      ])
      mock_os_fdopen.assert_has_calls([
          mock.call(mock_private_key_fd, "wb"),
          mock.call(mock_public_key_fd, "wb"),
      ])
      mock_private_key_file.write.assert_called_once_with(pem_private_bytes)
      mock_public_key_file.write.assert_called_once_with(pem_public_bytes)

  def test_key_manager_get_current_public_key(self):
    public_key_bytes = b"test_public_key"
    temp_dir = self.create_tempdir()
    public_key_path = pathlib.Path(temp_dir.full_path, "public.pem")
    with open(public_key_path, "wb") as f:
      f.write(public_key_bytes)

    key_manager = keys.KeyManager(public_key_path=public_key_path)
    self.assertEqual(key_manager.get_current_public_key(), public_key_bytes)

  def test_calculate_fingerprint(self):
    public_key = b"test_public_key"
    expected_fingerprint = hashlib.sha256(public_key).hexdigest()
    self.assertEqual(
        keys.calculate_fingerprint(public_key), expected_fingerprint
    )

  def test_key_manager_sign_payload(self):
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem_private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    private_key_file = self.create_tempfile(content=pem_private_bytes)
    key_manager = keys.KeyManager(
        private_key_path=pathlib.Path(private_key_file.full_path)
    )
    payload = b"test_payload"
    signature = key_manager.sign_payload(payload)

    public_key = private_key.public_key()
    self.assertIsNone(
        public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    )


if __name__ == "__main__":
  absltest.main()
