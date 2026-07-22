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
import pathlib
from unittest import mock

from absl.testing import absltest
from prompt_encryption_sdk.server import common
from prompt_encryption_sdk.server import keys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class KeysTest(absltest.TestCase):

  @mock.patch.object(keys.ec, "generate_private_key", autospec=True)
  def test_key_manager_generate_key_pair(self, mock_generate_private_key):
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
    pqc_private_key_path = pathlib.Path(temp_dir.full_path, "pqc_private.bin")
    pqc_public_key_path = pathlib.Path(temp_dir.full_path, "pqc_public.bin")

    mock_write_file = mock.Mock(spec=common.FileWriter)

    key_manager = keys.KeyManager(
        private_key_path=private_key_path,
        public_key_path=public_key_path,
        pqc_private_key_path=pqc_private_key_path,
        pqc_public_key_path=pqc_public_key_path,
        write_file_fn=mock_write_file,
    )
    public_key = key_manager.generate_key_pair()

    with self.subTest(name="PublicKeyReturned"):
      self.assertEqual(public_key, pem_public_bytes)

    with self.subTest(name="PrivateKeyGenerated"):
      mock_generate_private_key.assert_called_once()

    with self.subTest(name="KeysWritten"):
      self.assertEqual(mock_write_file.call_count, 4)
      mock_write_file.assert_any_call(private_key_path, pem_private_bytes, 0o600)
      mock_write_file.assert_any_call(public_key_path, pem_public_bytes, 0o644)

      # Verify PQC writes
      pqc_priv_call = [
          c
          for c in mock_write_file.call_args_list
          if c[0][0] == pqc_private_key_path
      ][0]
      self.assertEqual(pqc_priv_call[0][2], 0o600)
      self.assertIsInstance(pqc_priv_call[0][1], bytes)
      self.assertNotEmpty(pqc_priv_call[0][1])

      pqc_pub_call = [
          c for c in mock_write_file.call_args_list if c[0][0] == pqc_public_key_path
      ][0]
      self.assertEqual(pqc_pub_call[0][2], 0o644)
      self.assertIsInstance(pqc_pub_call[0][1], bytes)
      self.assertNotEmpty(pqc_pub_call[0][1])

  def test_key_manager_get_current_public_key(self):
    public_key_bytes = b"test_public_key"
    temp_dir = self.create_tempdir()
    public_key_path = pathlib.Path(temp_dir.full_path, "public.pem")
    with open(public_key_path, "wb") as f:
      f.write(public_key_bytes)

    key_manager = keys.KeyManager(public_key_path=public_key_path)
    self.assertEqual(key_manager.get_current_public_key(), public_key_bytes)

  def test_key_manager_get_current_pqc_public_key(self):
    pqc_public_bytes = b"test_pqc_public_keyset"
    temp_dir = self.create_tempdir()
    pqc_public_key_path = pathlib.Path(temp_dir.full_path, "pqc_public.bin")
    with open(pqc_public_key_path, "wb") as f:
      f.write(pqc_public_bytes)

    key_manager = keys.KeyManager(pqc_public_key_path=pqc_public_key_path)
    self.assertEqual(
        key_manager.get_current_pqc_public_key(), pqc_public_bytes
    )

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

  def test_key_manager_sign_payload_mldsa(self):
    mldsa_template = keys.signature.signature_key_templates.ML_DSA_65
    private_handle = keys.tink.new_keyset_handle(mldsa_template)

    private_bytes = keys.tink.proto_keyset_format.serialize(
        private_handle, keys.secret_key_access.TOKEN
    )

    temp_dir = self.create_tempdir()
    pqc_private_key_path = pathlib.Path(temp_dir.full_path, "pqc_private.bin")
    with open(pqc_private_key_path, "wb") as f:
      f.write(private_bytes)

    key_manager = keys.KeyManager(pqc_private_key_path=pqc_private_key_path)
    payload = b"test_payload"
    signature = key_manager.sign_payload_mldsa(payload)

    public_handle = private_handle.public_keyset_handle()
    verifier = public_handle.primitive(keys.signature.PublicKeyVerify)
    self.assertIsNone(verifier.verify(signature, payload))


if __name__ == "__main__":
  absltest.main()
