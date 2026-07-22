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

"""Tests for server.token."""

import hashlib
import http.client
import os
import pathlib
import random
import socket
import subprocess
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token


class _FakeHTTPResponse(http.client.HTTPResponse):
  status: int = 200
  reason: str = "OK"


class TokenTest(absltest.TestCase):

  def test_get_cs_token_bytes_success(self):
    mock_conn = mock.create_autospec(
        token.UnixSocketConnection, instance=True, spec_set=True
    )
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.__exit__.return_value = None

    mock_response = mock.create_autospec(
        _FakeHTTPResponse, instance=True, spec_set=True
    )
    mock_response.status = 200
    mock_response.read.return_value = b"test_token"
    mock_conn.getresponse.return_value = mock_response
    mock.seal(mock_response)
    mock.seal(mock_conn)
    mock_connection_factory = mock.create_autospec(
        token.UnixSocketConnection, instance=False, spec_set=True
    )
    mock_connection_factory.return_value = mock_conn
    mock.seal(mock_connection_factory)

    token_bytes = token.get_cs_token_bytes(
        socket_path=pathlib.Path("test_socket"),
        connection_factory=mock_connection_factory,
        audience="test_audience",
    )

    self.assertEqual(token_bytes, b"test_token")
    mock_connection_factory.assert_called_once_with(pathlib.Path("test_socket"))
    mock_conn.request.assert_called_once_with(
        "POST",
        "/v1/token",
        body='{"audience": "test_audience"}'.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

  def test_get_cs_token_bytes_error(self):
    mock_conn = mock.create_autospec(
        token.UnixSocketConnection, instance=True, spec_set=True
    )
    mock_conn.__enter__.return_value = mock_conn

    mock_response = mock.create_autospec(
        _FakeHTTPResponse, instance=True, spec_set=True
    )
    mock_response.status = 400
    mock_response.reason = "Bad Request"
    mock_conn.getresponse.return_value = mock_response
    mock_connection_factory = mock.create_autospec(
        token.UnixSocketConnection, instance=False, spec_set=True
    )
    mock_connection_factory.return_value = mock_conn

    with self.assertRaisesRegex(RuntimeError, "HTTP Error 400: Bad Request"):
      token.get_cs_token_bytes(
          connection_factory=mock_connection_factory, audience="test_audience"
      )

  @mock.patch.object(subprocess, "run", autospec=True)
  def test_get_cvm_token_bytes_success(self, mock_run):
    mock_result = mock.create_autospec(
        subprocess.CompletedProcess, instance=True
    )
    mock_result.stdout = b"test_token\n"
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    token_bytes = token.get_cvm_token_bytes(
        "test_audience", ["nonce1", "nonce2"]
    )

    self.assertEqual(token_bytes, b"test_token")
    mock_run.assert_called_once_with(
        [
            "gotpm",
            "token",
            "--audience",
            "test_audience",
            "--custom-nonce",
            "nonce1",
            "--custom-nonce",
            "nonce2",
        ],
        capture_output=True,
        check=False,
    )

  @mock.patch.object(subprocess, "run", autospec=True)
  def test_get_cvm_token_bytes_error(self, mock_run):
    mock_result = mock.create_autospec(
        subprocess.CompletedProcess, instance=True
    )
    mock_result.returncode = 1
    mock_result.stderr = b"test error"
    mock_run.return_value = mock_result

    with self.assertRaisesRegex(RuntimeError, "test error"):
      token.get_cvm_token_bytes("test_audience", ["nonce1"])

  @mock.patch.object(socket, "socket", autospec=True)
  def test_unix_socket_connection_connect(self, mock_socket):
    socket_path = "/test/socket"
    with token.UnixSocketConnection(pathlib.Path(socket_path)) as conn:
      conn.connect()
      mock_socket.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
      conn.sock.connect.assert_called_once_with(socket_path)


class TokenManagerTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_key_manager = mock.create_autospec(
        keys.KeyManager, instance=True, spec_set=True
    )
    self.temp_dir = self.create_tempdir()
    self.attestation_token_path = pathlib.Path(
        os.path.join(self.temp_dir.full_path, "attestation_token.txt")
    )
    self.seeded_rng = random.Random(24)

  @parameterized.named_parameters(
      dict(
          testcase_name="default_cs",
          env_vars={},
          mock_cs_return=b"test_token",
          mock_cvm_return=None,
          expect_cs_call=True,
          expect_cvm_call=False,
          expected_token=b"test_token",
          expected_error=None,
          expected_error_regex=None,
      ),
      dict(
          testcase_name="explicit_cs",
          env_vars={"ATTESTATION_TYPE": "uds"},
          mock_cs_return=b"test_token",
          mock_cvm_return=None,
          expect_cs_call=True,
          expect_cvm_call=False,
          expected_token=b"test_token",
          expected_error=None,
          expected_error_regex=None,
      ),
      dict(
          testcase_name="explicit_cvm",
          env_vars={"ATTESTATION_TYPE": "gotpm"},
          mock_cs_return=None,
          mock_cvm_return=b"cvm_test_token",
          expect_cs_call=False,
          expect_cvm_call=True,
          expected_token=b"cvm_test_token",
          expected_error=None,
          expected_error_regex=None,
      ),
      dict(
          testcase_name="unknown_tee",
          env_vars={"ATTESTATION_TYPE": "unknown"},
          mock_cs_return=None,
          mock_cvm_return=None,
          expect_cs_call=False,
          expect_cvm_call=False,
          expected_token=None,
          expected_error=ValueError,
          expected_error_regex="Unknown ATTESTATION_TYPE 'unknown'.",
      ),
  )
  @mock.patch.object(token, "get_cvm_token_bytes", autospec=True)
  @mock.patch.object(token, "get_cs_token_bytes", autospec=True)
  def test_refresh_environments(
      self,
      mock_get_cs_token_bytes,
      mock_get_cvm_token_bytes,
      env_vars,
      mock_cs_return,
      mock_cvm_return,
      expect_cs_call,
      expect_cvm_call,
      expected_token,
      expected_error,
      expected_error_regex,
  ):
    with mock.patch.dict(os.environ, env_vars, clear=True):
      ecdsa_pub = b"test_ecdsa_public_key"
      pqc_pub = b"test_pqc_public_keyset"

      ecdsa_fingerprint = hashlib.sha256(ecdsa_pub).hexdigest()
      pqc_fingerprint = hashlib.sha256(pqc_pub).hexdigest()

      self.mock_key_manager.get_current_public_key.return_value = ecdsa_pub
      self.mock_key_manager.get_current_pqc_public_key.return_value = pqc_pub

      if mock_cs_return is not None:
        mock_get_cs_token_bytes.return_value = mock_cs_return
      if mock_cvm_return is not None:
        mock_get_cvm_token_bytes.return_value = mock_cvm_return

      token_manager = token.TokenManager(
          key_manager=self.mock_key_manager,
          attestation_token_path=self.attestation_token_path,
          rng=self.seeded_rng,
      )

      if expected_error:
        with self.assertRaisesRegex(expected_error, expected_error_regex):
          token_manager.refresh()
      else:
        token_manager.refresh()

      if expect_cs_call:
        mock_get_cs_token_bytes.assert_called_once_with(
            audience="https://sts.google.com",
            token_type="OIDC",
            nonces=[ecdsa_fingerprint, pqc_fingerprint],
        )
      else:
        mock_get_cs_token_bytes.assert_not_called()

      if expect_cvm_call:
        mock_get_cvm_token_bytes.assert_called_once_with(
            audience="https://sts.google.com",
            nonces=[ecdsa_fingerprint, pqc_fingerprint],
        )
      else:
        mock_get_cvm_token_bytes.assert_not_called()

      if not expected_error:
        with open(self.attestation_token_path, "rb") as f:
          actual_token = f.read()
          if expected_token == b"":
            self.assertEmpty(actual_token)
          else:
            self.assertEqual(actual_token, expected_token)

  def test_get_public_key(self):
    public_key = b"test_public_key"
    self.mock_key_manager.get_current_public_key.return_value = public_key
    token_manager = token.TokenManager(key_manager=self.mock_key_manager)
    self.assertEqual(token_manager.get_public_key(), public_key)
    self.mock_key_manager.get_current_public_key.assert_called_once()

  def test_get_pqc_public_key(self):
    pqc_pub = b"test_pqc_public_keyset"
    self.mock_key_manager.get_current_pqc_public_key.return_value = pqc_pub
    token_manager = token.TokenManager(key_manager=self.mock_key_manager)
    self.assertEqual(token_manager.get_pqc_public_key(), pqc_pub)
    self.mock_key_manager.get_current_pqc_public_key.assert_called_once()

  def test_get_attestation_token(self):
    attestation_token = b"test_token"
    with open(self.attestation_token_path, "wb") as f:
      f.write(attestation_token)
    token_manager = token.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path=self.attestation_token_path,
    )
    self.assertEqual(token_manager.get_attestation_token(), attestation_token)

  def test_get_attestation_token_not_found(self):
    token_manager = token.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path="/nonexistent/path",
    )
    self.assertEmpty(token_manager.get_attestation_token())

  def test_get_identity_snapshot(self):
    ecdsa_pub = b"test_ecdsa_public_key"
    pqc_pub = b"test_pqc_public_keyset"
    attestation_token = b"test_token"

    self.mock_key_manager.get_current_public_key.return_value = ecdsa_pub
    self.mock_key_manager.get_current_pqc_public_key.return_value = pqc_pub

    with open(self.attestation_token_path, "wb") as f:
      f.write(attestation_token)

    token_manager = token.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path=self.attestation_token_path,
    )

    snapshot = token_manager.get_identity_snapshot()
    self.assertEqual(snapshot, (ecdsa_pub, pqc_pub, attestation_token))


if __name__ == "__main__":
  absltest.main()
