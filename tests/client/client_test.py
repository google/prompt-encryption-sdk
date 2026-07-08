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

from unittest import mock

from absl.testing import parameterized
from prompt_encryption_sdk.client import client
from prompt_encryption_sdk.client import connection
import requests

from absl.testing import absltest as googletest


class TestAttestedHTTPSAdapter(googletest.TestCase):
  """Tests for the AttestedHTTPSAdapter class."""

  def setUp(self):
    super().setUp()
    self.mock_policy = mock.create_autospec(
        client.attestation_pb2.AttestationPolicy
    )
    self.timeout = 123
    self.adapter = client.AttestedHTTPSAdapter(
        policy=self.mock_policy, revalidation_timeout=self.timeout
    )

  def test_init_sets_attributes_correctly(self):
    """Tests that init stores policy and timeout correctly.
    """
    self.assertEqual(self.adapter._policy, self.mock_policy)
    self.assertEqual(self.adapter._revalidation_timeout, self.timeout)

  @mock.patch.object(client, "constants", autospec=True)
  def test_init_with_none_timeout(self, mock_constants):
    mock_constants.DEFAULT_REVALIDATION_TIMEOUT = 12345
    adapter = client.AttestedHTTPSAdapter(
        policy=self.mock_policy, revalidation_timeout=None
    )
    self.assertEqual(adapter._revalidation_timeout, 12345)

  @mock.patch.object(connection, "AttestedPoolManager", autospec=True)
  def test_init_poolmanager_initializes_attested_pool(self, mock_pool_manager):
    """Tests that init_poolmanager correctly initializes AttestedPoolManager.

    Args:
      mock_pool_manager: The mock for client.connection.AttestedPoolManager.
    """
    connections = 10
    maxsize = 20
    block = True
    extra_kwarg = "something"

    # Act
    self.adapter.init_poolmanager(
        connections, maxsize, block=block, extra=extra_kwarg
    )

    # Assert
    with self.subTest("InternalPoolAttributes"):
      # Verify we set internal pool attributes (standard HTTPAdapter behavior)
      self.assertEqual(self.adapter._pool_connections, connections)
      self.assertEqual(self.adapter._pool_maxsize, maxsize)
      self.assertEqual(self.adapter._pool_block, block)

    with self.subTest("AttestedPoolManagerInstantiation"):
      # Verify AttestedPoolManager is instantiated with STRICTLY correct args
      # Catches mutants passing 'self.policy' but forgetting 'revalidation_timeout'.
      mock_pool_manager.assert_called_once_with(
          num_pools=connections,
          maxsize=maxsize,
          block=block,
          policy=self.mock_policy,
          revalidation_timeout=self.timeout,
          extra=extra_kwarg,
      )

    with self.subTest("PoolManagerAttributeSet"):
      # Verify the adapter's poolmanager attribute is actually set to the mock
      self.assertEqual(self.adapter.poolmanager, mock_pool_manager.return_value)


class TestPromptEncryptionClient(parameterized.TestCase):
  """Tests for the PromptEncryptionClient class."""

  def setUp(self):
    super().setUp()
    self.mock_policy = mock.create_autospec(
        client.attestation_pb2.AttestationPolicy
    )

    # Mock constants to ensure stable testing regardless of actual file values
    self.mock_constants = self.enter_context(
        mock.patch.object(client, "constants", autospec=True)
    )
    self.mock_constants.DEFAULT_REVALIDATION_TIMEOUT = 5555

  @parameterized.named_parameters(
      ("default_timeout", None, None),
      ("custom_timeout", 999, 999),
  )
  def test_init(self, input_timeout, expected_timeout):
    """Tests that init sets attributes correctly.

    Args:
      input_timeout: The value passed for revalidation_timeout during init.
      expected_timeout: The expected value of sdk.revalidation_timeout.
    """
    sdk = client.PromptEncryptionClient(
        self.mock_policy, revalidation_timeout=input_timeout
    )
    self.assertEqual(sdk.revalidation_timeout, expected_timeout)
    self.assertEqual(sdk.policy, self.mock_policy)

  @mock.patch.object(requests, "Session", autospec=True)
  @mock.patch.object(client, "AttestedHTTPSAdapter", autospec=True)
  def test_session_creation_and_mounting(
      self,
      mock_adapter_cls,
      mock_session_cls,
  ):
    """Tests that session() creates a session and mounts the adapter correctly.
    """
    sdk = client.PromptEncryptionClient(
        self.mock_policy, revalidation_timeout=777
    )

    # Act
    session = sdk.session()

    # Assert
    with self.subTest("AdapterInitialized"):
      # 1. Verify Adapter initialized correctly
      mock_adapter_cls.assert_called_once_with(
          policy=self.mock_policy, revalidation_timeout=777
      )

    with self.subTest("SessionCreated"):
      # 2. Verify Session created
      mock_session_cls.assert_called_once()

    with self.subTest("HTTPSMount"):
      # 3. CRITICAL: Verify mount is called on "https://" specifically
      # If the code was mutated to mount to "http://", this would fail.
      mock_session_instance = mock_session_cls.return_value
      mock_session_instance.mount.assert_called_once_with(
          "https://", mock_adapter_cls.return_value
      )

    with self.subTest("SessionReturned"):
      self.assertEqual(session, mock_session_instance)

  @mock.patch.object(client.PromptEncryptionClient, "session", autospec=True)
  def test_post_classmethod(self, mock_session_method):
    """Tests that post() creates a client, opens a session, posts data, and returns result.
    """
    # Setup
    url = "https://example.com/infer"
    data = {"key": "value"}
    kwargs = {"timeout": 30}

    # Mock the session context manager
    mock_sess_instance = mock.MagicMock()
    mock_session_method.return_value.__enter__.return_value = mock_sess_instance

    expected_response = mock.MagicMock()
    mock_sess_instance.post.return_value = expected_response

    # Act
    result = client.PromptEncryptionClient.post(
        self.mock_policy, url, data, **kwargs
    )

    # Assert
    with self.subTest("ResultReturned"):
      # 1. Verify result is passed back
      self.assertEqual(result, expected_response)

    with self.subTest("ClientConfiguration"):
      # Verify a PromptEncryptionClient instance was created with correct args.
      # Since session is mocked with autospec=True, the first arg is 'self'.
      (client_instance,), _ = mock_session_method.call_args
      self.assertEqual(client_instance.policy, self.mock_policy)
      self.assertIsNone(client_instance.revalidation_timeout)

    with self.subTest("SessionCalled"):
      # 2. Verify Client instantiated and session called
      # (implicit via classmethod logic)
      mock_session_method.assert_called_once()

    with self.subTest("PostCalledCorrectly"):
      # 3. Verify .post() called with exact arguments
      # Catches mutants changing json=data to data=data or forgetting kwargs
      mock_sess_instance.post.assert_called_once_with(url, json=data, **kwargs)

    with self.subTest("ContextManagerExited"):
      # 4. Verify context manager exit was called (ensures session is closed)
      mock_session_method.return_value.__exit__.assert_called_once()


if __name__ == "__main__":
  googletest.main()
