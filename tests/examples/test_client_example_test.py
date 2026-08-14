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

"""Tests that the codelab client preserves legacy and mutual modes."""

import importlib.util
import pathlib
import sys
from unittest import mock

from absl.testing import absltest


_EXAMPLE_PATH = (
    pathlib.Path(__file__).resolve().parents[2] / "examples" / "test_client.py"
)
_SPEC = importlib.util.spec_from_file_location("codelab_test_client", _EXAMPLE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
test_client = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(test_client)


class TestClientExampleTest(absltest.TestCase):

  def _argv(self) -> list[str]:
    return [
        "test_client.py",
        "--image-hash",
        "sha256:server",
        "--project-id",
        "server-project",
        "--zone",
        "us-central1-a",
        "--ip",
        "192.0.2.1",
    ]

  def test_default_mode_does_not_create_client_attestation_identity(self):
    with (
        mock.patch.object(sys, "argv", self._argv()),
        mock.patch.object(test_client.client, "PromptEncryptionClient") as client_cls,
        mock.patch.object(test_client.server, "KeyManager") as key_manager_cls,
        mock.patch.object(test_client, "_run_inference") as run_inference,
    ):
      test_client.main()

    client_cls.assert_called_once_with(policy=mock.ANY)
    key_manager_cls.assert_not_called()
    run_inference.assert_called_once()

  def test_mutual_mode_populates_and_passes_client_identity(self):
    identity_dir = self.create_tempdir().full_path
    argv = self._argv() + [
        "--mutual-attestation",
        "--attestation-type",
        "gotpm",
        "--identity-dir",
        identity_dir,
    ]
    identity = mock.MagicMock()
    with (
        mock.patch.object(sys, "argv", argv),
        mock.patch.object(test_client.server, "KeyManager") as key_manager_cls,
        mock.patch.object(
            test_client.server, "TokenManager", return_value=identity
        ) as token_manager_cls,
        mock.patch.object(test_client.client, "PromptEncryptionClient") as client_cls,
        mock.patch.object(test_client, "_run_inference") as run_inference,
        mock.patch.dict(test_client.os.environ, {}, clear=False),
    ):
      test_client.main()
      self.assertEqual(test_client.os.environ["ATTESTATION_TYPE"], "gotpm")

    key_manager_cls.assert_called_once()
    token_manager_cls.assert_called_once_with(
        key_manager=key_manager_cls.return_value,
        attestation_token_path=pathlib.Path(identity_dir) / "attestation-token.jwt",
    )
    identity.refresh.assert_called_once()
    client_cls.assert_called_once_with(
        policy=mock.ANY,
        mutual_attestation=True,
        client_token_manager=identity,
    )
    identity.__enter__.assert_called_once()
    identity.__exit__.assert_called_once()
    run_inference.assert_called_once()


if __name__ == "__main__":
  absltest.main()
