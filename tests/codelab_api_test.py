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

"""Tests that the SDK names that the codelab uses are available.

The codelab runs `examples/test_client.py` and `examples/vllm_server.py`. These
tests use the SDK in the same way as those files. If a test fails, update the
examples and the codelab in the same change.
"""

import socket

from absl.testing import absltest
from prompt_encryption_sdk import client
from prompt_encryption_sdk import server
from prompt_encryption_sdk.proto import attestation_pb2
import requests


def _make_codelab_client() -> client.PromptEncryptionClient:
  """Makes the client in the same way as examples/test_client.py."""
  hw_models = {
      "TDX": attestation_pb2.HARDWARE_MODEL_TDX,
      "SEV": attestation_pb2.HARDWARE_MODEL_SEV,
      "SEV_SNP": attestation_pb2.HARDWARE_MODEL_SEV_SNP,
  }
  policy = attestation_pb2.AttestationPolicy(
      hw_model=hw_models["TDX"],
      workload=attestation_pb2.WorkloadPolicy(image_hash="sha256:0"),
      gce_instance=attestation_pb2.GceInstancePolicy(
          project_id="project", zone="zone"
      ),
  )
  return client.PromptEncryptionClient(policy=policy)


def _closed_localhost_port() -> int:
  """Returns a localhost port that was bound and then released."""
  with socket.socket() as sock:
    sock.bind(("localhost", 0))
    return sock.getsockname()[1]


class CodelabApiTest(absltest.TestCase):

  def test_client_session_has_post(self):
    with _make_codelab_client().session() as http:
      self.assertTrue(callable(http.post))

  def test_refused_connection_raises_request_exception(self):
    # examples/test_client.py tries again only for requests.RequestException,
    # while the codelab server starts.
    url = f"https://localhost:{_closed_localhost_port()}/v1/completions"

    with _make_codelab_client().session() as http:
      with self.assertRaises(requests.RequestException):
        http.post(url, json={}, verify=False, timeout=10)

  def test_server_example_names(self):
    self.assertTrue(callable(server.run_uvicorn_app))


if __name__ == "__main__":
  absltest.main()
