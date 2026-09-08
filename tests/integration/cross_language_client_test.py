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

"""End-to-end contract tests shared by every client implementation."""

import json
import os
import pathlib
import subprocess
import time
from unittest import mock

from prompt_encryption_sdk.client import client
import requests

from local_attested_server import LocalAttestedServer
from local_attested_server import make_policy


def test_existing_python_client_attests_before_sending_application_data():
  server = LocalAttestedServer()
  try:
    with mock.patch(
        "prompt_encryption_sdk.client.constants.CS_OIDC_DISCOVERY_URL",
        server.oidc_discovery_url,
    ):
      sdk_client = client.PromptEncryptionClient(make_policy())
      with sdk_client.session() as session:
        response = session.post(
            f"{server.url}/v1/completions",
            json={"prompt": "cross-language contract"},
            verify=server.ca_path,
            timeout=5,
        )

    assert response.status_code == 200
    assert response.json() == {
        "received": {"prompt": "cross-language contract"}
    }
  finally:
    server.close()


def test_language_neutral_client_attests_before_forwarding_application_data(
    tmp_path: pathlib.Path,
):
  server = LocalAttestedServer()
  process = None
  try:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({
        "hw_model": "TDX",
        "workload": {"image_hash": "sha256:test-image"},
        "gce_instance": {
            "project_id": "test-project",
            "zone": "test-zone",
        },
    }))
    process = subprocess.Popen(
        [
            "go",
            "run",
            "./cmd/prompt-encryption-client",
            "--listen=127.0.0.1:0",
            f"--upstream={server.url}",
            f"--policy={policy_path}",
            f"--oidc-discovery-url={server.oidc_discovery_url}",
            f"--server-ca={server.ca_path}",
        ],
        cwd=pathlib.Path(__file__).parents[2] / "clientcore",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    ready = json.loads(process.stdout.readline())

    response = requests.post(
        f"{ready['url']}/v1/completions",
        json={"prompt": "cross-language contract"},
        timeout=10,
    )

    assert response.status_code == 200
    assert response.json() == {
        "received": {"prompt": "cross-language contract"}
    }
  finally:
    if process is not None:
      process.terminate()
      process.wait(timeout=5)
    server.close()


def test_unchanged_python_api_can_use_language_neutral_core(
    tmp_path: pathlib.Path,
):
  core_binary = tmp_path / "prompt-encryption-client"
  subprocess.run(
      ["go", "build", "-o", core_binary, "./cmd/prompt-encryption-client"],
      cwd=pathlib.Path(__file__).parents[2] / "clientcore",
      check=True,
  )
  server = LocalAttestedServer()
  try:
    environment = {
        "PROMPT_ENCRYPTION_CLIENT_CORE": str(core_binary),
    }
    with (
        mock.patch.dict(os.environ, environment),
        mock.patch(
            "prompt_encryption_sdk.client.constants.CS_OIDC_DISCOVERY_URL",
            server.oidc_discovery_url,
        ),
        mock.patch.object(
            client, "AttestedHTTPSAdapter", side_effect=AssertionError(
                "legacy Python attestation path was used"
            )
        ),
    ):
      sdk_client = client.PromptEncryptionClient(make_policy())
      with sdk_client.session() as session:
        response = session.post(
            f"{server.url}/v1/completions",
            json={"prompt": "same Python interface"},
            verify=server.ca_path,
            timeout=10,
        )

    assert response.status_code == 200
    assert response.json() == {
        "received": {"prompt": "same Python interface"}
    }
  finally:
    server.close()


def test_language_neutral_client_revalidates_a_pooled_connection(
    tmp_path: pathlib.Path,
):
  server = LocalAttestedServer()
  process = None
  try:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({
        "hw_model": "TDX",
        "workload": {"image_hash": "sha256:test-image"},
        "gce_instance": {
            "project_id": "test-project",
            "zone": "test-zone",
        },
    }))
    process = subprocess.Popen(
        [
            "go",
            "run",
            "./cmd/prompt-encryption-client",
            "--listen=127.0.0.1:0",
            f"--upstream={server.url}",
            f"--policy={policy_path}",
            f"--oidc-discovery-url={server.oidc_discovery_url}",
            "--revalidation-timeout=50ms",
            f"--server-ca={server.ca_path}",
        ],
        cwd=pathlib.Path(__file__).parents[2] / "clientcore",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    ready_line = process.stdout.readline()
    assert ready_line, process.stderr.read() if process.stderr else ""
    ready = json.loads(ready_line)

    first = requests.post(
        f"{ready['url']}/v1/completions",
        json={"prompt": "first"},
        timeout=10,
    )
    assert first.status_code == 200
    assert server.attestation_count == 1

    time.sleep(0.1)
    second = requests.post(
        f"{ready['url']}/v1/completions",
        json={"prompt": "second"},
        timeout=10,
    )
    assert second.status_code == 200
    assert server.attestation_count == 2
  finally:
    if process is not None:
      process.terminate()
      process.wait(timeout=5)
    server.close()


def test_language_neutral_client_rejects_policy_mismatch_before_forwarding(
    tmp_path: pathlib.Path,
):
  server = LocalAttestedServer()
  process = None
  try:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({
        "hw_model": "TDX",
        "workload": {"image_hash": "sha256:unexpected-image"},
        "gce_instance": {
            "project_id": "test-project",
            "zone": "test-zone",
        },
    }))
    process = subprocess.Popen(
        [
            "go",
            "run",
            "./cmd/prompt-encryption-client",
            "--listen=127.0.0.1:0",
            f"--upstream={server.url}",
            f"--policy={policy_path}",
            f"--oidc-discovery-url={server.oidc_discovery_url}",
            f"--server-ca={server.ca_path}",
        ],
        cwd=pathlib.Path(__file__).parents[2] / "clientcore",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    ready = json.loads(process.stdout.readline())

    response = requests.post(
        f"{ready['url']}/v1/completions",
        json={"prompt": "must not reach server"},
        timeout=10,
    )

    assert response.status_code == 502
    assert server.application_request_count == 0
  finally:
    if process is not None:
      process.terminate()
      process.wait(timeout=5)
    server.close()


def test_language_neutral_client_rejects_tampered_session_binding(
    tmp_path: pathlib.Path,
):
  server = LocalAttestedServer(tamper_session_signature=True)
  process = None
  try:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({
        "hw_model": "TDX",
        "workload": {"image_hash": "sha256:test-image"},
        "gce_instance": {
            "project_id": "test-project",
            "zone": "test-zone",
        },
    }))
    process = subprocess.Popen(
        [
            "go",
            "run",
            "./cmd/prompt-encryption-client",
            "--listen=127.0.0.1:0",
            f"--upstream={server.url}",
            f"--policy={policy_path}",
            f"--oidc-discovery-url={server.oidc_discovery_url}",
            f"--server-ca={server.ca_path}",
        ],
        cwd=pathlib.Path(__file__).parents[2] / "clientcore",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    ready = json.loads(process.stdout.readline())

    response = requests.post(
        f"{ready['url']}/v1/completions",
        json={"prompt": "must not reach server"},
        timeout=10,
    )

    assert response.status_code == 502
    assert server.application_request_count == 0
  finally:
    if process is not None:
      process.terminate()
      process.wait(timeout=5)
    server.close()
