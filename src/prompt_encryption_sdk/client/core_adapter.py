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

"""Requests adapter backed by the language-neutral client core."""

import json
import os
import pathlib
import queue
import subprocess
import tempfile
import threading
from urllib import parse

from prompt_encryption_sdk.proto import attestation_pb2
import requests

from . import constants


_CORE_ENV = "PROMPT_ENCRYPTION_CLIENT_CORE"


def configured_core_binary() -> str | None:
  """Returns the explicitly configured portable-core executable, if any."""
  return os.environ.get(_CORE_ENV)


def _policy_dict(
    policy: attestation_pb2.AttestationPolicy,
) -> dict[str, object]:
  hardware_models = {
      attestation_pb2.HARDWARE_MODEL_UNSPECIFIED: "",
      attestation_pb2.HARDWARE_MODEL_TDX: "TDX",
      attestation_pb2.HARDWARE_MODEL_SEV: "SEV",
      attestation_pb2.HARDWARE_MODEL_SEV_SNP: "SEV_SNP",
  }
  return {
      "hw_model": hardware_models.get(policy.hw_model, str(policy.hw_model)),
      "workload": {
          "image_hash": policy.workload.image_hash,
          "signing_key_id": policy.workload.signing_key_id,
      },
      "gce_instance": {
          "project_id": policy.gce_instance.project_id,
          "zone": policy.gce_instance.zone,
          "instance_id": policy.gce_instance.instance_id,
          "instance_name": policy.gce_instance.instance_name,
      },
  }


class _CoreProcess:
  """Owns one client-core process configured for one upstream origin."""

  def __init__(
      self,
      *,
      executable: str,
      upstream: str,
      policy_path: pathlib.Path,
      insecure_skip_tls_verify: bool,
      revalidation_timeout: int,
      server_ca_path: str | None,
      client_cert_path: str | None,
      client_key_path: str | None,
  ):
    command = [
        executable,
        "--listen=127.0.0.1:0",
        f"--upstream={upstream}",
        f"--policy={policy_path}",
        f"--oidc-discovery-url={constants.CS_OIDC_DISCOVERY_URL}",
        f"--oidc-issuer={constants.CS_DEFAULT_ISSUER}",
        f"--oidc-jwks-uri={constants.CS_DEFAULT_JWKS_URI}",
        f"--revalidation-timeout={revalidation_timeout}s",
    ]
    if insecure_skip_tls_verify:
      command.append("--insecure-skip-tls-verify")
    if server_ca_path:
      command.append(f"--server-ca={server_ca_path}")
    if client_cert_path:
      command.append(f"--client-cert={client_cert_path}")
      command.append(f"--client-key={client_key_path or client_cert_path}")
    self._process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert self._process.stdout is not None
    readiness: queue.Queue[str] = queue.Queue(maxsize=1)
    reader = threading.Thread(
        target=lambda: readiness.put(self._process.stdout.readline()),
        daemon=True,
    )
    reader.start()
    try:
      ready_line = readiness.get(timeout=10)
    except queue.Empty as error:
      self.close()
      raise requests.ConnectionError(
          "Prompt Encryption client core did not become ready within 10 seconds"
      ) from error
    if not ready_line:
      self.close()
      assert self._process.stderr is not None
      error = self._process.stderr.read().strip()
      raise requests.ConnectionError(
          f"Prompt Encryption client core failed to start: {error}"
      )
    try:
      self.url = json.loads(ready_line)["url"]
    except (json.JSONDecodeError, KeyError) as error:
      self.close()
      raise requests.ConnectionError(
          f"Invalid readiness response from client core: {ready_line!r}"
      ) from error

  def close(self) -> None:
    if self._process.poll() is not None:
      return
    self._process.terminate()
    try:
      self._process.wait(timeout=5)
    except subprocess.TimeoutExpired:
      self._process.kill()
      self._process.wait(timeout=5)

  def is_running(self) -> bool:
    return self._process.poll() is None


class CoreHTTPSAdapter(requests.adapters.HTTPAdapter):
  """Routes HTTPS requests through the portable attestation core."""

  def __init__(
      self,
      *,
      policy: attestation_pb2.AttestationPolicy,
      executable: str,
      revalidation_timeout: int | None = None,
      **kwargs,
  ):
    self._executable = executable
    self._revalidation_timeout = (
        revalidation_timeout
        if revalidation_timeout is not None
        else constants.DEFAULT_REVALIDATION_TIMEOUT
    )
    self._tempdir = tempfile.TemporaryDirectory()
    self._policy_path = pathlib.Path(self._tempdir.name) / "policy.json"
    self._policy_path.write_text(json.dumps(_policy_dict(policy)))
    self._processes: dict[
        tuple[str, bool, str | None, str | None, str | None], _CoreProcess
    ] = {}
    self._lock = threading.Lock()
    super().__init__(**kwargs)

  def send(
      self,
      request,
      stream=False,
      timeout=None,
      verify=True,
      cert=None,
      proxies=None,
  ):
    original_url = request.url
    split_url = parse.urlsplit(original_url)
    upstream = f"{split_url.scheme}://{split_url.netloc}"
    insecure = verify is False
    server_ca_path = os.fspath(verify) if isinstance(
        verify, (str, os.PathLike)
    ) else None
    if isinstance(cert, (tuple, list)):
      if len(cert) != 2:
        raise ValueError("cert must contain the certificate and private key")
      client_cert_path = os.fspath(cert[0])
      client_key_path = os.fspath(cert[1])
    elif cert:
      client_cert_path = os.fspath(cert)
      client_key_path = client_cert_path
    else:
      client_cert_path = None
      client_key_path = None
    core = self._get_process(
        upstream,
        insecure,
        server_ca_path,
        client_cert_path,
        client_key_path,
    )
    core_url = parse.urlsplit(core.url)
    request.url = parse.urlunsplit((
        core_url.scheme,
        core_url.netloc,
        split_url.path,
        split_url.query,
        split_url.fragment,
    ))
    try:
      response = super().send(
          request,
          stream=stream,
          timeout=timeout,
          verify=False,
          cert=None,
          proxies={},
      )
    finally:
      request.url = original_url
    response.url = original_url
    return response

  def close(self) -> None:
    try:
      with self._lock:
        for process in self._processes.values():
          process.close()
        self._processes.clear()
      self._tempdir.cleanup()
    finally:
      super().close()

  def _get_process(
      self,
      upstream: str,
      insecure_skip_tls_verify: bool,
      server_ca_path: str | None,
      client_cert_path: str | None,
      client_key_path: str | None,
  ) -> _CoreProcess:
    key = (
        upstream,
        insecure_skip_tls_verify,
        server_ca_path,
        client_cert_path,
        client_key_path,
    )
    with self._lock:
      process = self._processes.get(key)
      if process is not None and not process.is_running():
        process.close()
        del self._processes[key]
        process = None
      if process is None:
        process = _CoreProcess(
            executable=self._executable,
            upstream=upstream,
            policy_path=self._policy_path,
            insecure_skip_tls_verify=insecure_skip_tls_verify,
            revalidation_timeout=self._revalidation_timeout,
            server_ca_path=server_ca_path,
            client_cert_path=client_cert_path,
            client_key_path=client_key_path,
        )
        self._processes[key] = process
      return process
