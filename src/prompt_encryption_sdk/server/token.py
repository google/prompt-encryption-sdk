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

"""Token management logic for Prompt Encryption SDK."""

from collections.abc import Callable, Sequence
import http.client
import json
import os
import pathlib
import random
import socket  # Needed for AF_UNIX
import subprocess
import threading
import time
import types
from typing import Any

from absl import logging
from prompt_encryption_sdk.server import common
from prompt_encryption_sdk.server import keys
import jwt

TEE_SERVER_SOCKET_PATH = "/run/container_launcher/teeserver.sock"
TOKEN_ENDPOINT = "/v1/token"
DEFAULT_AUDIENCE = "https://sts.google.com"
TOKEN_TYPE = "OIDC"
DEFAULT_REFRESH_MULTIPLIER = 0.9
DEFAULT_RETRY_INTERVAL_SECONDS = 10


class UnixSocketConnection(http.client.HTTPConnection):
  """HTTPConnection that connects to a Unix domain socket."""

  def __init__(self, socket_path: pathlib.Path):
    super().__init__("localhost")
    self.socket_path = str(socket_path)

  def connect(self):
    self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.sock.connect(self.socket_path)

  def __enter__(self) -> "UnixSocketConnection":
    return self

  def __exit__(
      self,
      exc_type: type[BaseException] | None,
      exc_val: BaseException | None,
      exc_tb: types.TracebackType | None,
  ) -> None:
    self.close()

  def __repr__(self):
    return f"UnixSocketConnection(socket_path={self.socket_path!r})"


def get_cs_token_bytes(
    socket_path: pathlib.Path = pathlib.Path(TEE_SERVER_SOCKET_PATH),
    connection_factory: Callable[
        [pathlib.Path], http.client.HTTPConnection
    ] = UnixSocketConnection,
    **kwargs: Any,
) -> bytes:
  """Retrieves custom attestation token bytes via TEE server."""
  conn = connection_factory(socket_path)
  with conn:
    headers = {"Content-Type": "application/json"}
    body = json.dumps(kwargs).encode("utf-8")
    conn.request("POST", TOKEN_ENDPOINT, body=body, headers=headers)

    response = conn.getresponse()
    if response.status >= 400:
      logging.error(
          "HTTP Error %s: %s for request body: %s",
          response.status,
          response.reason,
          body,
      )
      raise RuntimeError(
          f"HTTP Error {response.status}: {response.reason} for request body:"
          f" {body}"
      )

    logging.info(
        "Successfully retrieved attestation token from socket: %s", socket_path
    )
    return response.read()


def get_cvm_token_bytes(audience: str, nonces: Sequence[str]) -> bytes:
  """Retrieves custom attestation token bytes via gotpm token CLI.

  Args:
    audience: The audience for the token.
    nonces: A sequence of nonces to include in the token.

  Returns:
    The attestation token bytes.

  Raises:
    RuntimeError: If the gotpm token command fails.
  """
  cmd = ["gotpm", "token", "--audience", audience]
  for n in nonces:
    cmd.extend(["--custom-nonce", n])
  result = subprocess.run(cmd, capture_output=True, check=False)
  if result.returncode != 0:
    logging.error("gotpm token failed: %r", result.stderr)
    raise RuntimeError(f"gotpm token failed: {result.stderr!r}")
  logging.info("Successfully retrieved attestation token from gotpm")
  return result.stdout.strip()


class TokenManager:
  """A manager for refreshing of keys and attestation tokens."""

  def __init__(
      self,
      *,
      key_manager: keys.KeyManager,
      jitter_window_seconds: float = 60.0,
      rng: random.Random | None = None,
      attestation_token_path: pathlib.Path = pathlib.Path(
          "attestation_token.txt"
      ),
  ):
    self.key_manager = key_manager
    self.attestation_token_path = attestation_token_path
    self.jitter_window_seconds = jitter_window_seconds
    self.rng = rng if rng is not None else random.Random()
    self._stop_event = threading.Event()
    self._thread = threading.Thread(target=self._run, daemon=True)
    self._lock = threading.Lock()

  def __repr__(self):
    return (
        f"TokenManager(key_manager={self.key_manager!r},"
        f" attestation_token_path={self.attestation_token_path!r},"
        f" jitter_window_seconds={self.jitter_window_seconds!r}"
    )

  @staticmethod
  def _fetch_attestation_token(public_key_fingerprint: str) -> bytes:
    """Attempts to fetch attestation token based on configured attestation type."""
    attestation_type = os.environ.get("ATTESTATION_TYPE", "uds").lower()

    if attestation_type == "uds":
      return get_cs_token_bytes(
          audience=DEFAULT_AUDIENCE,
          token_type=TOKEN_TYPE,
          nonces=[public_key_fingerprint],
      )
    elif attestation_type == "gotpm":
      return get_cvm_token_bytes(
          audience=DEFAULT_AUDIENCE, nonces=[public_key_fingerprint]
      )
    else:
      raise ValueError(f"Unknown ATTESTATION_TYPE {attestation_type!r}.")

  def refresh(self) -> None:
    """Refreshes the public key and attestation token and saves them to files."""
    logging.info("Refreshing keys and attestation token...")
    with self._lock:
      self.key_manager.generate_key_pair()
      public_key = self.key_manager.get_current_public_key()
      public_key_fingerprint = keys.calculate_fingerprint(public_key)

      attestation_token = self._fetch_attestation_token(public_key_fingerprint)
      common.write_file(self.attestation_token_path, attestation_token, 0o644)
    logging.info("Refresh complete.")

  def get_public_key(self) -> bytes:
    """Gets the current public key from the key manager."""
    with self._lock:
      return self.key_manager.get_current_public_key()

  def get_attestation_token(self) -> bytes:
    """Gets the current attestation token from its file."""
    with self._lock:
      try:
        with open(self.attestation_token_path, "rb") as f:
          return f.read()
      except FileNotFoundError:
        return b""

  def get_identity_snapshot(self) -> tuple[bytes, bytes]:
    """Gets the current public key and attestation token together."""
    with self._lock:
      public_key = self.key_manager.get_current_public_key()
      try:
        with open(self.attestation_token_path, "rb") as f:
          token = f.read()
      except FileNotFoundError:
        token = b""
      return public_key, token

  def _calculate_refresh_duration(self) -> float:
    """Calculates how long to sleep until the 90% mark, minus jitter."""
    token_bytes = self.get_attestation_token()

    if not token_bytes:
      logging.info("No token found. Refresh needed immediately.")
      return 0.0

    try:
      claims = jwt.decode(
          token_bytes.decode("utf-8"), options={"verify_signature": False}
      )
      exp = claims.get("exp")
      iat = claims.get("iat")
    except (
        jwt.exceptions.DecodeError,
        jwt.exceptions.InvalidTokenError,
        jwt.exceptions.InvalidSignatureError,
        jwt.exceptions.InvalidAlgorithmError,
    ):
      logging.exception(
          "Failed to parse token from %r for timing. Refreshing immediately.",
          self.attestation_token_path,
      )
      return 0.0

    if not exp or not iat:
      return 0.0

    now = time.time()
    lifespan = exp - iat
    target_time = iat + (lifespan * DEFAULT_REFRESH_MULTIPLIER)

    wait_seconds = target_time - now
    jitter = self.rng.uniform(0, self.jitter_window_seconds)
    return max(0.0, wait_seconds - jitter)

  def _run(self):
    """Checks if the token is expired based on iat and exp claims."""
    while not self._stop_event.is_set():
      try:
        sleep_duration = self._calculate_refresh_duration()
        if self._stop_event.wait(timeout=sleep_duration):
          break
        self.refresh()

      except (OSError, RuntimeError, ValueError):
        logging.exception("Refresher failed with unexpected error.")
        time.sleep(DEFAULT_RETRY_INTERVAL_SECONDS)

  def __enter__(self) -> "TokenManager":
    logging.info("Starting token manager.")
    self._thread.start()
    self._stop_event.clear()
    return self

  def __exit__(
      self,
      exc_type: type[BaseException] | None,
      exc_val: BaseException | None,
      exc_tb: types.TracebackType | None,
  ) -> None:
    logging.info("Stopping token manager.")
    self._stop_event.set()
    self._thread.join()
