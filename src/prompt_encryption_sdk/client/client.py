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

"""Client for making attested prompt encryption requests."""

import dataclasses
import os
from typing import Any

from prompt_encryption_sdk.proto import attestation_pb2
from google.protobuf import text_format
import requests
import requests.adapters

from . import connection
from . import constants
from . import core_adapter


class AttestedHTTPSAdapter(requests.adapters.HTTPAdapter):
  """Requests Adapter that enforces attestation on HTTPS connections."""

  def __init__(
      self, *,
      policy: attestation_pb2.AttestationPolicy,
      revalidation_timeout: int | None,
      **kwargs
  ):
    self._policy = policy
    self._revalidation_timeout = revalidation_timeout
    if self._revalidation_timeout is None:
      self._revalidation_timeout = constants.DEFAULT_REVALIDATION_TIMEOUT
    super().__init__(**kwargs)

  def __repr__(self) -> str:
    policy_str = text_format.MessageToString(self._policy, as_one_line=True)
    return (
        f"{self.__class__.__name__}(policy={policy_str}, "
        f"revalidation_timeout={self._revalidation_timeout!r})"
    )

  def init_poolmanager(
      self, connections, maxsize, block=False, **pool_kwargs
  ) -> None:
    """Overrides pool manager initialization to use AttestedPoolManager."""
    self._pool_connections = connections
    self._pool_maxsize = maxsize
    self._pool_block = block

    self.poolmanager = connection.AttestedPoolManager(
        num_pools=connections,
        maxsize=maxsize,
        block=block,
        policy=self._policy,
        revalidation_timeout=self._revalidation_timeout,
        **pool_kwargs
    )


@dataclasses.dataclass
class PromptEncryptionClient:
  """Client SDK for establishing attested connections to Prompt Encryption servers.

  Usage:
      policy = attestation_pb2.AttestationPolicy(...)
      # Auto-revalidate every 55 minutes (default)
      client = PromptEncryptionClient(policy)

      # Or customize the interval
      client = PromptEncryptionClient(policy, revalidation_timeout=1800)

      with client.session() as session:
        response = session.post("https://server/infer", json=data)

  Attributes:
      policy: The security policy to enforce.
      revalidation_timeout: Seconds before a session is considered 'stale' and
        requires re-attestation. Default: 3300s (55m).
  """

  policy: attestation_pb2.AttestationPolicy
  revalidation_timeout: int | None = None

  def session(self) -> requests.Session:
    """Creates a new requests.Session with the Attested Adapter mounted."""
    session = requests.Session()
    core_binary = core_adapter.configured_core_binary()
    if core_binary:
      if not os.path.isfile(core_binary) or not os.access(core_binary, os.X_OK):
        raise ValueError(
            "PROMPT_ENCRYPTION_CLIENT_CORE must name an executable file"
        )
      adapter = core_adapter.CoreHTTPSAdapter(
          policy=self.policy,
          executable=core_binary,
          revalidation_timeout=self.revalidation_timeout,
      )
    else:
      adapter = AttestedHTTPSAdapter(
          policy=self.policy, revalidation_timeout=self.revalidation_timeout
      )
    session.mount("https://", adapter)
    return session

  @classmethod
  def post(
      cls,
      policy: attestation_pb2.AttestationPolicy,
      url: str,
      json: Any,
      revalidation_timeout: int | None = None,
      **kwargs
  ) -> requests.Response:
    """Convenience method for a single-shot attested request."""
    with cls(policy, revalidation_timeout=revalidation_timeout).session() as sess:
      return sess.post(url, json=json, **kwargs)
