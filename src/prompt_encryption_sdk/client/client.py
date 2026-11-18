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
from typing import Any

from prompt_encryption_sdk import attestation as attestation_protocol
from prompt_encryption_sdk.proto import attestation_pb2
from google.protobuf import text_format
import requests
import requests.adapters

from . import connection
from . import constants


class AttestedHTTPSAdapter(requests.adapters.HTTPAdapter):
  """Requests Adapter that enforces attestation on HTTPS connections."""

  def __init__(
      self,
      *,
      policy: attestation_pb2.AttestationPolicy,
      revalidation_timeout: int | None,
      mutual_attestation: bool = False,
      attestation_prover: attestation_protocol.AttestationProver | None = None,
      **kwargs: Any,
  ):
    """Initializes the instance.

    Args:
      policy: The policy that the server must satisfy.
      revalidation_timeout: Seconds after which a server-only session attests
        again on the same connection. None means
        `constants.DEFAULT_REVALIDATION_TIMEOUT`.
      mutual_attestation: Whether connections also prove this client's own TEE
        identity.
      attestation_prover: Signs this client's proofs. Required when
        `mutual_attestation` is true; None otherwise.
      **kwargs: Passed to `requests.adapters.HTTPAdapter`.

    Raises:
      ValueError: If `attestation_prover` is given without
        `mutual_attestation`, or `mutual_attestation` without it.
    """
    connection.validate_mutual_settings(mutual_attestation, attestation_prover)
    self._policy = policy
    self._mutual_attestation = mutual_attestation
    self._attestation_prover = attestation_prover
    self._revalidation_timeout = (
        constants.DEFAULT_REVALIDATION_TIMEOUT
        if revalidation_timeout is None
        else revalidation_timeout
    )
    super().__init__(**kwargs)

  def __repr__(self) -> str:
    policy_str = text_format.MessageToString(self._policy, as_one_line=True)
    return (
        f"{self.__class__.__name__}(policy={policy_str}, "
        f"mutual_attestation={self._mutual_attestation!r}, "
        f"revalidation_timeout={self._revalidation_timeout!r})"
    )

  def init_poolmanager(
      self, connections, maxsize, block=False, **pool_kwargs
  ) -> None:
    """Overrides pool manager initialization to use AttestedPoolManager."""
    self._pool_connections = connections
    self._pool_maxsize = maxsize
    self._pool_block = block

    if self._mutual_attestation:
      pool_kwargs["mutual_attestation"] = True
      pool_kwargs["attestation_prover"] = self._attestation_prover

    self.poolmanager = connection.AttestedPoolManager(
        num_pools=connections,
        maxsize=maxsize,
        block=block,
        policy=self._policy,
        revalidation_timeout=self._revalidation_timeout,
        **pool_kwargs,
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

      # Mutual: this client runs in a TEE too and proves it in the same
      # round trip. No revalidation; open a new connection to re-attest.
      with token_manager:  # server.TokenManager for this client's identity
        client = PromptEncryptionClient(
            policy,
            mutual_attestation=True,
            client_token_manager=token_manager,
        )

  Attributes:
      policy: The security policy to enforce.
      revalidation_timeout: Seconds before a session is considered 'stale' and
        requires re-attestation. Default: 3300s (55m). Not supported when
        mutual_attestation is enabled.
      mutual_attestation: Also prove this client's own TEE identity to the
        server, in the same round trip. Sessions established this way are never
        revalidated; the server drops any session that tries.
      client_token_manager: A started TokenManager (or any object exposing
        `key_manager` and `get_identity_snapshot()`) holding this confidential
        client's keys and attestation token. Required in mutual mode, and not
        allowed otherwise. A process that is both client and server must share
        one `TokenManager` or give each its own key and token paths, because the
        defaults use fixed paths.

  Raises:
    ValueError: If `mutual_attestation` is set without a
      `client_token_manager` or with a `revalidation_timeout`, or if a
      `client_token_manager` is given without `mutual_attestation`.
  """

  policy: attestation_pb2.AttestationPolicy
  revalidation_timeout: int | None = None
  mutual_attestation: bool = False
  client_token_manager: attestation_protocol.IdentitySnapshotProvider | None = (
      None
  )

  def __post_init__(self) -> None:
    if not self.mutual_attestation:
      if self.client_token_manager is not None:
        # Otherwise the client would silently attest only the server.
        raise ValueError(
            "client_token_manager is valid only when mutual_attestation is"
            " enabled."
        )
      return
    if self.client_token_manager is None:
      raise ValueError(
          "client_token_manager is required when mutual_attestation is enabled."
      )
    if self.revalidation_timeout is not None:
      raise ValueError(
          "revalidation_timeout is not supported with mutual_attestation; a"
          " mutually attested session is attested exactly once."
      )

  def session(self) -> requests.Session:
    """Creates a new requests.Session with the Attested Adapter mounted."""
    self.__post_init__()
    session = requests.Session()
    adapter_kwargs: dict[str, Any] = {
        "policy": self.policy,
        "revalidation_timeout": self.revalidation_timeout,
    }
    if self.mutual_attestation and self.client_token_manager is not None:
      adapter_kwargs["mutual_attestation"] = True
      adapter_kwargs["attestation_prover"] = (
          attestation_protocol.AttestationProver(self.client_token_manager)
      )
    adapter = AttestedHTTPSAdapter(**adapter_kwargs)
    session.mount("https://", adapter)
    return session

  @classmethod
  def post(
      cls,
      policy: attestation_pb2.AttestationPolicy,
      url: str,
      json: Any,
      revalidation_timeout: int | None = None,
      mutual_attestation: bool = False,
      client_token_manager: (
          attestation_protocol.IdentitySnapshotProvider | None
      ) = None,
      **kwargs: Any,
  ) -> requests.Response:
    """Sends one attested POST request on a new session.

    Args:
      policy: The policy that the server must satisfy.
      url: The HTTPS URL to post to.
      json: The JSON body.
      revalidation_timeout: See the class attributes. None means the default.
      mutual_attestation: See the class attributes.
      client_token_manager: See the class attributes. Required when
        `mutual_attestation` is true; None otherwise.
      **kwargs: Passed to `requests.Session.post`.

    Returns:
      The response.

    Raises:
      ValueError: If the mutual settings are inconsistent; see the class.
    """
    with cls(
        policy,
        revalidation_timeout=revalidation_timeout,
        mutual_attestation=mutual_attestation,
        client_token_manager=client_token_manager,
    ).session() as session:
      return session.post(url, json=json, **kwargs)
