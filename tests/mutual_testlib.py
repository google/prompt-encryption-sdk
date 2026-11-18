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

"""Shared fakes for the mutual attestation tests.

The unit tests in `tests/` and the real-TLS integration tests in
`tests/integration/` both import this module. It is in `tests/`, not in a
subdirectory, because the export puts `tests/` outside the package: there, the
tests import it as the top-level module `mutual_testlib`. pytest puts `tests/`
on `sys.path` because `tests/conftest.py` is there and `tests/` has no
`__init__.py`.

Google Cloud Attestation (GCA) is the only fake, because a real token needs a
live Confidential Space workload. Keys, signatures, `TokenManager`, and
`AttestationValidator` are real.
"""

from collections.abc import Mapping
import hashlib
import pathlib
import secrets
import time
from typing import Any, Protocol, cast

from prompt_encryption_sdk import attestation
from prompt_encryption_sdk.client import constants
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation as server_attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token
import jwt

TLS_1_3 = "TLSv1.3"
TLS_1_2 = "TLSv1.2"

_FAKE_GCA_ALGORITHM = "HS256"
_TOKEN_LIFETIME_SECONDS = 3600
_TOKEN_FILENAME = "attestation_token.txt"


class FakeGca:
  """Stands in for GCA, both as the token issuer and as the OIDC validator.

  Tokens are real JWTs that a per-instance secret signs. `validate_token`
  checks them like `validator.OIDCTokenValidator` does: the signature, the
  `typ` header, the issuer, the audience, and the expiry, with no clock skew
  allowance. Unlike `tls_testlib.FakeGca`, it can issue a token with any
  expiry, which the expiry tests need.
  """

  def __init__(self):
    """Initializes the instance with a new signing secret."""
    self._secret = secrets.token_bytes(32)

  def __repr__(self) -> str:
    return "FakeGca()"

  def issue_token(
      self,
      key_manager: keys.KeyManager,
      *,
      audience: str = constants.DEFAULT_AUDIENCE,
      expires_at: float | None = None,
      extra_claims: Mapping[str, Any] | None = None,
  ) -> bytes:
    """Issues a token that binds the current keys of `key_manager`.

    Args:
      key_manager: Holds the ECDSA and ML-DSA public keys to bind.
      audience: The `aud` claim.
      expires_at: The `exp` claim, in Unix seconds. Defaults to one hour from
        now, like a new GCA token.
      extra_claims: More claims, for example `submods` for a policy test. They
        replace the default claims with the same name.

    Returns:
      The token, in the same form that the TEE server returns it.
    """
    now = int(time.time())
    claims = {
        "iss": constants.CS_DEFAULT_ISSUER,
        "aud": audience,
        "iat": now,
        "exp": (
            now + _TOKEN_LIFETIME_SECONDS
            if expires_at is None
            else int(expires_at)
        ),
        "eat_nonce": [
            keys.calculate_fingerprint(key_manager.get_current_public_key()),
            keys.calculate_fingerprint(
                key_manager.get_current_pqc_public_key()
            ),
        ],
        "swname": "CONFIDENTIAL_SPACE",
        "submods": {"container": {}, "gce": {}, "confidential_space": {}},
    }
    claims.update(extra_claims or {})
    encoded = jwt.encode(
        claims,
        self._secret,
        algorithm=_FAKE_GCA_ALGORITHM,
        headers={"typ": "JWT"},
    )
    return encoded.encode("utf-8")

  # The parameter is `token_str`, not `token` as in OIDCTokenValidator, so that
  # it does not shadow the `token` module. AttestationValidator passes the token
  # by position.
  def validate_token(
      self,
      token_str: str,
      *,
      expected_audience: str = constants.DEFAULT_AUDIENCE,
  ) -> dict[str, Any]:
    """Verifies a token like `validator.OIDCTokenValidator.validate_token`.

    Args:
      token_str: The raw JWT.
      expected_audience: The `aud` claim that the token must have.

    Returns:
      The verified claims.

    Raises:
      exceptions.AttestationVerificationError: If this fake did not issue the
        token, or if the token is expired, is for another audience or issuer,
        or does not have the `typ: JWT` header.
    """
    try:
      if jwt.get_unverified_header(token_str).get("typ") != "JWT":
        raise jwt.InvalidTokenError("The typ header is not JWT.")
      return jwt.decode(
          token_str,
          self._secret,
          algorithms=[_FAKE_GCA_ALGORITHM],
          audience=expected_audience,
          issuer=constants.CS_DEFAULT_ISSUER,
          # Like Tink, refuse a token without an expiry.
          options={"require": ["exp"]},
      )
    except jwt.InvalidTokenError as e:
      raise exceptions.AttestationVerificationError(
          "OIDC Token validation failed."
      ) from e

  def close(self) -> None:
    """Matches `validator.OIDCTokenValidator.close`."""

  def validator_factory(
      self, policy: attestation_pb2.AttestationPolicy
  ) -> validator.AttestationValidator:
    """Makes a real validator that uses this fake to verify tokens.

    Use it as `attestation_validator_cls` on the client and on `AttestedTLS`.

    Args:
      policy: The policy that the peer must satisfy.

    Returns:
      An `AttestationValidator` with this fake as its OIDC validator.
    """
    oidc_validator = cast(validator.OIDCTokenValidator, self)
    return validator.AttestationValidator(policy, oidc_validator=oidc_validator)


def make_token_manager(
    directory: pathlib.Path,
    gca: FakeGca,
    *,
    expires_at: float | None = None,
) -> token.TokenManager:
  """Makes a real TokenManager with real keys and a token from `gca`.

  The test never enters the TokenManager, so it never calls the TEE server.
  Instead, this function writes the token file that `TokenManager.refresh()`
  writes after it gets a token. Use the result as the server identity, or as
  the `client_token_manager` of a mutual client.

  Args:
    directory: A directory for the key and token files. It is created if it does
      not exist.
    gca: Issues the attestation token.
    expires_at: The `exp` claim of the token. Defaults to one hour from now.

  Returns:
    A TokenManager that can produce attestation proofs.
  """
  directory.mkdir(parents=True, exist_ok=True)
  key_manager = keys.KeyManager(
      private_key_path=directory / "ecdsa_private.pem",
      public_key_path=directory / "ecdsa_public.pem",
      pqc_private_key_path=directory / "mldsa_private.bin",
      pqc_public_key_path=directory / "mldsa_public.bin",
  )
  key_manager.generate_key_pair()
  token_manager = token.TokenManager(
      key_manager=key_manager,
      attestation_token_path=directory / _TOKEN_FILENAME,
  )
  reissue_token(token_manager, gca, expires_at=expires_at)
  return token_manager


def reissue_token(
    token_manager: token.TokenManager,
    gca: FakeGca,
    *,
    expires_at: float | None = None,
    extra_claims: Mapping[str, Any] | None = None,
) -> None:
  """Replaces the token of `token_manager`, as a token refresh does.

  The next proof that `token_manager` produces carries the new token.

  Args:
    token_manager: A TokenManager from `make_token_manager`.
    gca: Issues the new token.
    expires_at: The `exp` claim. Defaults to one hour from now.
    extra_claims: More claims; see `FakeGca.issue_token`.
  """
  token_manager.attestation_token_path.write_bytes(
      gca.issue_token(
          token_manager.key_manager,
          audience=token_manager.audience,
          expires_at=expires_at,
          extra_claims=extra_claims,
      )
  )


class FakeTlsSession:
  """Stands in for the TLS object of one session, for tests without sockets.

  Both peers of a session get the same keying material from it, as from a real
  TLS session. A different `secret` models a different session. Pass it as
  `ssl_obj` to `AttestedTLS.attest_connection`.
  """

  def __init__(
      self,
      secret: bytes = b"fake-tls-session",
      *,
      tls_version: str = TLS_1_3,
  ):
    """Initializes the instance.

    Args:
      secret: Stands for the session's master secret. Two instances with the
        same secret model the same session.
      tls_version: What `version()` returns, for example `TLS_1_2`.
    """
    self._secret = secret
    self._tls_version = tls_version

  def __repr__(self) -> str:
    return f"FakeTlsSession(tls_version={self._tls_version!r})"

  def version(self) -> str:
    """Returns the negotiated protocol, like `ssl.SSLObject.version`."""
    return self._tls_version

  def export_keying_material(
      self, label: bytes, length: int, context: bytes | None = None
  ) -> bytes:
    """Derives keying material like RFC 5705: no context differs from b""."""
    seed = self._secret + label
    if context is not None:
      seed += b"\x01" + context
    return hashlib.sha256(seed).digest()[:length]

  def ekm(self) -> bytes:
    """Returns the keying material that both peers bind in mutual mode."""
    return self.export_keying_material(
        attestation.EKM_LABEL, attestation.EKM_LENGTH
    )


def mutual_request(
    client_identity: attestation.IdentitySnapshotProvider,
    tls_ekm: bytes,
    **overrides: Any,
) -> attestation_pb2.AttestConnectionRequest:
  """Builds the request that a mutual client sends, with its own proof.

  Args:
    client_identity: The client TokenManager that signs the proof.
    tls_ekm: The keying material of the session.
    **overrides: AttestConnectionRequest fields that replace the correct ones,
      for example `protocol_version=2` or `client_attestation=other_proof`.

  Returns:
    The request.
  """
  fields: dict[str, Any] = dict(
      required_verifier_type=[attestation_pb2.VERIFIER_TYPE_GCA],
      protocol_version=attestation.MUTUAL_ATTESTATION_PROTOCOL_VERSION,
      mode=attestation_pb2.ATTESTATION_MODE_MUTUAL,
      client_attestation=client_proof(client_identity, tls_ekm),
  )
  fields.update(overrides)
  return attestation_pb2.AttestConnectionRequest(**fields)


def client_proof(
    client_identity: attestation.IdentitySnapshotProvider,
    tls_ekm: bytes,
    *,
    peer_role: attestation_pb2.AttestationPeerRole = (
        attestation_pb2.ATTESTATION_PEER_ROLE_CLIENT
    ),
    mode: attestation_pb2.AttestationMode = (
        attestation_pb2.ATTESTATION_MODE_MUTUAL
    ),
) -> attestation_pb2.AttestationProof:
  """Signs a proof as a mutual client does; override a field to forge one.

  When `(mode, peer_role)` is not a pair that `build_signature_payload`
  accepts, builds and signs the raw `SessionSignaturePayload` directly to
  simulate a hostile peer for negative tests.

  Args:
    client_identity: The TokenManager that signs the proof.
    tls_ekm: The keying material of the session.
    peer_role: The role to sign as.
    mode: The mode to sign for.

  Returns:
    The proof.
  """
  try:
    return attestation.AttestationProver(client_identity).create_proof(
        tls_ekm, peer_role=peer_role, mode=mode
    )
  except ValueError:
    pass
  ecdsa_public_key, pqc_public_key, attestation_token = (
      client_identity.get_identity_snapshot()
  )
  protocol_version = (
      attestation.MUTUAL_ATTESTATION_PROTOCOL_VERSION
      if mode == attestation_pb2.ATTESTATION_MODE_MUTUAL
      else 0
  )
  payload = attestation_pb2.SessionSignaturePayload(
      ekm_hash=hashlib.sha256(tls_ekm).digest(),
      token_hash=hashlib.sha256(attestation_token).digest(),
      peer_role=peer_role,
      mode=mode,
      protocol_version=protocol_version,
  ).SerializeToString(deterministic=True)
  return attestation_pb2.AttestationProof(
      evidence=[
          attestation_pb2.AttestationEvidence(
              verifier_type=attestation_pb2.VERIFIER_TYPE_GCA,
              gca_bundle=attestation_pb2.GcaTrustBundle(
                  attestation_token=attestation_token.decode("utf-8")
              ),
          )
      ],
      instance_public_key=attestation_pb2.EcdsaP256PublicKey(
          key_bytes=ecdsa_public_key
      ),
      session_signature=client_identity.key_manager.sign_payload(payload),
      pqc_public_key=attestation_pb2.MlDsaPublicKey(
          serialized_public_keyset=pqc_public_key
      ),
      pqc_session_signature=client_identity.key_manager.sign_payload_mldsa(
          payload
      ),
  )


def make_attested_tls(
    server_identity: token.TokenManager,
    gca: FakeGca,
    *,
    client_policy: attestation_pb2.AttestationPolicy | None = None,
    require_mutual_attestation: bool = False,
) -> server_attestation.AttestedTLS:
  """Makes the real server handler, with `gca` as the client verifier.

  Args:
    server_identity: The server TokenManager.
    gca: Verifies the client tokens.
    client_policy: The policy that clients must satisfy. None disables mutual
      attestation.
    require_mutual_attestation: Whether to reject server-only clients.

  Returns:
    The handler.
  """
  return server_attestation.AttestedTLS(
      server_identity,
      client_policy=client_policy,
      require_mutual_attestation=require_mutual_attestation,
      attestation_validator_cls=gca.validator_factory,
  )


class TlsTestServer(Protocol):
  """The parts of a `tls_testlib.TlsServer` that `enable_mutual` changes.

  Attributes:
    attested_tls: The handler behind the middleware.
    middleware: The WSGI or ASGI middleware, which reads `attested_tls` on every
      request.
  """

  attested_tls: server_attestation.AttestedTLS
  middleware: Any


def enable_mutual(
    server: TlsTestServer,
    gca: FakeGca,
    *,
    client_policy: attestation_pb2.AttestationPolicy,
    require_mutual_attestation: bool = False,
) -> None:
  """Turns on mutual attestation on a `tls_testlib` WSGI or ASGI test server.

  `tls_testlib` makes the server with no client policy, and the safety tests
  must not change, so this replaces the handler behind the middleware. Call it
  before the first connection.

  Args:
    server: A `tls_testlib.WsgiTlsServer` or `tls_testlib.AsgiTlsServer`.
    gca: Verifies the client tokens.
    client_policy: The policy that clients must satisfy.
    require_mutual_attestation: Whether to reject server-only clients.
  """
  attested_tls = make_attested_tls(
      server.attested_tls.token_manager,
      gca,
      client_policy=client_policy,
      require_mutual_attestation=require_mutual_attestation,
  )
  server.attested_tls = attested_tls
  server.middleware.attested_tls = attested_tls
