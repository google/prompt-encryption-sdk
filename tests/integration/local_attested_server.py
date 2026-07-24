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

"""Hermetic attested TLS server used by cross-language contract tests."""

import base64
import datetime
import hashlib
from http import server
import ipaddress
import json
import pathlib
import ssl
import tempfile
import threading
import time
from typing import Any

from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from google.protobuf import json_format
import jwt


_AUDIENCE = "https://sts.google.com"
_IMAGE_HASH = "sha256:test-image"
_PROJECT_ID = "test-project"
_ZONE = "test-zone"


def _base64url_uint(value: int) -> str:
  length = (value.bit_length() + 7) // 8
  return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(
      b"="
  ).decode("ascii")


def make_policy() -> attestation_pb2.AttestationPolicy:
  return attestation_pb2.AttestationPolicy(
      hw_model=attestation_pb2.HARDWARE_MODEL_TDX,
      workload=attestation_pb2.WorkloadPolicy(image_hash=_IMAGE_HASH),
      gce_instance=attestation_pb2.GceInstancePolicy(
          project_id=_PROJECT_ID,
          zone=_ZONE,
      ),
  )


class _SigningKeyManager:

  def __init__(self, private_key: ec.EllipticCurvePrivateKey):
    self._private_key = private_key

  def sign_payload(self, payload: bytes) -> bytes:
    return self._private_key.sign(payload, ec.ECDSA(hashes.SHA256()))


class _TokenManager:

  def __init__(self, private_key: ec.EllipticCurvePrivateKey, token: str):
    self.key_manager = _SigningKeyManager(private_key)
    self._public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    self._token = token.encode("utf-8")

  def get_identity_snapshot(self) -> tuple[bytes, bytes]:
    return self._public_key, self._token


class _ThreadingHttpServer(server.ThreadingHTTPServer):
  daemon_threads = True


class _OidcHandler(server.BaseHTTPRequestHandler):
  protocol_version = "HTTP/1.1"

  def do_GET(self) -> None:  # pylint: disable=invalid-name
    oidc_server = self.server
    if self.path == "/.well-known/openid-configuration":
      self._write_json({
          "issuer": oidc_server.issuer,
          "jwks_uri": f"{oidc_server.issuer}/jwks",
      })
      return
    if self.path == "/jwks":
      self._write_json(oidc_server.jwks)
      return
    self.send_error(404)

  def _write_json(self, payload: Any) -> None:
    encoded = json.dumps(payload).encode("utf-8")
    self.send_response(200)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(encoded)))
    self.end_headers()
    self.wfile.write(encoded)

  def log_message(self, *_args: Any) -> None:
    pass


class _AttestedHandler(server.BaseHTTPRequestHandler):
  protocol_version = "HTTP/1.1"

  def do_POST(self) -> None:  # pylint: disable=invalid-name
    if self.path == "/_attest-connection":
      self._attest()
      return

    connection_id = id(self.connection)
    if connection_id not in self.server.attested_connections:
      self._write_json(401, {"error": "connection is not attested"})
      return

    length = int(self.headers.get("Content-Length", "0"))
    payload = json.loads(self.rfile.read(length) or b"{}")
    self.server.application_request_count += 1
    self._write_json(200, {"received": payload})

  def _attest(self) -> None:
    length = int(self.headers.get("Content-Length", "0"))
    body = json.loads(self.rfile.read(length) or b"{}")
    request = json_format.ParseDict(
        body, attestation_pb2.AttestConnectionRequest()
    )
    response = self.server.attested_tls.attest_connection(
        request, ssl_obj=self.connection
    )
    self.server.attestation_count += 1
    if self.server.tamper_session_signature:
      response.session_signature = b"tampered-session-signature"
    self.server.attested_connections.add(id(self.connection))
    self._write_json(200, json_format.MessageToDict(response))

  def _write_json(self, status: int, payload: Any) -> None:
    encoded = json.dumps(payload).encode("utf-8")
    self.send_response(status)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(encoded)))
    self.end_headers()
    self.wfile.write(encoded)

  def log_message(self, *_args: Any) -> None:
    pass


class LocalAttestedServer:
  """Runs a local OIDC issuer and attested TLS echo server."""

  def __init__(self, *, tamper_session_signature: bool = False):
    self._tempdir = tempfile.TemporaryDirectory()
    self._threads: list[threading.Thread] = []
    self._servers: list[_ThreadingHttpServer] = []

    oidc_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    oidc_numbers = oidc_private_key.public_key().public_numbers()
    self._oidc = _ThreadingHttpServer(("127.0.0.1", 0), _OidcHandler)
    self._oidc.issuer = f"http://127.0.0.1:{self._oidc.server_port}"
    self._oidc.jwks = {
        "keys": [{
            "kty": "RSA",
            "kid": "local-test-key",
            "use": "sig",
            "alg": "RS256",
            "n": _base64url_uint(oidc_numbers.n),
            "e": _base64url_uint(oidc_numbers.e),
        }]
    }
    self._start(self._oidc)

    instance_key = ec.generate_private_key(ec.SECP256R1())
    public_key = instance_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_fingerprint = hashlib.sha256(public_key).hexdigest()
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": self._oidc.issuer,
            "aud": _AUDIENCE,
            "iat": now - 1,
            "exp": now + 300,
            "hwmodel": "GCP_INTEL_TDX",
            "eat_nonce": [key_fingerprint],
            "submods": {
                "container": {"image_digest": _IMAGE_HASH},
                "gce": {"project_id": _PROJECT_ID, "zone": _ZONE},
            },
        },
        oidc_private_key,
        algorithm="RS256",
        headers={"kid": "local-test-key", "typ": "JWT"},
    )

    cert_path, key_path = self._create_tls_certificate()
    self._cert_path = cert_path
    self._tls = _ThreadingHttpServer(("127.0.0.1", 0), _AttestedHandler)
    self._tls.attested_tls = attestation.AttestedTLS(
        _TokenManager(instance_key, token)
    )
    self._tls.attested_connections = set()
    self._tls.attestation_count = 0
    self._tls.application_request_count = 0
    self._tls.tamper_session_signature = tamper_session_signature
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert_path, key_path)
    self._tls.socket = context.wrap_socket(self._tls.socket, server_side=True)
    self._start(self._tls)

  @property
  def url(self) -> str:
    return f"https://127.0.0.1:{self._tls.server_port}"

  @property
  def oidc_discovery_url(self) -> str:
    return f"{self._oidc.issuer}/.well-known/openid-configuration"

  @property
  def ca_path(self) -> str:
    return self._cert_path

  @property
  def attestation_count(self) -> int:
    return self._tls.attestation_count

  @property
  def application_request_count(self) -> int:
    return self._tls.application_request_count

  def close(self) -> None:
    for running_server in reversed(self._servers):
      running_server.shutdown()
      running_server.server_close()
    for thread in self._threads:
      thread.join(timeout=2)
    self._tempdir.cleanup()

  def _start(self, running_server: _ThreadingHttpServer) -> None:
    thread = threading.Thread(
        target=running_server.serve_forever, daemon=True
    )
    self._servers.append(running_server)
    self._threads.append(thread)
    thread.start()

  def _create_tls_certificate(self) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    temp_path = pathlib.Path(self._tempdir.name)
    cert_path = temp_path / "cert.pem"
    key_path = temp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)
