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

"""Key management logic for Prompt Encryption SDK."""

import hashlib
import pathlib
from absl import logging
from prompt_encryption_sdk.server import common
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import tink
from tink import secret_key_access
from tink import signature

signature.register()


class KeyManager:
  """Manages the generation, storage, and rotation of cryptographic keys."""

  def __init__(
      self,
      *,
      private_key_path: pathlib.Path = pathlib.Path("/dev/shm/private_key.pem"),
      public_key_path: pathlib.Path = pathlib.Path("/dev/shm/public_key.pem"),
      pqc_private_key_path: pathlib.Path = pathlib.Path(
          "/dev/shm/mldsa_private.bin"
      ),
      pqc_public_key_path: pathlib.Path = pathlib.Path(
          "/dev/shm/mldsa_public.bin"
      ),
      write_file_fn: common.FileWriter | None = None,
      read_file_fn: common.FileReader | None = None,
  ):
    """Initializes the KeyManager.

    Args:
        private_key_path: File path to store the ECDSA private key.
        public_key_path: File path to store the ECDSA public key.
        pqc_private_key_path: File path to store the PQC private keyset.
        pqc_public_key_path: File path to store the PQC public keyset.
        write_file_fn: Function to write files. Defaults to the internal
          `common.write_file`.
        read_file_fn: Function to read files. Defaults to the internal
          `common.read_file`.
    """
    self.private_key_path = private_key_path
    self.public_key_path = public_key_path
    self.pqc_private_key_path = pqc_private_key_path
    self.pqc_public_key_path = pqc_public_key_path
    self._write_file_fn = (
        write_file_fn if write_file_fn is not None else common.write_file
    )
    self._read_file_fn = (
        read_file_fn if read_file_fn is not None else common.read_file
    )

  def __repr__(self):
    return (
        f"KeyManager(private_key_path={self.private_key_path!r},"
        f" public_key_path={self.public_key_path!r},"
        f" pqc_private_key_path={self.pqc_private_key_path!r},"
        f" pqc_public_key_path={self.pqc_public_key_path!r},"
        f" write_file_fn={self._write_file_fn!r},"
        f" read_file_fn={self._read_file_fn!r})"
    )

  def generate_key_pair(self) -> bytes:
    """Generates ECDSA P-256 and ML-DSA-65 key pairs and saves them."""
    logging.info(
        "Generating new key pairs. "
        "ECDSA Private: %s, ECDSA Public: %s, "
        "PQC Private: %s, PQC Public: %s",
        self.private_key_path,
        self.public_key_path,
        self.pqc_private_key_path,
        self.pqc_public_key_path,
    )

    # 1. Generate Classical ECDSA Key Pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    self._write_file_fn(self.private_key_path, pem_private, 0o600)
    self._write_file_fn(self.public_key_path, pem_public, 0o644)

    # 2. Generate PQC ML-DSA-65 Key Pair using Tink
    mldsa_template = signature.signature_key_templates.ML_DSA_65
    pqc_private_handle = tink.new_keyset_handle(mldsa_template)
    pqc_public_handle = pqc_private_handle.public_keyset_handle()

    # Serialize PQC private keyset
    pqc_private_bytes = tink.proto_keyset_format.serialize(
        pqc_private_handle, secret_key_access.TOKEN
    )
    self._write_file_fn(self.pqc_private_key_path, pqc_private_bytes, 0o600)

    # Serialize PQC public keyset
    pqc_public_bytes = tink.proto_keyset_format.serialize_without_secret(
        pqc_public_handle
    )
    self._write_file_fn(self.pqc_public_key_path, pqc_public_bytes, 0o644)

    logging.info("Successfully generated and saved ECDSA and PQC key pairs.")
    return pem_public

  def sign_payload(self, payload: bytes) -> bytes:
    """Signs a payload using the ECDSA private key.

    Args:
      payload: The bytes of the payload to be signed.

    Returns:
      The ECDSA signature of the payload.
    """
    private_key_bytes = self._read_file_fn(self.private_key_path)
    private_key = serialization.load_pem_private_key(
        private_key_bytes, password=None
    )
    return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))

  def sign_payload_mldsa(self, payload: bytes) -> bytes:
    """Signs a payload using the ML-DSA private key.

    Args:
      payload: The bytes of the payload to be signed.

    Returns:
      The ML-DSA signature of the payload.
    """
    pqc_private_bytes = self._read_file_fn(self.pqc_private_key_path)
    pqc_private_handle = tink.proto_keyset_format.parse(
        pqc_private_bytes, secret_key_access.TOKEN
    )
    signer = pqc_private_handle.primitive(signature.PublicKeySign)
    return signer.sign(payload)

  def get_current_public_key(self) -> bytes:
    """Reads and returns the ECDSA public key bytes."""
    return self._read_file_fn(self.public_key_path)

  def get_current_pqc_public_key(self) -> bytes:
    """Reads and returns the PQC public keyset bytes."""
    return self._read_file_fn(self.pqc_public_key_path)


def calculate_fingerprint(public_key: bytes) -> str:
  """Calculates the SHA-256 fingerprint of the public key."""
  return hashlib.sha256(public_key).hexdigest()
