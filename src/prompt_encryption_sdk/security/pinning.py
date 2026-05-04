# Copyright 2026 Google LLC
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

"""Certificate pinning via SHA256 fingerprint validation."""

import hashlib
import logging
from typing import Dict, List, Optional

from prompt_encryption_sdk.client import exceptions

logger = logging.getLogger(__name__)


class CertificatePinner:
  """Validates certificates against SHA256 fingerprints.
  
  Implements certificate pinning to prevent MITM attacks via compromised CAs.
  Stores SHA256 hashes of the actual certificates and validates against them.
  """

  def __init__(
      self,
      pinned_fingerprints: Dict[str, List[str]],
      security_logger=None,
  ):
    """Initializes the certificate pinner.
    
    Args:
      pinned_fingerprints: Map of hostname -> list of allowed SHA256 fingerprints
        in hex format (lowercase). Example:
        {
          "api.example.com": [
            "abcd1234...",  # Primary
            "efgh5678...",  # Backup
          ]
        }
      security_logger: Optional SecurityLogger for structured logging.
    
    Raises:
      ValueError: If fingerprints are invalid format.
    """
    self._pinned_fingerprints = pinned_fingerprints
    self._security_logger = security_logger
    self._validate_fingerprint_format()

  def _validate_fingerprint_format(self):
    """Validates that all fingerprints are valid hex strings."""
    for hostname, fingerprints in self._pinned_fingerprints.items():
      if not isinstance(fingerprints, list):
        raise ValueError(
            f"Fingerprints for {hostname} must be a list, "
            f"got {type(fingerprints)}"
        )
      
      for fp in fingerprints:
        if not isinstance(fp, str):
          raise ValueError(
              f"Fingerprint for {hostname} must be string, got {type(fp)}"
          )
        
        # Validate hex format (64 chars for SHA256)
        if len(fp) != 64:
          raise ValueError(
              f"SHA256 fingerprint must be 64 hex chars, got {len(fp)}: {fp}"
          )
        
        try:
          int(fp, 16)
        except ValueError:
          raise ValueError(f"Invalid hex fingerprint: {fp}")

  def validate_certificate(
      self,
      cert_der: bytes,
      hostname: str,
  ) -> None:
    """Validates a DER certificate against pinned fingerprints.
    
    Args:
      cert_der: Certificate in DER format (binary).
      hostname: The hostname being validated.
    
    Raises:
      AttestationHandshakeError: If cert fingerprint doesn't match pins.
    """
    if hostname not in self._pinned_fingerprints:
      # No pins configured for this host
      logger.debug(f"No certificate pins configured for {hostname}; skipping")
      return

    # Calculate SHA256 fingerprint of certificate
    cert_fingerprint = hashlib.sha256(cert_der).hexdigest().lower()
    allowed_fingerprints = self._pinned_fingerprints[hostname]

    # Check if cert matches any pinned fingerprint
    if cert_fingerprint not in allowed_fingerprints:
      error_msg = (
          f"Certificate pin validation failed for {hostname}. "
          f"Got fingerprint {cert_fingerprint}, "
          f"expected one of {allowed_fingerprints}"
      )
      
      if self._security_logger:
        self._security_logger.log_certificate_validation(
            hostname=hostname,
            valid=False,
            reason="Fingerprint mismatch",
        )
      
      logger.warning(error_msg)
      raise exceptions.AttestationHandshakeError(
          f"Certificate pin validation failed for {hostname}"
      )

    logger.info(f"Certificate pin validation passed for {hostname}")
    
    if self._security_logger:
      self._security_logger.log_certificate_validation(
          hostname=hostname,
          valid=True,
          fingerprint=cert_fingerprint[:16] + "...",  # Log only first 16 chars
      )

  def get_certificate_der_from_socket(self, sock) -> Optional[bytes]:
    """Extracts DER certificate from SSL socket.
    
    Args:
      sock: The SSL socket connection.
    
    Returns:
      DER certificate bytes, or None if unavailable.
    """
    try:
      # Get peer certificate in DER format
      cert_der = sock.getpeercert(binary_form=True)
      return cert_der
    except Exception as e:
      logger.warning(f"Could not extract certificate from socket: {e}")
      return None
