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

"""Replay attack prevention via nonce and timestamp validation."""

import logging
import time
from typing import Optional, Set, Tuple

from prompt_encryption_sdk.client import exceptions

logger = logging.getLogger(__name__)


class ReplayProtectionValidator:
  """Validates nonces and timestamps to prevent replay attacks.
  
  Tracks recently seen nonces to detect replayed attestations.
  Validates timestamp freshness to catch delayed/stale attestations.
  """

  def __init__(
      self,
      nonce_ttl_seconds: int = 3600,
      timestamp_skew_seconds: int = 60,
      security_logger=None,
  ):
    """Initializes replay protection.
    
    Args:
      nonce_ttl_seconds: How long to remember nonces (default: 1 hour).
      timestamp_skew_seconds: Maximum allowed clock skew (default: 60s).
      security_logger: Optional SecurityLogger for structured logging.
    """
    self._nonce_ttl_seconds = nonce_ttl_seconds
    self._timestamp_skew_seconds = timestamp_skew_seconds
    self._security_logger = security_logger
    
    # In-memory nonce tracking: Set of (nonce_hex, expiry_time) tuples
    self._seen_nonces: Set[Tuple[str, float]] = set()

  def validate_nonce_freshness(
      self,
      nonce: bytes,
      nonce_source: str = "client",
  ) -> None:
    """Validates that a nonce hasn't been seen before.
    
    Args:
      nonce: The nonce bytes to validate.
      nonce_source: Description of where nonce came from (for logging).
    
    Raises:
      AttestationVerificationError: If nonce is a replay.
    """
    nonce_hex = nonce.hex()
    current_time = time.time()
    
    # Clean up expired nonces
    self._seen_nonces = {
        (n, exp) for n, exp in self._seen_nonces
        if exp > current_time
    }
    
    # Check if this nonce was seen before
    for seen_nonce, _ in self._seen_nonces:
      if seen_nonce == nonce_hex:
        error_msg = f"Replay detected: nonce {nonce_hex[:16]}... already seen"
        
        if self._security_logger:
          self._security_logger.log_replay_protection_event(
              event="nonce_replay",
              nonce=nonce_hex[:16] + "...",
              source=nonce_source,
              valid=False,
          )
        
        logger.warning(error_msg)
        raise exceptions.AttestationVerificationError(error_msg)
    
    # Track this nonce
    expiry_time = current_time + self._nonce_ttl_seconds
    self._seen_nonces.add((nonce_hex, expiry_time))
    
    logger.debug(f"Nonce {nonce_hex[:16]}... validated (source: {nonce_source})")
    
    if self._security_logger:
      self._security_logger.log_replay_protection_event(
          event="nonce_accepted",
          nonce=nonce_hex[:16] + "...",
          source=nonce_source,
          valid=True,
      )

  def validate_token_timestamp(
      self,
      token_iat: int,
      token_exp: int,
      current_time: Optional[float] = None,
  ) -> None:
    """Validates that token timestamp is within acceptable range.
    
    Prevents:
    - Tokens issued in the future (clock skew)
    - Tokens that are expired
    
    Args:
      token_iat: Token "issued at" time (unix timestamp).
      token_exp: Token expiration time (unix timestamp).
      current_time: Current time (for testing). Defaults to time.time().
    
    Raises:
      AttestationVerificationError: If timestamp is invalid or too far in future.
    """
    if current_time is None:
      current_time = time.time()
    
    # Check if token issued in the future (beyond allowed skew)
    if token_iat > current_time + self._timestamp_skew_seconds:
      error_msg = (
          f"Token issued in future. iat={token_iat}, "
          f"now={current_time}, skew={self._timestamp_skew_seconds}s"
      )
      
      if self._security_logger:
        self._security_logger.log_replay_protection_event(
            event="timestamp_invalid",
            reason="issued_in_future",
            valid=False,
        )
      
      logger.warning(error_msg)
      raise exceptions.AttestationVerificationError(
          "Token timestamp in future (clock skew or clock attack)"
      )
    
    # Check if token is expired
    if token_exp < current_time:
      error_msg = f"Token expired. exp={token_exp}, now={current_time}"
      
      if self._security_logger:
        self._security_logger.log_replay_protection_event(
            event="timestamp_invalid",
            reason="expired",
            valid=False,
        )
      
      logger.warning(error_msg)
      raise exceptions.AttestationVerificationError("Token is expired")
    
    logger.debug(
        f"Token timestamp valid. iat={token_iat}, exp={token_exp}, now={current_time}"
    )
    
    if self._security_logger:
      self._security_logger.log_replay_protection_event(
          event="timestamp_valid",
          valid=True,
      )
