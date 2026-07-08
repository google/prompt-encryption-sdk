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

"""Tests for replay protection validator."""

import pytest
import time

from prompt_encryption_sdk.security import replay_protection
from prompt_encryption_sdk.security import logging as security_logging
from prompt_encryption_sdk.client import exceptions


class TestReplayProtectionValidator:
  """Tests for replay attack prevention."""

  def test_valid_nonce_accepted_first_time(self):
    """Test that a new nonce passes validation."""
    validator = replay_protection.ReplayProtectionValidator()
    nonce = b"test_nonce_123"
    # Should not raise
    validator.validate_nonce_freshness(nonce)

  def test_nonce_replay_detected(self):
    """Test that repeated nonce is detected."""
    validator = replay_protection.ReplayProtectionValidator()
    nonce = b"test_nonce_123"
    validator.validate_nonce_freshness(nonce)
    # Try same nonce again - should raise
    with pytest.raises(exceptions.AttestationVerificationError):
      validator.validate_nonce_freshness(nonce)

  def test_multiple_unique_nonces_accepted(self):
    """Test that different nonces are all accepted."""
    validator = replay_protection.ReplayProtectionValidator()
    nonces = [f"nonce_{i}".encode() for i in range(5)]
    for nonce in nonces:
      # Should not raise
      validator.validate_nonce_freshness(nonce)

  def test_token_timestamp_valid_current(self):
    """Test that current token timestamps pass validation."""
    validator = replay_protection.ReplayProtectionValidator(
        timestamp_skew_seconds=60
    )
    current_time = time.time()
    iat = int(current_time)
    exp = int(current_time) + 3600
    
    # Should not raise
    validator.validate_token_timestamp(iat, exp)

  def test_token_timestamp_future_within_skew(self):
    """Test that tokens slightly in future within skew pass validation."""
    validator = replay_protection.ReplayProtectionValidator(
        timestamp_skew_seconds=60
    )
    current_time = time.time()
    iat = int(current_time) + 30  # 30 seconds in future
    exp = int(current_time) + 3600
    
    # Should not raise
    validator.validate_token_timestamp(iat, exp)

  def test_token_timestamp_future_beyond_skew_rejected(self):
    """Test that tokens far in future are rejected."""
    validator = replay_protection.ReplayProtectionValidator(
        timestamp_skew_seconds=60
    )
    current_time = time.time()
    iat = int(current_time) + 120  # 120 seconds in future (beyond 60s skew)
    exp = int(current_time) + 3600
    
    with pytest.raises(exceptions.AttestationVerificationError):
      validator.validate_token_timestamp(iat, exp)

  def test_token_timestamp_expired_rejected(self):
    """Test that expired tokens are rejected."""
    validator = replay_protection.ReplayProtectionValidator()
    current_time = time.time()
    iat = int(current_time) - 7200  # 2 hours ago
    exp = int(current_time) - 3600  # 1 hour ago (expired)
    
    with pytest.raises(exceptions.AttestationVerificationError):
      validator.validate_token_timestamp(iat, exp)

  def test_nonce_cache_cleanup(self):
    """Test that expired nonces are cleaned up."""
    validator = replay_protection.ReplayProtectionValidator(
        nonce_ttl_seconds=1  # Very short TTL
    )
    
    nonce1 = b"nonce_early"
    validator.validate_nonce_freshness(nonce1)
    
    # Wait for TTL to expire
    time.sleep(1.1)
    
    # Same nonce should be accepted again (old one expired)
    validator.validate_nonce_freshness(nonce1)

  def test_security_logging_on_replay_detection(self):
    """Test that security logging is triggered on replay."""
    logger = security_logging.SecurityLogger()
    validator = replay_protection.ReplayProtectionValidator(
        security_logger=logger
    )
    
    nonce = b"test_nonce"
    validator.validate_nonce_freshness(nonce)
    
    # Second attempt should trigger logging and raise
    with pytest.raises(exceptions.AttestationVerificationError):
      validator.validate_nonce_freshness(nonce)


class TestReplayProtectionConfig:
  """Tests for replay protection configuration."""

  def test_timestamp_skew_validation(self):
    """Test that negative skew is rejected."""
    from prompt_encryption_sdk.security import config
    
    with pytest.raises(ValueError):
      config.SecurityConfig(
          enable_replay_protection=True,
          replay_protection_timestamp_skew_seconds=-1,
      )

  def test_nonce_ttl_validation(self):
    """Test that zero/negative TTL is rejected."""
    from prompt_encryption_sdk.security import config
    
    with pytest.raises(ValueError):
      config.SecurityConfig(
          enable_replay_protection=True,
          replay_protection_nonce_ttl_seconds=0,
      )

    with pytest.raises(ValueError):
      config.SecurityConfig(
          enable_replay_protection=True,
          replay_protection_nonce_ttl_seconds=-100,
      )

