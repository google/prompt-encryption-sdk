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

"""Tests for security logging."""

import pytest

from prompt_encryption_sdk.security import logging as security_logging


class TestSecurityLogger:
  """Tests for structured security event logging."""

  def test_logger_initialization(self):
    """Test logger creation with different log levels."""
    logger = security_logging.SecurityLogger(level="DEBUG")
    assert logger is not None
    
    logger_info = security_logging.SecurityLogger(level="INFO")
    assert logger_info is not None
    
    logger_error = security_logging.SecurityLogger(level="ERROR")
    assert logger_error is not None

  def test_log_certificate_validation(self):
    """Test certificate validation logging."""
    logger = security_logging.SecurityLogger()
    
    # Should not raise
    logger.log_certificate_validation(
        hostname="example.com",
        valid=True,
        fingerprint="abc123def456",
    )
    
    logger.log_certificate_validation(
        hostname="example.com",
        valid=False,
        reason="fingerprint_mismatch",
    )

  def test_log_attestation_result(self):
    """Test attestation result logging."""
    logger = security_logging.SecurityLogger()
    
    logger.log_attestation_result(
        valid=True,
        host="api.example.com",
    )
    
    logger.log_attestation_result(
        valid=False,
        reason="policy_violation",
        hw_model="SEV_SNP",
    )

  def test_log_replay_protection_event(self):
    """Test replay protection event logging."""
    logger = security_logging.SecurityLogger()
    
    logger.log_replay_protection_event(
        event="nonce_accepted",
        valid=True,
        nonce="abc123...",
        source="client",
    )
    
    logger.log_replay_protection_event(
        event="nonce_replay",
        valid=False,
        reason="duplicate_nonce",
    )

  def test_log_policy_violation(self):
    """Test policy violation logging."""
    logger = security_logging.SecurityLogger()
    
    logger.log_policy_violation(
        policy_type="hardware_model",
        expected="SEV_SNP",
        actual="SEV",
        host="secure-server.example.com",
    )

  def test_invalid_log_level_in_config(self):
    """Test that invalid log levels are rejected."""
    from prompt_encryption_sdk.security import config
    
    with pytest.raises(ValueError):
      config.SecurityConfig(
          enable_security_logging=True,
          security_log_level="INVALID",
      )
