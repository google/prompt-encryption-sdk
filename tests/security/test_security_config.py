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

"""Tests for security configuration."""

import pytest

from prompt_encryption_sdk.security import config


class TestSecurityConfig:
  """Tests for SecurityConfig dataclass."""

  def test_default_config_all_features_disabled(self):
    """Test that default config has all features disabled."""
    cfg = config.SecurityConfig()
    
    assert cfg.enable_certificate_pinning is False
    assert cfg.enable_replay_protection is False
    assert cfg.enable_security_logging is False
    assert len(cfg.pinned_cert_fingerprints) == 0

  def test_config_immutability(self):
    """Test that config fields are properly initialized."""
    cfg = config.SecurityConfig(
        enable_certificate_pinning=True,
        pinned_cert_fingerprints={"example.com": ["abc123"]},
    )
    
    assert cfg.enable_certificate_pinning is True
    assert cfg.pinned_cert_fingerprints["example.com"] == ["abc123"]

  def test_replay_protection_defaults(self):
    """Test replay protection default values."""
    cfg = config.SecurityConfig(enable_replay_protection=True)
    
    assert cfg.replay_protection_nonce_ttl_seconds == 3600
    assert cfg.replay_protection_timestamp_skew_seconds == 60

  def test_security_logging_defaults(self):
    """Test security logging default values."""
    cfg = config.SecurityConfig(enable_security_logging=True)
    
    assert cfg.security_log_level == "INFO"

  def test_invalid_nonce_ttl(self):
    """Test that zero/negative nonce TTL is rejected."""
    with pytest.raises(ValueError, match="nonce_ttl_seconds must be > 0"):
      config.SecurityConfig(
          enable_replay_protection=True,
          replay_protection_nonce_ttl_seconds=0,
      )

    with pytest.raises(ValueError, match="nonce_ttl_seconds must be > 0"):
      config.SecurityConfig(
          enable_replay_protection=True,
          replay_protection_nonce_ttl_seconds=-100,
      )

  def test_invalid_timestamp_skew(self):
    """Test that negative timestamp skew is rejected."""
    with pytest.raises(ValueError, match="timestamp_skew_seconds must be >= 0"):
      config.SecurityConfig(
          enable_replay_protection=True,
          replay_protection_timestamp_skew_seconds=-1,
      )

  def test_invalid_log_level(self):
    """Test that invalid log levels are rejected."""
    with pytest.raises(ValueError, match="security_log_level must be one of"):
      config.SecurityConfig(
          enable_security_logging=True,
          security_log_level="INVALID",
      )

  def test_valid_log_levels(self):
    """Test that all valid log levels are accepted."""
    for level in ["DEBUG", "INFO", "WARNING", "ERROR"]:
      cfg = config.SecurityConfig(
          enable_security_logging=True,
          security_log_level=level,
      )
      assert cfg.security_log_level == level

  def test_mixed_features_enabled(self):
    """Test config with multiple features enabled."""
    cfg = config.SecurityConfig(
        enable_certificate_pinning=True,
        enable_replay_protection=True,
        enable_security_logging=True,
        pinned_cert_fingerprints={
            "api.example.com": ["fingerprint1", "fingerprint2"]
        },
        replay_protection_timestamp_skew_seconds=120,
        security_log_level="DEBUG",
    )
    
    assert cfg.enable_certificate_pinning is True
    assert cfg.enable_replay_protection is True
    assert cfg.enable_security_logging is True
    assert len(cfg.pinned_cert_fingerprints["api.example.com"]) == 2
    assert cfg.replay_protection_timestamp_skew_seconds == 120
    assert cfg.security_log_level == "DEBUG"
