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

"""Security configuration for Prompt Encryption SDK."""

import dataclasses
from typing import Dict, List, Optional


@dataclasses.dataclass
class SecurityConfig:
  """Optional security hardening configuration.
  
  All features default to OFF for backward compatibility. Enable individually
  as needed in your deployment.
  """
  
  # Certificate Pinning
  enable_certificate_pinning: bool = False
  """Enable SHA256 certificate fingerprint validation."""
  
  pinned_cert_fingerprints: Dict[str, List[str]] = dataclasses.field(
      default_factory=dict
  )
  """Map of hostname -> list of allowed SHA256 fingerprints (hex format).
  
  Example:
    {
      "api.example.com": [
        "abc123def456...",  # Primary cert
        "xyz789uvw123...",  # Backup cert
      ]
    }
  """
  
  # Replay Protection
  enable_replay_protection: bool = False
  """Enable nonce and timestamp validation for replay attack prevention."""
  
  replay_protection_nonce_ttl_seconds: int = 3600
  """How long to track nonces (default: 1 hour)."""
  
  replay_protection_timestamp_skew_seconds: int = 60
  """Maximum allowed clock skew for timestamp validation (default: 60s)."""
  
  # Security Logging
  enable_security_logging: bool = False
  """Enable structured JSON logging for security events."""
  
  security_log_level: str = "INFO"
  """Log level for security events (DEBUG, INFO, WARNING, ERROR)."""
  
  def __post_init__(self):
    """Validate configuration."""
    if self.replay_protection_nonce_ttl_seconds <= 0:
      raise ValueError("replay_protection_nonce_ttl_seconds must be > 0")
    
    if self.replay_protection_timestamp_skew_seconds < 0:
      raise ValueError("replay_protection_timestamp_skew_seconds must be >= 0")
    
    if self.security_log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
      raise ValueError(
          f"security_log_level must be one of DEBUG, INFO, WARNING, ERROR; "
          f"got {self.security_log_level}"
      )
