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

"""Structured security event logging."""

import json
import logging
import time
from typing import Any, Dict, Optional


class SecurityLogger:
  """Provides structured JSON logging for security events.
  
  Outputs JSON-formatted security events for easy parsing and analysis
  in log aggregation systems.
  """

  def __init__(self, name: str = "prompt_encryption_sdk.security", level: str = "INFO"):
    """Initializes the security logger.
    
    Args:
      name: Logger name.
      level: Log level (DEBUG, INFO, WARNING, ERROR).
    """
    self._logger = logging.getLogger(name)
    self._logger.setLevel(getattr(logging, level.upper()))

  def _log_event(self, event_type: str, level: str, details: Dict[str, Any]) -> None:
    """Logs a structured security event as JSON.
    
    Args:
      event_type: Type of security event.
      level: Logging level (debug, info, warning, error).
      details: Dictionary of event details.
    """
    event = {
        "timestamp": time.time(),
        "event_type": event_type,
        "details": details,
    }
    
    message = json.dumps(event)
    log_fn = getattr(self._logger, level.lower(), self._logger.info)
    log_fn(message)

  def log_certificate_validation(
      self,
      hostname: str,
      valid: bool,
      fingerprint: Optional[str] = None,
      reason: Optional[str] = None,
  ) -> None:
    """Logs certificate pinning validation result.
    
    Args:
      hostname: The hostname being validated.
      valid: Whether validation passed.
      fingerprint: The certificate fingerprint (can be truncated for security).
      reason: Reason for validation failure (if applicable).
    """
    details = {
        "hostname": hostname,
        "valid": valid,
    }
    
    if fingerprint:
      details["fingerprint"] = fingerprint
    
    if reason:
      details["reason"] = reason
    
    self._log_event(
        "certificate_validation",
        "warning" if not valid else "info",
        details,
    )

  def log_attestation_result(
      self,
      valid: bool,
      host: Optional[str] = None,
      reason: Optional[str] = None,
      hw_model: Optional[str] = None,
  ) -> None:
    """Logs attestation validation result.
    
    Args:
      valid: Whether attestation passed.
      host: The server hostname.
      reason: Reason for failure (if applicable).
      hw_model: Hardware model (TEE type).
    """
    details = {"valid": valid}
    
    if host:
      details["host"] = host
    
    if reason:
      details["reason"] = reason
    
    if hw_model:
      details["hw_model"] = hw_model
    
    self._log_event(
        "attestation_validation",
        "warning" if not valid else "info",
        details,
    )

  def log_replay_protection_event(
      self,
      event: str,
      valid: bool,
      nonce: Optional[str] = None,
      source: Optional[str] = None,
      reason: Optional[str] = None,
  ) -> None:
    """Logs replay protection event.
    
    Args:
      event: Event type (nonce_accepted, nonce_replay, timestamp_valid, timestamp_invalid).
      valid: Whether the validation passed.
      nonce: The nonce (can be truncated for security).
      source: Nonce source (client, server, etc.).
      reason: Reason for event (if applicable).
    """
    details = {"valid": valid}
    
    if nonce:
      details["nonce"] = nonce
    
    if source:
      details["source"] = source
    
    if reason:
      details["reason"] = reason
    
    self._log_event(
        "replay_protection",
        "warning" if not valid else "debug",
        details,
    )

  def log_policy_violation(
      self,
      policy_type: str,
      expected: str,
      actual: str,
      host: Optional[str] = None,
  ) -> None:
    """Logs policy violation.
    
    Args:
      policy_type: Type of policy (hardware_model, workload, gce_instance, etc.).
      expected: Expected value.
      actual: Actual value.
      host: The server hostname.
    """
    details = {
        "policy_type": policy_type,
        "expected": expected,
        "actual": actual,
    }
    
    if host:
      details["host"] = host
    
    self._log_event("policy_violation", "warning", details)

  def log_security_error(
      self,
      error_type: str,
      message: str,
      context: Optional[Dict[str, Any]] = None,
  ) -> None:
    """Logs a security-related error.
    
    Args:
      error_type: Type of error (connection_failed, validation_failed, etc.).
      message: Error message.
      context: Additional context as dict.
    """
    details = {
        "error_type": error_type,
        "message": message,
    }
    
    if context:
      details.update(context)
    
    self._log_event("security_error", "error", details)
