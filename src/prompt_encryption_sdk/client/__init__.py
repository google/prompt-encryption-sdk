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

"""Prompt Encryption Client SDK.

This package provides a client-side SDK for establishing E2E encrypted and
attested TLS connections with Confidential Space workloads.
"""

from .client import PromptEncryptionClient
from .exceptions import (
    AttestationHandshakeError,
    AttestationVerificationError,
    PromptEncryptionError,
    PolicyViolationError,
)

__all__ = (
    'PromptEncryptionClient',
    'PromptEncryptionError',
    'AttestationVerificationError',
    'PolicyViolationError',
    'AttestationHandshakeError',
)
