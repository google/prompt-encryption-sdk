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

"""Server-side components for Prompt Encryption SDK.

Imports are lazy so a mutually attesting *client* can use KeyManager and
TokenManager to hold its own TEE identity without installing the ASGI, WSGI,
Gunicorn, or Uvicorn dependencies.
"""

import importlib
import types
import typing

if typing.TYPE_CHECKING:
  from prompt_encryption_sdk.server.asgi import PromptEncryptionASGIMiddleware
  from prompt_encryption_sdk.server.asgi import run_uvicorn_app
  from prompt_encryption_sdk.server.attestation import AttestedTLS
  from prompt_encryption_sdk.server.keys import KeyManager
  from prompt_encryption_sdk.server.token import TokenManager
  from prompt_encryption_sdk.server.wsgi import PromptEncryptionWSGIMiddleware
  from prompt_encryption_sdk.server.wsgi import run_gunicorn_app

__all__ = (
    "AttestedTLS",
    "PromptEncryptionASGIMiddleware",
    "PromptEncryptionWSGIMiddleware",
    "KeyManager",
    "TokenManager",
    "run_gunicorn_app",
    "run_uvicorn_app",
)

_EXPORTS = types.MappingProxyType({
    "AttestedTLS": (".attestation", "AttestedTLS"),
    "PromptEncryptionASGIMiddleware": (
        ".asgi",
        "PromptEncryptionASGIMiddleware",
    ),
    "PromptEncryptionWSGIMiddleware": (
        ".wsgi",
        "PromptEncryptionWSGIMiddleware",
    ),
    "KeyManager": (".keys", "KeyManager"),
    "TokenManager": (".token", "TokenManager"),
    "run_gunicorn_app": (".wsgi", "run_gunicorn_app"),
    "run_uvicorn_app": (".asgi", "run_uvicorn_app"),
})


def __getattr__(name: str) -> typing.Any:  # pylint: disable=invalid-name
  """Resolves a public name to its module on first access."""
  try:
    module_name, attribute_name = _EXPORTS[name]
  except KeyError as e:
    raise AttributeError(name) from e
  value = getattr(
      importlib.import_module(module_name, __name__), attribute_name
  )
  globals()[name] = value
  return value


def __dir__() -> list[str]:  # pylint: disable=invalid-name
  """Returns module attributes including lazy public exports."""
  return sorted(set(globals()) | set(__all__))
