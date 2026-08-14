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

"""Server and shared Confidential Space identity components.

Imports are lazy so a mutual-attestation client can use KeyManager and
TokenManager without installing ASGI, WSGI, Gunicorn, or Uvicorn dependencies.
"""

from importlib import import_module


__all__ = (
    "AttestedTLS",
    "PromptEncryptionASGIMiddleware",
    "PromptEncryptionWSGIMiddleware",
    "KeyManager",
    "TokenManager",
    "run_gunicorn_app",
    "run_uvicorn_app",
)

_EXPORTS = {
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
}


def __getattr__(name: str):
  try:
    module_name, attribute_name = _EXPORTS[name]
  except KeyError as e:
    raise AttributeError(name) from e
  value = getattr(import_module(module_name, __name__), attribute_name)
  globals()[name] = value
  return value
