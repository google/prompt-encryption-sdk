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

"""Tests for the lazy public names of the `server` package."""

import importlib
import sys
import types
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk import server
from prompt_encryption_sdk.server import asgi
from prompt_encryption_sdk.server import attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token
from prompt_encryption_sdk.server import wsgi

_PUBLIC_NAMES = types.MappingProxyType({
    "AttestedTLS": attestation.AttestedTLS,
    "KeyManager": keys.KeyManager,
    "PromptEncryptionASGIMiddleware": asgi.PromptEncryptionASGIMiddleware,
    "PromptEncryptionWSGIMiddleware": wsgi.PromptEncryptionWSGIMiddleware,
    "TokenManager": token.TokenManager,
    "run_gunicorn_app": wsgi.run_gunicorn_app,
    "run_uvicorn_app": asgi.run_uvicorn_app,
})

_SERVER_FRAMEWORKS = ("gunicorn", "starlette", "uvicorn", "werkzeug")


class ServerPackageTest(parameterized.TestCase):

  def test_all_lists_exactly_the_public_names(self):
    self.assertCountEqual(server.__all__, _PUBLIC_NAMES)

  def test_dir_lists_every_public_name(self):
    with mock.patch.dict(vars(server)):
      for name in server.__all__:
        vars(server).pop(name, None)

      names = dir(server)

    self.assertContainsSubset(server.__all__, names)
    self.assertIn("__name__", names)

  @parameterized.named_parameters((name, name) for name in _PUBLIC_NAMES)
  def test_public_name_resolves_to_its_definition(self, name):
    self.assertIs(getattr(server, name), _PUBLIC_NAMES[name])

  def test_star_import_binds_every_public_name(self):
    namespace = {}
    exec("from prompt_encryption_sdk.server import *", namespace)  # pylint: disable=exec-used

    for name, value in _PUBLIC_NAMES.items():
      with self.subTest(name):
        self.assertIs(namespace[name], value)

  def test_an_unknown_name_raises_attribute_error(self):
    with self.assertRaisesRegex(AttributeError, "NoSuchName"):
      getattr(server, "NoSuchName")

  def test_identity_classes_do_not_import_the_server_frameworks(self):
    """A mutual client uses TokenManager without the server extras."""
    package = server.__name__
    unloaded = {
        name: module
        for name, module in sys.modules.items()
        if name == package
        or name.startswith(package + ".")
        or name.split(".")[0] in _SERVER_FRAMEWORKS
    }
    # Importing a package also binds it on its parent; undo that too.
    parent = sys.modules[package.rpartition(".")[0]]
    with mock.patch.dict(sys.modules), mock.patch.object(
        parent, "server", server
    ):
      for name in unloaded:
        del sys.modules[name]

      fresh_server = importlib.import_module(package)
      fresh_server.TokenManager  # pylint: disable=pointless-statement
      fresh_server.KeyManager  # pylint: disable=pointless-statement

      loaded = {name.split(".")[0] for name in sys.modules}
      self.assertEmpty(loaded.intersection(_SERVER_FRAMEWORKS))


if __name__ == "__main__":
  absltest.main()
