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

"""Tests for prompt_encryption_sdk.ekm.__init__."""

from prompt_encryption_sdk import ekm
from prompt_encryption_sdk.ekm import exporter

from absl.testing import absltest as googletest


class InitTest(googletest.TestCase):

  def test_exposes_export_keying_material(self) -> None:
    """Verifies that ekm.export_keying_material points to the correct function."""
    with self.subTest("HasAttr"):
      self.assertTrue(hasattr(ekm, "export_keying_material"))
    with self.subTest("IsCorrectFunction"):
      self.assertIs(ekm.export_keying_material, exporter.export_keying_material)
    with self.subTest("IsCallable"):
      self.assertTrue(callable(ekm.export_keying_material))


if __name__ == "__main__":
  googletest.main()
