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

"""Tests for server.common."""

import os
import pathlib

from absl.testing import absltest
from prompt_encryption_sdk.server import common


class CommonTest(absltest.TestCase):

  def test_write_file_atomically(self):
    temp_dir = self.create_tempdir()
    file_path = temp_dir.create_file("test.txt").full_path
    common.write_file(pathlib.Path(file_path), b"new_content", 0o644)
    with open(file_path, "rb") as f:
      self.assertEqual(f.read(), b"new_content")

  def test_read_file_success(self):
    temp_dir = self.create_tempdir()
    file_path = temp_dir.create_file("test.txt", content=b"file_content").full_path
    self.assertEqual(common.read_file(pathlib.Path(file_path)), b"file_content")

  def test_read_file_not_found(self):
    with self.assertRaisesRegex(ValueError, "Could not read file"):
      common.read_file(pathlib.Path("nonexistent.txt"))


if __name__ == "__main__":
  absltest.main()
