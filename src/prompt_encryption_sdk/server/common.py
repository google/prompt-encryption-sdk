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

"""Common utilities for Prompt Encryption SDK server."""

import os
import pathlib
from typing import Protocol


class FileWriter(Protocol):

  def __call__(self, path: pathlib.Path, data: bytes, mode: int) -> None:
    ...


class FileReader(Protocol):

  def __call__(self, path: pathlib.Path) -> bytes:
    ...


def write_file(path: pathlib.Path, data: bytes, mode: int) -> None:
  """Helper to write files atomically."""
  path = pathlib.Path(path)
  temp_path = path.with_name(path.name + ".tmp")
  try:
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
      f.write(data)
    os.replace(temp_path, path)
  except Exception as e:
    if temp_path.exists():
      os.remove(temp_path)
    raise ValueError(f"Could not write file atomically: {path!r}") from e


def read_file(path: pathlib.Path) -> bytes:
  """Helper to read files safely."""
  try:
    with open(path, "rb") as f:
      return f.read()
  except OSError as err:
    raise ValueError(f"Could not read file: {path!r}") from err
