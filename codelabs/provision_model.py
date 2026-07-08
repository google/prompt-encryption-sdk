from collections import abc
import os
import pathlib
import shutil
from absl import app
from absl import flags
from google.cloud import storage
from huggingface_hub import snapshot_download

flags.DEFINE_string("bucket_name", None, "GCS bucket name.", required=True)
flags.DEFINE_string(
    "model_id", "google/gemma-3-1b-it", "Hugging Face model ID."
)
flags.DEFINE_string(
    "hf_token", os.environ.get("HF_TOKEN"), "Hugging Face API token."
)

FLAGS = flags.FLAGS


def main(argv: abc.Sequence[str]) -> None:
  if len(argv) > 1:
    raise app.UsageError("Too many command-line arguments.")

  # Download from HF
  print(f"Downloading {FLAGS.model_id} from Hugging Face...")

  local_dir = pathlib.Path("/tmp/model_download")
  local_dir.mkdir(parents=True, exist_ok=True)

  snapshot_dir = snapshot_download(
      repo_id=FLAGS.model_id,
      local_dir=local_dir,
      token=FLAGS.hf_token,
      local_dir_use_symlinks=False,
  )
  print(f"Downloaded to {snapshot_dir}")

  # Upload to GCS
  print(f"Uploading to GCS bucket gs://{FLAGS.bucket_name}...")
  storage_client = storage.Client()
  bucket = storage_client.bucket(FLAGS.bucket_name)

  for path in local_dir.rglob("*"):
    if path.is_file():
      blob_name = str(path.relative_to(local_dir))
      blob = bucket.blob(blob_name)
      print(f"Uploading {blob_name}...")
      blob.upload_from_filename(str(path))

  print("Upload complete!")

  # Cleanup
  print("Cleaning up local files...")
  shutil.rmtree(local_dir)
  print("Done!")


if __name__ == "__main__":
  app.run(main)
