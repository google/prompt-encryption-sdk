"""FastAPI server running vLLM."""

import os
import pathlib
import uuid

from prompt_encryption_sdk import server
from prompt_encryption_sdk.proto import attestation_pb2
import fastapi
from fastapi import responses
from google.cloud import storage
import vllm

os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "1"
os.environ["VLLM_ATTENTION_BACKEND"] = "FLASHINFER"
os.environ["HF_HUB_OFFLINE"] = "1"

_MutualAttestationConfig = tuple[attestation_pb2.AttestationPolicy | None, bool]


def _mutual_attestation_config() -> _MutualAttestationConfig:
  """Builds the trusted confidential-client policy from codelab settings."""
  require_mutual = os.environ.get("REQUIRE_MUTUAL_ATTESTATION", "false").lower() in (
      "1",
      "true",
      "yes",
  )
  client_image_hash = os.environ.get("TRUSTED_CLIENT_IMAGE_HASH", "")
  if not client_image_hash:
    if require_mutual:
      raise ValueError(
          "TRUSTED_CLIENT_IMAGE_HASH is required when mutual attestation is "
          "required."
      )
    return None, False

  hw_model_name = os.environ.get("TRUSTED_CLIENT_HW_MODEL", "TDX")
  hw_model_by_name = {
      "TDX": attestation_pb2.HARDWARE_MODEL_TDX,
      "SEV": attestation_pb2.HARDWARE_MODEL_SEV,
      "SEV_SNP": attestation_pb2.HARDWARE_MODEL_SEV_SNP,
  }
  try:
    hw_model = hw_model_by_name[hw_model_name]
  except KeyError as e:
    raise ValueError(f"Unsupported TRUSTED_CLIENT_HW_MODEL: {hw_model_name!r}") from e

  return (
      attestation_pb2.AttestationPolicy(
          hw_model=hw_model,
          workload=attestation_pb2.WorkloadPolicy(image_hash=client_image_hash),
          gce_instance=attestation_pb2.GceInstancePolicy(
              project_id=os.environ.get("TRUSTED_CLIENT_PROJECT_ID", ""),
              zone=os.environ.get("TRUSTED_CLIENT_ZONE", ""),
          ),
      ),
      require_mutual,
  )


def download_model_from_gcs(bucket_name: str, model_dir: str) -> None:
  """Downloads model from GCS bucket."""
  print(f"Downloading model from bucket {bucket_name} to {model_dir}...")
  storage_client = storage.Client()
  bucket = storage_client.bucket(bucket_name)

  blobs = bucket.list_blobs()
  for blob in blobs:
    local_path = pathlib.Path(model_dir) / blob.name
    local_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {blob.name}...")
    blob.download_to_filename(str(local_path))
  print("Download complete.")


BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME")
MODEL_DIR = os.environ.get("HF_HOME", "/app/models")

if BUCKET_NAME is not None:
  if not any(pathlib.Path(MODEL_DIR).glob("*")):
    download_model_from_gcs(BUCKET_NAME, MODEL_DIR)
else:
  print("GCS_BUCKET_NAME not set. Skipping GCS download.")

app = fastapi.FastAPI()
# Initialize LLM with an ungated model.
# enforce_eager=True helps with memory constraints.
llm = vllm.LLM(model=MODEL_DIR, enforce_eager=True)


@app.post("/v1/completions")
async def completions(request: fastapi.Request) -> responses.JSONResponse:
  """Handles text completion requests using the confidential vLLM model."""
  data = (await request.json()) or {}
  prompt = data.get("prompt", "")
  max_tokens = data.get("max_tokens", 50)

  sampling_params = vllm.SamplingParams(max_tokens=max_tokens)
  outputs = llm.generate([prompt], sampling_params)
  [request_output] = outputs
  [completion_output] = request_output.outputs
  text = completion_output.text

  return responses.JSONResponse(
      {
          "id": str(uuid.uuid4()),
          "object": "text_completion",
          "model": "google/gemma-3-1b-it",
          "choices": [{"text": text, "index": 0}],
      }
  )


if __name__ == "__main__":
  client_policy, require_mutual_attestation = _mutual_attestation_config()
  server.run_uvicorn_app(
      app,
      host="0.0.0.0",
      port=8000,
      ssl_keyfile="/tmp/server.key",
      ssl_certfile="/tmp/server.crt",
      client_policy=client_policy,
      require_mutual_attestation=require_mutual_attestation,
  )
