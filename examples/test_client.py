import argparse
import logging
import os
import pathlib
import time
from prompt_encryption_sdk import client
from prompt_encryption_sdk import server
from prompt_encryption_sdk.proto import attestation_pb2
import requests


def _run_inference(
    sdk_client: client.PromptEncryptionClient,
    *,
    target_url: str,
    payload: dict[str, object],
) -> None:
  """Runs the inference request with retry handling."""
  logging.info("Connecting to %s...", target_url)

  max_retries = 15
  retry_delay = 30

  for attempt in range(max_retries):
    try:
      with sdk_client.session() as http:
        # The codelab server uses a self-signed certificate. Attestation still
        # binds the verified TEE identity to this exact TLS session.
        response = http.post(target_url, json=payload, verify=False)
        logging.info("Status: %s", response.status_code)
        if response.status_code == 200:
          print("\n" + "=" * 50)
          print("AI RESPONSE:")
          print(response.json()["choices"][0]["text"])
          print("=" * 50 + "\n")
        else:
          logging.error("Error Response: %s", response.text)
        return
    except (requests.RequestException, client.PromptEncryptionError) as e:
      logging.info(
          "Attempt %d failed: %s. Retrying in %d seconds...",
          attempt + 1,
          e,
          retry_delay,
      )
      time.sleep(retry_delay)

  raise RuntimeError(f"Inference failed after {max_retries} attempts.")


def main() -> None:
  parser = argparse.ArgumentParser(description="Secure Inference Client")
  parser.add_argument(
      "--image-hash", required=True, help="SHA256 hash of the container image"
  )
  parser.add_argument("--project-id", required=True, help="GCP project ID")
  parser.add_argument("--zone", required=True, help="GCP zone")
  parser.add_argument("--ip", required=True, help="Load Balancer or VM IP address")
  parser.add_argument(
      "--hw-model",
      default="TDX",
      choices=["TDX", "SEV", "SEV_SNP"],
      help="Hardware model (TDX, SEV, or SEV_SNP)",
  )
  parser.add_argument(
      "--model", default="google/gemma-3-1b-it", help="Model name for inference"
  )
  parser.add_argument(
      "--prompt",
      default=(
          "Hello via Confidential Space! Explain Quantum Entanglement in two"
          " sentences."
      ),
      help="Inference prompt",
  )
  parser.add_argument(
      "--max-tokens",
      type=int,
      default=100,
      help="Maximum number of tokens to generate",
  )
  parser.add_argument(
      "--mutual-attestation",
      action="store_true",
      help=(
          "Enable mutual attestation. The client must itself run in "
          "Confidential Space."
      ),
  )
  parser.add_argument(
      "--attestation-type",
      choices=["uds", "gotpm"],
      default=os.environ.get("ATTESTATION_TYPE", "uds").lower(),
      help="Client token source in mutual mode (default: uds).",
  )
  parser.add_argument(
      "--identity-dir",
      type=pathlib.Path,
      default=pathlib.Path("/dev/shm/prompt-encryption-client"),
      help="In-memory directory for the confidential client's ephemeral identity.",
  )

  args = parser.parse_args()

  logging.basicConfig(level=logging.DEBUG)

  hw_model_map = {
      "TDX": attestation_pb2.HARDWARE_MODEL_TDX,
      "SEV": attestation_pb2.HARDWARE_MODEL_SEV,
      "SEV_SNP": attestation_pb2.HARDWARE_MODEL_SEV_SNP,
  }
  hw_model_enum = hw_model_map[args.hw_model]

  policy = attestation_pb2.AttestationPolicy(
      hw_model=hw_model_enum,
      workload=attestation_pb2.WorkloadPolicy(image_hash=args.image_hash),
      gce_instance=attestation_pb2.GceInstancePolicy(
          project_id=args.project_id, zone=args.zone
      ),
  )

  target_url = f"https://{args.ip}:8000/v1/completions"

  payload = {
      "model": args.model,
      "prompt": args.prompt,
      "max_tokens": args.max_tokens,
  }

  if not args.mutual_attestation:
    sdk_client = client.PromptEncryptionClient(policy=policy)
    _run_inference(sdk_client, target_url=target_url, payload=payload)
    return

  os.environ["ATTESTATION_TYPE"] = args.attestation_type
  args.identity_dir.mkdir(parents=True, exist_ok=True)
  key_manager = server.KeyManager(
      private_key_path=args.identity_dir / "ecdsa-private.pem",
      public_key_path=args.identity_dir / "ecdsa-public.pem",
      pqc_private_key_path=args.identity_dir / "mldsa-private.bin",
      pqc_public_key_path=args.identity_dir / "mldsa-public.bin",
  )
  identity = server.TokenManager(
      key_manager=key_manager,
      attestation_token_path=args.identity_dir / "attestation-token.jwt",
  )
  logging.info(
      "Creating the confidential client identity using %s...",
      args.attestation_type,
  )
  # Populate the identity synchronously so the first connection cannot race the
  # background token refresh thread.
  identity.refresh()
  sdk_client = client.PromptEncryptionClient(
      policy=policy,
      mutual_attestation=True,
      client_token_manager=identity,
  )
  with identity:
    _run_inference(sdk_client, target_url=target_url, payload=payload)


if __name__ == "__main__":
  main()
