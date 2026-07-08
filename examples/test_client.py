import argparse
import logging
import time
from prompt_encryption_sdk import client
from prompt_encryption_sdk.proto import attestation_pb2
import requests


def main() -> None:
  parser = argparse.ArgumentParser(description="Secure Inference Client")
  parser.add_argument(
      "--image-hash", required=True, help="SHA256 hash of the container image"
  )
  parser.add_argument("--project-id", required=True, help="GCP project ID")
  parser.add_argument("--zone", required=True, help="GCP zone")
  parser.add_argument(
      "--ip", required=True, help="Load Balancer or VM IP address"
  )
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

  sdk_client = client.PromptEncryptionClient(policy=policy)
  target_url = f"https://{args.ip}:8000/v1/completions"

  payload = {
      "model": args.model,
      "prompt": args.prompt,
      "max_tokens": args.max_tokens,
  }

  logging.info("Connecting to %s...", target_url)

  max_retries = 15
  retry_delay = 30

  for attempt in range(max_retries):
    try:
      with sdk_client.session() as http:
        # Disabling SSL verification because the server inside the confidential
        # VM uses a self-signed certificate.
        response = http.post(target_url, json=payload, verify=False)
        logging.info("Status: %s", response.status_code)
        if response.status_code == 200:
          print("\n" + "=" * 50)
          print("AI RESPONSE:")
          print(response.json()["choices"][0]["text"])
          print("=" * 50 + "\n")
        else:
          logging.error("Error Response: %s", response.text)
        break
    except requests.RequestException as e:
      logging.info(
          "Attempt %d failed: %s. Retrying in %d seconds...",
          attempt + 1,
          e,
          retry_delay,
      )
      time.sleep(retry_delay)


if __name__ == "__main__":
  main()
