# Prompt Encryption SDK

The Prompt Encryption SDK establishes an end-to-end, attested TLS channel to a workload in a Trusted Execution Environment (TEE) on Google Cloud. This ensures a cryptographically verified and encrypted channel between your client application and a remote inference server (e.g., vLLM, FastAPI) running on Confidential Space.

This SDK is particularly useful for protecting sensitive data, ensuring that prompts and payloads are only decrypted by a server whose hardware configuration and software stack have been successfully cryptographically attested.

## Features

- **End-to-End Encryption**: Encrypts data in transit directly into the secure enclave, protecting it from intermediate infrastructure.
- **Attested TLS**: Seamlessly ties Google Cloud Confidential Space attestation into the TLS handshake.
- **Client & Server Support**: High-level primitives to build attested clients and compliant ASGI/WSGI servers.
- **Language-Neutral Client Core**: Kotlin, Swift, Go, Python, and other clients can use their normal HTTP libraries through one loopback-only attested client executable. See [clientcore/README.md](clientcore/README.md).

## Prerequisites

- Python 3.10+
- OpenSSL (for generating certificates if running a local test server)
- A Google Cloud Project with Confidential Space enabled (for production server deployments)

For more technical details on how the SDK works, see the [Architecture Documentation](ARCHITECTURE.md).

## Installation

You can install the SDK directly from the source code.

To install the base client library:

```bash
git clone https://github.com/GoogleCloudPlatform/prompt-encryption-sdk.git # Replace with the actual repository URL if different
cd prompt-encryption-sdk
pip install .
```

If you are implementing the server side, you will need the optional server dependencies (which include ASGI/WSGI dependencies like `uvicorn` and `gunicorn`):

```bash
pip install .[server]
```

## Usage

The SDK allows you to verify the server's identity (hardware model, software hash, launch configuration) before sending sensitive data.

### Client-Side Example

```python
from prompt_encryption_sdk.client import PromptEncryptionClient
from prompt_encryption_sdk.proto import attestation_pb2

# Define the attestation policy
# The client will only establish a connection if the server satisfies these rules.
policy = attestation_pb2.AttestationPolicy(
    hw_model=attestation_pb2.HARDWARE_MODEL_SEV, # Or HARDWARE_MODEL_TDX
    workload=attestation_pb2.WorkloadPolicy(
        image_hash="sha256:YOUR_EXPECTED_CONTAINER_IMAGE_HASH"
    ),
    gce_instance=attestation_pb2.GceInstancePolicy(
        project_id="your-project-id",
        zone="us-central1-a"
    )
)

# Initialize the client with the policy
client = PromptEncryptionClient(policy)

target_url = "https://<YOUR_LOAD_BALANCER_OR_VM_IP>:8000/v1/completions"
payload = {
    "prompt": "Hello via Prompt Encryption SDK!"
}

# Use the client to make requests
try:
    with client.session() as http:
        # verify=False bypasses standard TLS checks since we use Attested TLS.
        # The connection's security is guaranteed by the TEE hardware attestation.
        response = http.post(target_url, json=payload, verify=False)
        print(f"Status: {response.status_code}")
        print(f"Data: {response.json()}")
except Exception as e:
    print(f"Error: {e}")
```

### Server-Side Example

The library provides high-level ASGI and WSGI middlewares in `prompt_encryption_sdk.server` for implementing an Attested TLS server easily.

```python
from fastapi import FastAPI
from prompt_encryption_sdk.server import run_uvicorn_app

app = FastAPI()

@app.post("/v1/completions")
def completions(data: dict):
    return {"message": "Hello via Prompt Encryption SDK!", "received_prompt": data.get("prompt")}

if __name__ == "__main__":
    # Attested TLS requires an underlying TLS connection to extract the exported keying material (EKM).
    # Provide an SSL key and certificate (can be self-signed) to enable HTTPS.
    # Note: Ensure the container EXPOSEs the port in your Dockerfile so Confidential Space routes it.
    run_uvicorn_app(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="key.pem",
        ssl_certfile="cert.pem"
    )
```

## License

Apache 2.0 - See [LICENSE](LICENSE) for more information.
