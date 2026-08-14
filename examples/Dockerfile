FROM docker.io/vllm/vllm-openai:latest

# Install build dependencies for C extension (_ekm.c) and openssl for certs
RUN apt-get update && apt-get install -y gcc libssl-dev openssl && rm -rf /var/lib/apt/lists/*

# Generate a self-signed certificate for TLS
RUN openssl req -x509 -newkey rsa:4096 -keyout /tmp/server.key -out /tmp/server.crt -days 365 -nodes -subj "/CN=localhost"

LABEL "tee.launch_policy.allow_env_override"="HF_HOME,GCS_BUCKET_NAME,REQUIRE_MUTUAL_ATTESTATION,TRUSTED_CLIENT_IMAGE_HASH,TRUSTED_CLIENT_PROJECT_ID,TRUSTED_CLIENT_ZONE,TRUSTED_CLIENT_HW_MODEL"
WORKDIR /app
COPY examples/requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir hf_transfer==0.1.9 && \
    pip install --no-cache-dir -r requirements.txt

# Build and install the library in a separate directory to avoid import shadowing
WORKDIR /build
COPY src /build/src
COPY pyproject.toml /build/pyproject.toml
COPY setup.py /build/setup.py
RUN pip install . && \
    rm -rf /build

WORKDIR /app

ENV HF_HOME=/app/models
ENV HF_HUB_ENABLE_HF_TRANSFER=1



COPY examples/vllm_server.py /app/vllm_server.py

EXPOSE 8000
ENTRYPOINT ["python3", "vllm_server.py"]
