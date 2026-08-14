FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY src /build/src
COPY pyproject.toml /build/pyproject.toml
COPY setup.py /build/setup.py
COPY LICENSE /build/LICENSE
COPY AUTHORS /build/AUTHORS
COPY README.md /build/README.md
RUN pip install --no-cache-dir . && rm -rf /build

WORKDIR /app
COPY examples/test_client.py /app/test_client.py
COPY examples/mutual_client_entrypoint.sh /app/mutual_client_entrypoint.sh
RUN chmod +x /app/mutual_client_entrypoint.sh

# These values select the server identity and address. Production deployments
# should authenticate/pin launch configuration rather than treating arbitrary
# operator-provided overrides as trusted policy.
LABEL "tee.launch_policy.allow_env_override"="SERVER_IMAGE_HASH,SERVER_LB_IP,SERVER_PROJECT_ID,SERVER_ZONE,SERVER_HW_MODEL,ATTESTATION_TYPE"

ENTRYPOINT ["/app/mutual_client_entrypoint.sh"]
