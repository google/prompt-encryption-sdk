#!/bin/bash
set -e

required_variables=(
    SERVER_IMAGE_HASH
    SERVER_LB_IP
    SERVER_PROJECT_ID
    SERVER_ZONE
)
for variable_name in "${required_variables[@]}"; do
    if [ -z "${!variable_name}" ]; then
        echo "${variable_name} must be set."
        exit 1
    fi
done

exec python3 /app/test_client.py \
    --image-hash "${SERVER_IMAGE_HASH}" \
    --project-id "${SERVER_PROJECT_ID}" \
    --zone "${SERVER_ZONE}" \
    --ip "${SERVER_LB_IP}" \
    --hw-model "${SERVER_HW_MODEL:-TDX}" \
    --mutual-attestation \
    --attestation-type "${ATTESTATION_TYPE:-uds}"
