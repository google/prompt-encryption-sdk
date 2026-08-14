#!/bin/bash
set -e
cd "$(dirname "$0")/.."

if [ -z "$1" ]; then
    echo "Usage: $0 <PROJECT_ID> [ZONE] [uds|gotpm]"
    echo "Run this script inside a Confidential Space client workload."
    exit 1
fi

PROJECT_ID="$1"
ZONE="${2:-us-central1-a}"
ATTESTATION_TYPE="${3:-uds}"

case "${ATTESTATION_TYPE}" in
    uds)
        if [ ! -S /run/container_launcher/teeserver.sock ]; then
            echo "Confidential Space token socket not found. This client must run in Confidential Space."
            exit 1
        fi
        ;;
    gotpm)
        if ! command -v gotpm >/dev/null 2>&1; then
            echo "gotpm was not found on PATH."
            exit 1
        fi
        ;;
    *)
        echo "Attestation type must be 'uds' or 'gotpm'."
        exit 1
        ;;
esac

if [ -n "${SERVER_IMAGE_HASH}" ]; then
    IMAGE_HASH="${SERVER_IMAGE_HASH}"
elif [ -f .image_hash ]; then
    IMAGE_HASH=$(cat .image_hash)
else
    echo "Set SERVER_IMAGE_HASH or provide .image_hash."
    exit 1
fi

if [ -n "${SERVER_LB_IP}" ]; then
    LB_IP="${SERVER_LB_IP}"
elif [ -f .lb_ip ]; then
    LB_IP=$(cat .lb_ip)
else
    echo "Set SERVER_LB_IP or provide .lb_ip."
    exit 1
fi

echo "Running mutually attested confidential client..."
PYTHONPATH=src python3 examples/test_client.py \
    --image-hash "${IMAGE_HASH}" \
    --project-id "${PROJECT_ID}" \
    --zone "${ZONE}" \
    --ip "${LB_IP}" \
    --hw-model "TDX" \
    --mutual-attestation \
    --attestation-type "${ATTESTATION_TYPE}"
