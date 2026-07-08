#!/bin/bash
set -e
cd "$(dirname "$0")/.."

# Default values
PROJECT_ID=""
ZONE="us-central1-a"
REGION="us-central1"
IMAGE_NAME=""
SA_NAME="secure-inference-sa"
VM_NAME="secure-inference-node"
IG_NAME="secure-inference-ig"
HC_NAME="secure-inference-hc"
BACKEND_NAME="secure-inference-backend"
FW_VLLM_NAME="allow-vllm-ingress"
FW_HC_NAME="allow-hc-ingress"
FWD_RULE_NAME="secure-inference-forwarding-rule"

usage() {
    echo "Usage: $0 --project-id <PROJECT_ID> [OPTIONS]"
    echo "Options:"
    echo "  --zone <ZONE>                  Default: us-central1-a"
    echo "  --region <REGION>              Default: us-central1"
    echo "  --image-name <IMAGE_NAME>      Default: gcr.io/<PROJECT_ID>/secure-vllm:v1"
    echo "  --sa-name <SA_NAME>            Default: secure-inference-sa"
    echo "  --vm-name <VM_NAME>            Default: secure-inference-node"
    echo "  --ig-name <IG_NAME>            Default: secure-inference-ig"
    echo "  --hc-name <HC_NAME>            Default: secure-inference-hc"
    echo "  --backend-name <BACKEND>       Default: secure-inference-backend"
    echo "  --fw-vllm-name <FW_VLLM>       Default: allow-vllm-ingress"
    echo "  --fw-hc-name <FW_HC>           Default: allow-hc-ingress"
    echo "  --fwd-rule-name <FWD_RULE>     Default: secure-inference-forwarding-rule"
    exit 1
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --project-id) PROJECT_ID="$2"; shift ;;
        --zone) ZONE="$2"; shift ;;
        --region) REGION="$2"; shift ;;
        --image-name) IMAGE_NAME="$2"; shift ;;
        --sa-name) SA_NAME="$2"; shift ;;
        --vm-name) VM_NAME="$2"; shift ;;
        --ig-name) IG_NAME="$2"; shift ;;
        --hc-name) HC_NAME="$2"; shift ;;
        --backend-name) BACKEND_NAME="$2"; shift ;;
        --fw-vllm-name) FW_VLLM_NAME="$2"; shift ;;
        --fw-hc-name) FW_HC_NAME="$2"; shift ;;
        --fwd-rule-name) FWD_RULE_NAME="$2"; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown parameter passed: $1"; usage ;;
    esac
    shift
done

if [ -z "${PROJECT_ID}" ]; then
    echo "ERROR: --project-id is required."
    usage
fi

if [ -z "${IMAGE_NAME}" ]; then
    IMAGE_NAME="gcr.io/${PROJECT_ID}/secure-vllm:v1"
fi

if [ -z "${HF_TOKEN}" ]; then
    echo "ERROR: HF_TOKEN environment variable is not set."
    echo "Gemma models require a Hugging Face token to download. Get one at https://huggingface.co/settings/tokens and set it via:"
    echo "export HF_TOKEN='your_hf_token'"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 is not installed or not in PATH."
    exit 1
fi

echo "Enabling APIs..."
gcloud services enable compute.googleapis.com \
    confidentialcomputing.googleapis.com \
    logging.googleapis.com \
    storage.googleapis.com \
    --project="${PROJECT_ID}"

BUCKET_NAME="secure-vllm-model-${PROJECT_ID}"

echo "Creating GCS bucket gs://${BUCKET_NAME}..."
gcloud storage buckets create "gs://${BUCKET_NAME}" --location="${REGION}" --project="${PROJECT_ID}" || true

echo "Provisioning model to GCS..."
python3 -m venv venv-provision
./venv-provision/bin/pip install -i https://pypi.org/simple/ huggingface_hub google-cloud-storage absl-py
./venv-provision/bin/python3 codelabs/provision_model.py --bucket_name "${BUCKET_NAME}"
rm -rf venv-provision

echo "Building and pushing Docker image..."
docker build -t "${IMAGE_NAME}" -f examples/Dockerfile .
docker push "${IMAGE_NAME}"

IMAGE_HASH=$(gcloud container images describe "${IMAGE_NAME}" --format="value(image_summary.digest)" --project="${PROJECT_ID}")
echo "Image Hash: ${IMAGE_HASH}"

echo "Creating Service Account..."
gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Secure Inference Service Account" \
    --project="${PROJECT_ID}" || true

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "Granting permissions..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/confidentialcomputing.workloadUser" || true

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/storage.objectViewer" || true

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/confidentialcomputing.viewer" || true

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/logging.logWriter" || true

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/artifactregistry.reader" || true

echo "Waiting for IAM permissions to propagate..."
sleep 60

echo "Creating Confidential VM..."
gcloud compute instances create "${VM_NAME}" \
    --project="${PROJECT_ID}" \
    --zone="${ZONE}" \
    --machine-type=a3-highgpu-1g \
    --confidential-compute-type=TDX \
    --maintenance-policy=TERMINATE \
    --image-family=confidential-space-debug \
    --image-project=confidential-space-images \
    --service-account="${SA_EMAIL}" \
    --scopes=cloud-platform \
    --tags="${VM_NAME}" \
    --provisioning-model=SPOT \
    --shielded-secure-boot \
    --boot-disk-size=100GB \
    --metadata="tee-image-reference=${IMAGE_NAME},tee-install-gpu-driver=true,tee-experiment-enable-confidential-gpu-support=true,tee-container-log-redirect=true,tee-mount-tmp=true,tee-env-GCS_BUCKET_NAME=${BUCKET_NAME}" || true

echo "Configuring Network & Load Balancer..."
gcloud compute firewall-rules create "${FW_VLLM_NAME}" \
    --project="${PROJECT_ID}" \
    --allow=tcp:8000 \
    --target-tags="${VM_NAME}" \
    --description="Allow vLLM secure inference requests" || true

gcloud compute instance-groups unmanaged create "${IG_NAME}" --zone="${ZONE}" --project="${PROJECT_ID}" || true
gcloud compute instance-groups unmanaged set-named-ports "${IG_NAME}" \
    --named-ports=http:8000 --zone="${ZONE}" --project="${PROJECT_ID}" || true
gcloud compute instance-groups unmanaged add-instances "${IG_NAME}" \
    --zone="${ZONE}" --instances="${VM_NAME}" --project="${PROJECT_ID}" || true

gcloud compute health-checks create tcp "${HC_NAME}" \
    --region="${REGION}" --port=8000 --project="${PROJECT_ID}" || true

gcloud compute backend-services create "${BACKEND_NAME}" \
    --protocol=TCP --region="${REGION}" --load-balancing-scheme=EXTERNAL \
    --health-checks="${HC_NAME}" --health-checks-region="${REGION}" --project="${PROJECT_ID}" || true

gcloud compute backend-services add-backend "${BACKEND_NAME}" \
    --instance-group="${IG_NAME}" --instance-group-zone="${ZONE}" --region="${REGION}" --project="${PROJECT_ID}" || true

gcloud compute firewall-rules create "${FW_HC_NAME}" \
    --project="${PROJECT_ID}" \
    --allow=tcp:8000 \
    --source-ranges=130.211.0.0/22,35.191.0.0/16 \
    --target-tags="${VM_NAME}" \
    --description="Allow Load Balancer Health Check probes" || true

gcloud compute forwarding-rules create "${FWD_RULE_NAME}" \
    --region="${REGION}" --ports=8000 --backend-service="${BACKEND_NAME}" --project="${PROJECT_ID}" || true

LB_IP=$(gcloud compute forwarding-rules describe "${FWD_RULE_NAME}" --region="${REGION}" --format="value(IPAddress)" --project="${PROJECT_ID}")

echo "=================================================="
echo "Setup Complete!"
echo "Image Hash: ${IMAGE_HASH}"
echo "Load Balancer IP: ${LB_IP}"
echo "=================================================="
echo "${IMAGE_HASH}" > .image_hash
echo "${LB_IP}" > .lb_ip
