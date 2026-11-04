#!/usr/bin/env bash
# ==============================================================================
# Create Public Bucket ACL Trigger Script (Bash / gcloud)
# ==============================================================================
# Creates a Google Cloud Storage bucket configured specifically to trigger the
# Security Command Center (SCC) finding: 'Public bucket ACL' (PUBLIC_BUCKET_ACL).
#
# Finding Explanation:
# "This bucket is public and can be accessed by anyone on the Internet.
#  allUsers represents anyone on the Internet, and allAuthenticatedUsers represents
#  anyone who is authenticated with a Google Account; neither is constrained to
#  users within your organisation."
#
# Detector Requirements:
# 1. Uniform Bucket-Level Access (UBLA) must be disabled.
# 2. Public Access Prevention must not be enforced (set to inherited).
# 3. An ACL grant is assigned to 'allUsers' or 'allAuthenticatedUsers'.
# ==============================================================================

set -euo pipefail

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-go-capstone-manus}"
LOCATION="${GCP_REGION:-europe-west2}"
TIMESTAMP="$(date +%s)"
BUCKET_NAME="${1:-public-acl-${PROJECT_ID}-${TIMESTAMP}}"
ENTITY="${2:-allUsers}"  # 'allUsers' (anyone on Internet) or 'allAuthenticatedUsers' (any Google login)
ROLE="${3:-READER}"     # 'READER', 'WRITER', or 'OWNER'

echo "================================================================="
echo " Creating Public Bucket ACL to Trigger SCC Finding"
echo "================================================================="
echo "Project ID:        ${PROJECT_ID}"
echo "Bucket Name:       gs://${BUCKET_NAME}"
echo "Location:          ${LOCATION}"
echo "Public Entity:     ${ENTITY}"
echo "ACL Role:          ${ROLE}"
echo "UBLA:              Disabled (--no-uniform-bucket-level-access)"
echo "-----------------------------------------------------------------"

# Step 1: Create the bucket with UBLA disabled
echo "[1/3] Creating bucket gs://${BUCKET_NAME} with UBLA disabled..."
if command -v gcloud &> /dev/null; then
    gcloud storage buckets create "gs://${BUCKET_NAME}" \
        --project="${PROJECT_ID}" \
        --location="${LOCATION}" \
        --no-uniform-bucket-level-access \
        --public-access-prevention=inherited

    # Step 2: Add public ACL grant
    echo "[2/3] Adding public ACL grant (${ENTITY}:${ROLE})..."
    gcloud storage buckets update "gs://${BUCKET_NAME}" \
        --add-acl-grant="entity=${ENTITY},role=${ROLE}"

    # Step 3: Verify ACL
    echo "[3/3] Verifying bucket ACL..."
    gcloud storage buckets describe "gs://${BUCKET_NAME}" --format="yaml(acl,iamConfiguration)"

elif command -v gsutil &> /dev/null; then
    gsutil mb -p "${PROJECT_ID}" -l "${LOCATION}" -b off "gs://${BUCKET_NAME}"
    gsutil pap set inherited "gs://${BUCKET_NAME}" || true
    echo "[2/3] Adding public ACL grant (${ENTITY}:${ROLE})..."
    gsutil acl ch -u "${ENTITY}:${ROLE:0:1}" "gs://${BUCKET_NAME}"
    echo "[3/3] Verifying bucket ACL..."
    gsutil acl get "gs://${BUCKET_NAME}"
else
    echo "Neither gcloud nor gsutil found in PATH. Please run python3 scripts/create_public_bucket.py instead."
    exit 1
fi

echo ""
echo "================================================================="
echo " Finding Triggered: 'Public bucket ACL' (PUBLIC_BUCKET_ACL)"
echo "================================================================="
echo "This bucket is public and can be accessed by anyone on the Internet."
echo "allUsers represents anyone on the Internet, and allAuthenticatedUsers"
echo "represents anyone who is authenticated with a Google Account; neither"
echo "is constrained to users within your organisation."
echo ""
echo "To clean up / delete the bucket when done:"
echo "  gcloud storage rm --recursive gs://${BUCKET_NAME}"
echo "================================================================="
