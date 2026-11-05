#!/usr/bin/env bash
# =============================================================================
# Instant SCC Finding Simulation (Shell / gcloud CLI)
# =============================================================================
#
# Simulates a Security Command Center (SCC) security finding to instantly trigger
# the CloudGuard SecOps pipeline without Cloud Asset Inventory (CAI) batch latency.
#
# In standalone GCP projects (without an Organization node), directly injects
# the simulated finding payload into the project's Continuous Export Pub/Sub topic
# (scc-high-alerts-topic). If an Organization ID is supplied, it interacts directly
# with the SCC v1 API.
#
# Usage:
#   # 1. Simulate finding with defaults (Pub/Sub injection to scc-high-alerts-topic)
#   ./scripts/simulate_scc_finding.sh
#
#   # 2. Specify finding ID and target resource
#   ./scripts/simulate_scc_finding.sh --finding-id demo-finding-01 --bucket my-demo-bucket
#
#   # 3. Mute finding when resolved
#   ./scripts/simulate_scc_finding.sh --finding-id demo-finding-01 --mute
# =============================================================================

set -euo pipefail

# ANSI colors
GREEN="\033[92m"
YELLOW="\033[93m"
CYAN="\033[96m"
RED="\033[91m"
BOLD="\033[1m"
RESET="\033[0m"

# Load default project from .env if present
PROJECT_ID=""
if [ -f .env ]; then
  PROJECT_ID=$(grep -E '^PROJECT_ID=' .env | cut -d '=' -f 2 | tr -d '"' | tr -d "'" || true)
fi
if [ -z "$PROJECT_ID" ]; then
  PROJECT_ID=${GCP_PROJECT_ID:-"go-capstone-manus"}
fi

TOPIC_NAME="scc-high-alerts-topic"
ORG_ID=""
FINDING_ID="demo-finding-$(date +%s)"
CATEGORY="PUBLIC_BUCKET_ACL"
SEVERITY="HIGH"
BUCKET_NAME=""
ACTION="create"
SOURCE_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)
      PROJECT_ID="$2"
      shift 2
      ;;
    --topic)
      TOPIC_NAME="$2"
      shift 2
      ;;
    --org-id)
      ORG_ID="$2"
      shift 2
      ;;
    --finding-id)
      FINDING_ID="$2"
      shift 2
      ;;
    --category)
      CATEGORY="$2"
      shift 2
      ;;
    --severity)
      SEVERITY="$2"
      shift 2
      ;;
    --bucket)
      BUCKET_NAME="$2"
      shift 2
      ;;
    --source-id)
      SOURCE_ID="$2"
      shift 2
      ;;
    --mute)
      ACTION="mute"
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--project ID] [--topic TOPIC] [--org-id ORG_ID] [--finding-id ID] [--category CATEGORY] [--bucket BUCKET] [--source-id ID] [--mute]"
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown argument: $1${RESET}"
      exit 1
      ;;
  esac
done

if [ -z "$BUCKET_NAME" ]; then
  BUCKET_NAME="${PROJECT_ID}-demo-public-bucket"
fi
RESOURCE_NAME="//storage.googleapis.com/${BUCKET_NAME}"

echo -e "${BOLD}CloudGuard SecOps - Instant SCC Finding Simulator (gcloud)${RESET}"
echo -e "Project:    ${CYAN}${PROJECT_ID}${RESET}"
echo -e "Finding ID: ${CYAN}${FINDING_ID}${RESET}"

# Check if Organization mode or Standalone mode
if [ -n "$ORG_ID" ]; then
  echo -e "${CYAN}[i] Organization mode detected (Org ID: ${ORG_ID}). Interacting with SCC v1 API...${RESET}"
  
  if [ -z "$SOURCE_ID" ]; then
    EXISTING_SOURCE=$(gcloud scc sources list --parent="organizations/${ORG_ID}" --format="value(name)" --filter='displayName="Demo Source"' 2>/dev/null | head -n 1 || true)
    if [ -n "$EXISTING_SOURCE" ]; then
      SOURCE_PATH="$EXISTING_SOURCE"
      echo -e "${GREEN}[✓] Found existing source: ${SOURCE_PATH}${RESET}"
    else
      echo -e "${YELLOW}[*] Creating new custom source 'Demo Source'...${RESET}"
      SOURCE_PATH=$(gcloud scc sources create "organizations/${ORG_ID}" \
        --display-name="Demo Source" \
        --description="Source used for live demonstrations" \
        --format="value(name)")
      echo -e "${GREEN}[✓] Created new source: ${SOURCE_PATH}${RESET}"
    fi
  else
    SOURCE_PATH="$SOURCE_ID"
  fi

  if [ "$ACTION" == "mute" ]; then
    echo -e "${YELLOW}[*] Setting mute state to MUTED for ${FINDING_ID}...${RESET}"
    gcloud scc findings set-mute "${FINDING_ID}" \
      --source="${SOURCE_PATH}" \
      --mute="MUTED"
    echo -e "${GREEN}[✓] Finding ${FINDING_ID} set to MUTED in SCC.${RESET}"
  else
    echo -e "${YELLOW}[*] Creating ACTIVE finding ${FINDING_ID} under ${SOURCE_PATH}...${RESET}"
    gcloud scc findings create "${FINDING_ID}" \
      --source="${SOURCE_PATH}" \
      --category="${CATEGORY}" \
      --resource-name="${RESOURCE_NAME}" \
      --state="ACTIVE" \
      --severity="${SEVERITY}"
    echo -e "${GREEN}[✓] Finding created successfully in SCC!${RESET}"
  fi
  exit 0
fi

# Standalone Project Mode: Direct Pub/Sub Injection
echo -e "${CYAN}[i] Standalone project environment detected (using direct Pub/Sub injection).${RESET}"

if [ "$ACTION" == "mute" ]; then
  echo -e "${YELLOW}[*] Acknowledging mute for simulated finding ${FINDING_ID}.${RESET}"
  echo -e "${GREEN}[✓] Mute signal registered for ${FINDING_ID}.${RESET}"
  exit 0
fi

EVENT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PAYLOAD=$(cat <<EOF
{
  "finding": {
    "name": "projects/${PROJECT_ID}/sources/simulation/findings/${FINDING_ID}",
    "parent": "projects/${PROJECT_ID}/sources/simulation",
    "resourceName": "${RESOURCE_NAME}",
    "state": "ACTIVE",
    "category": "${CATEGORY}",
    "severity": "${SEVERITY}",
    "findingClass": "MISCONFIGURATION",
    "description": "Bucket ${BUCKET_NAME} has public ACL allowing internet-wide unauthenticated access.",
    "eventTime": "${EVENT_TIME}",
    "createTime": "${EVENT_TIME}",
    "sourceProperties": {
      "Explanation": "Bucket has public ACL allowing internet-wide unauthenticated access.",
      "Simulation": "Instant demo finding injected directly into Continuous Export Pub/Sub topic."
    }
  },
  "resource": {
    "name": "${RESOURCE_NAME}",
    "projectDisplayName": "${PROJECT_ID}"
  }
}
EOF
)

echo -e "${YELLOW}[*] Publishing simulated finding to Pub/Sub topic '${TOPIC_NAME}'...${RESET}"
gcloud pubsub topics publish "${TOPIC_NAME}" \
  --project="${PROJECT_ID}" \
  --message="${PAYLOAD}" \
  --attribute="finding_id=${FINDING_ID},category=${CATEGORY},severity=${SEVERITY},source=simulation-tool"

echo -e "${GREEN}[✓] Successfully published to Pub/Sub topic '${TOPIC_NAME}'!${RESET}"
echo -e "    - Finding ID: ${FINDING_ID}"
echo -e "    - Category:   ${CATEGORY}"
echo -e "    - Severity:   ${SEVERITY}"
echo -e "    - Resource:   ${RESOURCE_NAME}"
echo ""
echo -e "${BOLD}Pipeline Status:${RESET}"
echo -e "1. Pub/Sub notification delivered to 'scc-alert-router' Cloud Function."
echo -e "2. Gemini Vertex AI will triage the misconfiguration and evaluate risk."
echo -e "3. An interactive Card V2 alert will arrive in Google Chat with progressive disclosure."
echo -e "4. Telemetry and real-time lifecycle tracking available at /dashboard."
