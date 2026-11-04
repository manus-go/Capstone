#!/usr/bin/env bash
# =============================================================================
# Instant SCC Finding Simulation via Custom Source (Shell / gcloud CLI)
# =============================================================================
#
# Creates a custom SCC source (if not existing), publishes an active HIGH severity
# finding directly into SCC, and triggers the CloudGuard Pub/Sub -> Cloud Functions
# pipeline instantly without waiting for Cloud Asset Inventory (CAI) batch latency.
#
# Usage:
#   # 1. Create finding with defaults
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
      echo "Usage: $0 [--project ID] [--finding-id ID] [--category CATEGORY] [--bucket BUCKET] [--source-id ID] [--mute]"
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

echo -e "${BOLD}CloudGuard SecOps - Instant SCC Finding Generator (gcloud)${RESET}"
echo -e "Project:    ${CYAN}${PROJECT_ID}${RESET}"
echo -e "Finding ID: ${CYAN}${FINDING_ID}${RESET}"

# Step 1: Ensure Custom Source exists
if [ -z "$SOURCE_ID" ]; then
  echo -e "${YELLOW}[*] Checking for existing 'Demo Source' in project ${PROJECT_ID}...${RESET}"
  EXISTING_SOURCE=$(gcloud scc sources list --parent="projects/${PROJECT_ID}" --format="value(name)" --filter='displayName="Demo Source"' 2>/dev/null | head -n 1 || true)

  if [ -n "$EXISTING_SOURCE" ]; then
    SOURCE_PATH="$EXISTING_SOURCE"
    echo -e "${GREEN}[✓] Found existing source: ${SOURCE_PATH}${RESET}"
  else
    echo -e "${YELLOW}[*] Creating new custom source 'Demo Source'...${RESET}"
    SOURCE_PATH=$(gcloud scc sources create "projects/${PROJECT_ID}" \
      --display-name="Demo Source" \
      --description="Source used for live demonstrations" \
      --format="value(name)")
    echo -e "${GREEN}[✓] Created new source: ${SOURCE_PATH}${RESET}"
  fi
else
  if [[ "$SOURCE_ID" == projects/* ]]; then
    SOURCE_PATH="$SOURCE_ID"
  elif [[ "$SOURCE_ID" == sources/* ]]; then
    SOURCE_PATH="projects/${PROJECT_ID}/${SOURCE_ID}"
  else
    SOURCE_PATH="projects/${PROJECT_ID}/sources/${SOURCE_ID}"
  fi
fi

# Step 2: Perform Action
if [ "$ACTION" == "mute" ]; then
  echo -e "${YELLOW}[*] Setting mute state to MUTED for ${FINDING_ID}...${RESET}"
  gcloud scc findings set-mute "${FINDING_ID}" \
    --source="${SOURCE_PATH}" \
    --mute="MUTED"
  echo -e "${GREEN}[✓] Finding ${FINDING_ID} set to MUTED.${RESET}"
else
  echo -e "${YELLOW}[*] Creating ACTIVE finding ${FINDING_ID} under ${SOURCE_PATH}...${RESET}"
  gcloud scc findings create "${FINDING_ID}" \
    --source="${SOURCE_PATH}" \
    --category="${CATEGORY}" \
    --resource-name="${RESOURCE_NAME}" \
    --state="ACTIVE" \
    --severity="${SEVERITY}"

  echo -e "${GREEN}[✓] Finding created successfully!${RESET}"
  echo -e "    - Resource: ${RESOURCE_NAME}"
  echo -e "    - Severity: ${SEVERITY}"
  echo -e "    - Source:   ${SOURCE_PATH}"
  echo ""
  echo -e "${BOLD}Pipeline Status:${RESET}"
  echo -e "1. Refresh SCC Console -> Finding is immediately visible under Findings."
  echo -e "2. Continuous Export stream publishes to Pub/Sub topic 'scc-high-alerts-topic'."
  echo -e "3. Once your GitOps PR resolves the alert, run:"
  echo -e "   ${CYAN}$0 --source-id $(echo $SOURCE_PATH | awk -F'/' '{print $NF}') --finding-id ${FINDING_ID} --mute${RESET}"
fi
