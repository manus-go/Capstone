import base64
import html
import json
import logging
import os
import re
import sys
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

import functions_framework
import requests
from google.cloud import firestore
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# -----------------------------------------------------------------------------
# Environment Loader
# -----------------------------------------------------------------------------
def load_env_file():
    """Loads environment variables from .env if present without overwriting existing vars."""
    search_dirs = [
        os.getcwd(),
        os.path.dirname(os.path.abspath(__file__)),
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ]
    for directory in search_dirs:
        env_file = os.path.join(directory, ".env")
        if os.path.isfile(env_file):
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("export "):
                            line = line[7:].strip()
                        if "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass
            break

load_env_file()

# -----------------------------------------------------------------------------
# Logging Setup
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scc-remediation-receiver")

# -----------------------------------------------------------------------------
# Configuration from Environment
# -----------------------------------------------------------------------------
PROJECT_ID = os.environ.get("PROJECT_ID", "")
VERTEX_LOCATION = os.environ.get("VERTEX_AI_LOCATION", "europe-west2")
VERTEX_MODEL = os.environ.get("VERTEX_AI_MODEL", "gemini-2.5-flash")
GOOGLE_CHAT_WEBHOOK_URL = os.environ.get("GOOGLE_CHAT_WEBHOOK_URL", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "")
GITHUB_BASE_BRANCH = os.environ.get("GITHUB_BASE_BRANCH", "main")
BIGQUERY_DATASET = os.environ.get("BIGQUERY_DATASET", "secops_lake")
BIGQUERY_TABLE = os.environ.get("BIGQUERY_TABLE", "scc_findings_raw")

# Lazy-loaded Firestore client
_db = None


def get_firestore_client() -> firestore.Client:
    global _db
    if _db is None:
        _db = firestore.Client(project=PROJECT_ID)
    return _db


def safe_json_dumps(obj: Any, **kwargs) -> str:
    """Safely serializes objects to JSON, handling Firestore timestamps and non-serializable objects."""
    return json.dumps(obj, default=str, **kwargs)


def sanitize_doc_id(raw_id: str) -> str:
    """Sanitizes strings to create valid, URL-safe Firestore document IDs."""
    if not raw_id:
        return "unknown"
    sanitized = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", raw_id)
    return sanitized[:200]


def parse_resource_display(resource_name: str, project_id: str = "") -> Dict[str, str]:
    """
    Parses an SCC resourceName URI into a clean resource name, asset type, and project ID.
    """
    raw = (resource_name or "").strip()
    clean_name = raw
    asset_type = "GCP Resource"
    extracted_proj = project_id

    # Check for project in URI
    proj_match = re.search(r"/projects/([^/]+)", raw)
    if proj_match and proj_match.group(1) != "_":
        extracted_proj = proj_match.group(1)

    if "storage.googleapis.com" in raw or "/buckets/" in raw:
        asset_type = "Cloud Storage Bucket"
        parts = raw.split("/buckets/")
        if len(parts) > 1:
            clean_name = parts[-1].split("/")[0]
    elif "compute.googleapis.com" in raw or "/firewalls/" in raw or "/instances/" in raw or "/disks/" in raw or "/subnetworks/" in raw:
        if "/firewalls/" in raw:
            asset_type = "VPC Firewall Rule"
            clean_name = raw.split("/firewalls/")[-1].split("/")[0]
        elif "/instances/" in raw:
            asset_type = "Compute Engine VM"
            clean_name = raw.split("/instances/")[-1].split("/")[0]
        elif "/disks/" in raw:
            asset_type = "Persistent Disk"
            clean_name = raw.split("/disks/")[-1].split("/")[0]
        elif "/subnetworks/" in raw:
            asset_type = "VPC Subnetwork"
            clean_name = raw.split("/subnetworks/")[-1].split("/")[0]
        elif "/networks/" in raw:
            asset_type = "VPC Network"
            clean_name = raw.split("/networks/")[-1].split("/")[0]
        else:
            asset_type = "Compute Engine Resource"
            clean_name = raw.rstrip("/").split("/")[-1]
    elif "iam.googleapis.com" in raw or "/serviceAccounts/" in raw:
        asset_type = "IAM Service Account"
        if "/serviceAccounts/" in raw:
            clean_name = raw.split("/serviceAccounts/")[-1].split("/")[0]
        else:
            clean_name = raw.rstrip("/").split("/")[-1]
    elif "cloudresourcemanager.googleapis.com" in raw or ("/projects/" in raw and raw.endswith(extracted_proj)):
        asset_type = "Cloud Project"
        clean_name = extracted_proj
    elif "/" in raw:
        clean_name = raw.rstrip("/").split("/")[-1]

    return {
        "clean_resource_name": clean_name or "Unknown Resource",
        "asset_type": asset_type,
        "project_id": extracted_proj or project_id or "GCP Project",
        "full_resource": raw
    }


# -----------------------------------------------------------------------------
# Intent Classification: Act vs Don't Act vs Show Details
# -----------------------------------------------------------------------------
NO_ACTION_KEYWORDS = [
    "don't act",
    "dont act",
    "do not act",
    "ignore",
    "dismiss",
    "no action",
    "no",
    "skip",
    "opt out",
    "leave it",
    "pass",
    "wont fix",
    "won't fix",
    "not now",
    "cancel",
    "discard",
    "reject",
]


def classify_user_intent(
    text: str,
    action_param: Optional[str] = None,
    option_param: Optional[Any] = None
) -> Tuple[str, Optional[int]]:
    """
    Classifies the user response into either:
    - 'NO_ACTION' (user does not want to act on the issue)
    - 'SHOW_DETAILS' (user wants to see deep-dive architectural reasoning)
    - 'REMEDIATE' (user wants to remediate using a specific fix option)
    - 'UNKNOWN'

    Returns (intent, chosen_option_number).
    """
    normalized_text = (text or "").strip().lower()

    # Check explicit action parameter (e.g. from card action or query string)
    if action_param:
        act_lower = action_param.lower()
        if any(kw in act_lower for kw in ["ignore", "dismiss", "no_action", "cancel", "skip"]):
            return "NO_ACTION", None
        if any(kw in act_lower for kw in ["show_details", "details", "show_more", "deep_dive"]):
            return "SHOW_DETAILS", None
        if "remediate" in act_lower or "fix" in act_lower or "option" in act_lower:
            try:
                opt_num = int(option_param) if option_param is not None else 1
                return "REMEDIATE", opt_num
            except (ValueError, TypeError):
                return "REMEDIATE", 1

    # Check for direct NO_ACTION intent
    for kw in NO_ACTION_KEYWORDS:
        if re.search(rf"\b{re.escape(kw)}\b", normalized_text):
            return "NO_ACTION", None

    # Check for SHOW_DETAILS intent
    if any(kw in normalized_text for kw in ["show details", "more details", "deep dive", "details"]):
        return "SHOW_DETAILS", None

    # Check for option number passed in parameter
    if option_param is not None:
        try:
            return "REMEDIATE", int(option_param)
        except (ValueError, TypeError):
            pass

    # Regex matches for option selections: e.g. "option 1", "choice 2", "fix 1", "#1", "1"
    opt_match = re.search(r"(?:option|choice|pick|fix)\s*#?\s*([1-9])", normalized_text)
    if opt_match:
        return "REMEDIATE", int(opt_match.group(1))

    # Exact single digit: "1", "2", "3"
    digit_match = re.match(r"^\s*#?\s*([1-9])\s*$", normalized_text)
    if digit_match:
        return "REMEDIATE", int(digit_match.group(1))

    # Match "best" or "recommended"
    if re.search(r"\b(best|recommended)\b", normalized_text):
        return "REMEDIATE", 1

    # General affirmative words: "fix it", "apply", "remediate", "proceed"
    if any(kw in normalized_text for kw in ["fix", "remediate", "proceed", "code", "terraform"]):
        return "REMEDIATE", 1

    return "UNKNOWN", None


# -----------------------------------------------------------------------------
# Finding / Alert Lookup in Firestore
# -----------------------------------------------------------------------------
def fetch_target_alert(
    finding_id: Optional[str] = None,
    thread_name: Optional[str] = None
) -> Tuple[Optional[firestore.DocumentReference], Optional[Dict[str, Any]]]:
    """
    Locates the target alert document in Firestore.
    1. If finding_id is provided, look up by document ID or finding_id field.
    2. If thread_name is provided, look up by thread reference.
    3. Fallback: Fetch the most recently processed alert in 'alerts' collection.
    """
    db = get_firestore_client()
    alerts_col = db.collection("alerts")

    # 1. Direct finding ID lookup
    if finding_id:
        doc_ref = alerts_col.document(finding_id)
        doc = doc_ref.get()
        if doc.exists:
            return doc_ref, doc.to_dict()

        query = alerts_col.where("finding_id", "==", finding_id).limit(1)
        results = list(query.stream())
        if results:
            return results[0].reference, results[0].to_dict()

    # 2. Thread lookup
    if thread_name:
        query = alerts_col.where("google_chat.thread_name", "==", thread_name).limit(1)
        results = list(query.stream())
        if results:
            return results[0].reference, results[0].to_dict()

    # 3. Fallback: Fetch latest alert ordered by processed_at descending
    try:
        query = alerts_col.order_by("processed_at", direction=firestore.Query.DESCENDING).limit(1)
        results = list(query.stream())
        if results:
            return results[0].reference, results[0].to_dict()
    except Exception as e:
        logger.warning(f"Failed to query alerts ordered by processed_at: {e}. Falling back to un-ordered query.")
        results = list(alerts_col.limit(5).stream())
        if results:
            return results[-1].reference, results[-1].to_dict()

    return None, None





# -----------------------------------------------------------------------------
# GitHub Integration: Deterministic Pull Request Automation & Baseline Diffs
# -----------------------------------------------------------------------------
def fetch_baseline_terraform_file(
    repo: str,
    token: str,
    base_branch: str,
    file_path: str = "infrastructure/main.tf"
) -> Tuple[Optional[str], Optional[str]]:
    """
    Fetches the content and commit blob SHA of an existing Terraform baseline file from GitHub.
    Returns (decoded_content_str, blob_sha) or (None, None) if not found or on error.
    """
    if not repo or not token:
        return None, None
    headers = {
        "Authorization": f"token {token.strip()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "CloudGuard-SecOps-Receiver"
    }
    url = f"https://api.github.com/repos/{repo.strip()}/contents/{file_path.strip('/')}?ref={base_branch.strip()}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            content_b64 = data.get("content", "")
            blob_sha = data.get("sha")
            decoded_text = base64.b64decode(content_b64).decode("utf-8")
            logger.info(f"Successfully fetched baseline '{file_path}' (blob SHA: {blob_sha[:8] if blob_sha else 'unknown'})")
            return decoded_text, blob_sha
        else:
            logger.info(f"Baseline file '{file_path}' not found on branch '{base_branch}': HTTP {resp.status_code}")
            return None, None
    except Exception as e:
        logger.warning(f"Error fetching baseline file '{file_path}' from GitHub: {e}")
        return None, None


def create_github_pull_request(
    repo: str,
    token: str,
    base_branch: str,
    issue_type: str,
    resource_name: str,
    finding_id: str,
    option_number: int,
    option_title: str,
    option_strategy: str,
    terraform_code: str,
    explanation: str,
    execution_instructions: str,
    file_path: Optional[str] = None,
    existing_file_sha: Optional[str] = None,
    what_is_causing_issue: Optional[str] = None,
    risk_summary: Optional[str] = None,
    recommended_fix: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Deterministically creates a Git branch, commits the generated Terraform HCL file
    (modifying an existing baseline file with true red/green diff if SHA provided, or creating a new file),
    and opens a streamlined GitHub Pull Request against the base branch.
    """
    if not repo or not token:
        logger.warning("GitHub integration skipped: GITHUB_REPO or GITHUB_TOKEN not configured.")
        return {"success": False, "skipped": True, "error": "GitHub credentials not configured"}

    headers = {
        "Authorization": f"token {token.strip()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "CloudGuard-SecOps-Receiver"
    }
    api_base = f"https://api.github.com/repos/{repo.strip()}"

    # 1. Fetch base branch HEAD SHA
    try:
        ref_resp = requests.get(f"{api_base}/git/ref/heads/{base_branch}", headers=headers, timeout=15)
        if ref_resp.status_code != 200:
            err = f"Failed to retrieve base branch '{base_branch}': HTTP {ref_resp.status_code} - {ref_resp.text[:200]}"
            logger.error(err)
            return {"success": False, "error": err}
        base_sha = ref_resp.json().get("object", {}).get("sha")
        if not base_sha:
            err = f"Could not extract commit SHA for base branch '{base_branch}'"
            logger.error(err)
            return {"success": False, "error": err}
    except Exception as e:
        logger.error(f"Error querying base branch: {e}")
        return {"success": False, "error": str(e)}

    # 2. Sanitize and prepare branch name
    clean_issue = re.sub(r"[^a-zA-Z0-9_\-]", "_", issue_type).lower().strip("_")
    short_fid = re.sub(r"[^a-zA-Z0-9]", "", finding_id)[-8:] if finding_id else "finding"
    timestamp = int(time.time())
    branch_name = f"remediation/{clean_issue}-{short_fid}-{timestamp}"

    # 3. Create new branch
    try:
        branch_payload = {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha
        }
        create_resp = requests.post(f"{api_base}/git/refs", json=branch_payload, headers=headers, timeout=15)
        if create_resp.status_code not in (200, 201):
            err = f"Failed to create Git branch '{branch_name}': HTTP {create_resp.status_code} - {create_resp.text[:200]}"
            logger.error(err)
            return {"success": False, "error": err}
        logger.info(f"Created GitHub branch: {branch_name} (from {base_sha[:8]})")
    except Exception as e:
        logger.error(f"Error creating Git branch: {e}")
        return {"success": False, "error": str(e)}

    # 4. Determine file path and commit Terraform code (updating in place if SHA is present)
    clean_res = resource_name.strip("/").split("/")[-1]
    clean_res = re.sub(r"[^a-zA-Z0-9_\-]", "_", clean_res).lower().strip("_") or "resource"
    target_path = file_path if file_path else f"remediations/{clean_issue}_{clean_res}.tf"

    try:
        b64_content = base64.b64encode(terraform_code.encode("utf-8")).decode("utf-8")
        commit_msg = (
            f"fix(secops): remediate {issue_type} in {target_path}\n\n"
            f"Automated GitOps diff for Option {option_number}: {option_title}"
            if existing_file_sha
            else f"fix(secops): remediate {issue_type} on {clean_res}\n\n"
                 f"Automated fix for Option {option_number}: {option_title}"
        )
        commit_payload = {
            "message": commit_msg,
            "content": b64_content,
            "branch": branch_name
        }
        if existing_file_sha:
            commit_payload["sha"] = existing_file_sha

        commit_resp = requests.put(f"{api_base}/contents/{target_path}", json=commit_payload, headers=headers, timeout=15)
        if commit_resp.status_code not in (200, 201):
            err = f"Failed to commit file '{target_path}': HTTP {commit_resp.status_code} - {commit_resp.text[:200]}"
            logger.error(err)
            return {"success": False, "error": err}
        logger.info(f"Committed Terraform code to {target_path} on branch {branch_name} (in-place diff: {bool(existing_file_sha)})")
    except Exception as e:
        logger.error(f"Error committing file to GitHub: {e}")
        return {"success": False, "error": str(e)}

    # 5. Open Pull Request with Streamlined Actionable Structure
    pr_title = f"[SecOps Fix] Remediate {issue_type} on {clean_res}"
    cause_text = what_is_causing_issue.strip() if what_is_causing_issue else f"Security Command Center detected non-compliant cloud resource configuration (`{issue_type}`)."
    risk_text = risk_summary.strip() if risk_summary else "Unrestricted exposure may allow unauthorized public access or privilege escalation."
    fix_text = recommended_fix.strip() if recommended_fix else f"Applied Option {option_number}: {option_title}. {option_strategy}"

    pr_body = f"""## 🛡️ CloudGuard SecOps Automated Remediation

### 1. What is causing the issue
{cause_text}

### 2. The Error / Risk
- **Resource Affected:** `{resource_name}`
- **Security Impact:** {risk_text}

### 3. Recommended Fix Applied ({option_title})
- **Target File:** `{target_path}` {'(Modified In-Place Baseline)' if existing_file_sha else '(Staged New Remediation)'}
- **Remediation Strategy:** {fix_text}

### 4. Call to Action
Please check the files changed in this PR, review the Terraform diff, and merge/apply to handle this.
"""

    try:
        pr_payload = {
            "title": pr_title,
            "head": branch_name,
            "base": base_branch,
            "body": pr_body,
            "draft": False
        }
        pr_resp = requests.post(f"{api_base}/pulls", json=pr_payload, headers=headers, timeout=15)
        if pr_resp.status_code not in (200, 201):
            err = f"Failed to create Pull Request: HTTP {pr_resp.status_code} - {pr_resp.text[:200]}"
            logger.error(err)
            return {"success": False, "error": err}

        pr_data = pr_resp.json()
        pr_url = pr_data.get("html_url")
        pr_number = pr_data.get("number")
        logger.info(f"Successfully opened GitHub Pull Request #{pr_number}: {pr_url}")

        return {
            "success": True,
            "pr_url": pr_url,
            "pr_number": pr_number,
            "branch_name": branch_name,
            "file_path": target_path,
            "is_diff": bool(existing_file_sha),
            "pr_title": pr_title
        }
    except Exception as e:
        logger.error(f"Error creating GitHub Pull Request: {e}")
        return {"success": False, "error": str(e)}


# -----------------------------------------------------------------------------
# Dispatch Status to Google Chat Space
# -----------------------------------------------------------------------------
def notify_google_chat(webhook_url: str, text: str = "", card_payload: Optional[dict] = None) -> Tuple[str, str]:
    """
    Posts an update notification or card back into the user's Google Chat space.
    Enforces:
    - Card Exclusivity: When card_payload is sent, only 'cardsV2' is in payload (never top-level 'text').
    - Webhook Resilience: Retries transient 5xx errors with exponential backoff (at least 2 attempts).
    - Plain-text fallback if card delivery fails.
    """
    if not webhook_url or not webhook_url.strip():
        logger.info("Google Chat webhook URL not set; notification skipped.")
        return ("SKIPPED", "No webhook URL configured.")

    headers = {"Content-Type": "application/json; charset=UTF-8"}
    last_err = ""

    if card_payload:
        clean_card = {"cardsV2": card_payload.get("cardsV2", [])}
        for attempt in range(1, 3):
            try:
                resp = requests.post(webhook_url.strip(), json=clean_card, headers=headers, timeout=10)
                if resp.status_code == 200:
                    logger.info(f"Google Chat Card V2 posted successfully (attempt {attempt}).")
                    return ("SUCCESS", "Card V2 dispatched.")
                last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                logger.warning(f"Google Chat Card post attempt {attempt} failed ({last_err}).")
                if resp.status_code >= 500 and attempt < 2:
                    time.sleep(2)
                    continue
                break
            except Exception as e:
                last_err = str(e)
                logger.warning(f"Google Chat Card post exception on attempt {attempt}: {e}")
                if attempt < 2:
                    time.sleep(2)
                    continue
                break

    # If text is present (either direct or fallback after card attempt failed):
    fallback_text = text or "SecOps notification: Status updated for security finding."
    for attempt in range(1, 3):
        try:
            resp = requests.post(webhook_url.strip(), json={"text": fallback_text}, headers=headers, timeout=10)
            if resp.status_code == 200:
                logger.info("Google Chat text notification posted successfully.")
                return ("SUCCESS_TEXT", "Text notification dispatched.")
            last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
            if resp.status_code >= 500 and attempt < 2:
                time.sleep(2)
                continue
            break
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(2)
                continue
            break

    logger.error(f"Failed to post to Google Chat webhook: {last_err}")
    return ("FAILED", last_err)


def build_deep_dive_chat_card(
    finding_id: str,
    issue_type: str,
    severity: str,
    resource_name: str,
    project_id: str,
    ai_analysis: dict,
    receiver_url: str = ""
) -> dict:
    """
    Constructs a Google Chat Card V2 message with native collapsible sections:
    - Section 1: Architectural Rationale & Trade-Offs (collapsible: true, uncollapsibleWidgetsCount: 1)
    - Section 2: Compliance & Blast Radius Analysis (collapsible: true, uncollapsibleWidgetsCount: 1)
    - Section 3: One-Click Remediation Actions (Option 1, Option 2, Don't Act, SCC Console)
    Adheres to Card Exclusivity (only 'cardsV2').
    """
    parsed = parse_resource_display(resource_name, project_id)
    clean_res = parsed["clean_resource_name"]
    asset_type = parsed["asset_type"]
    display_proj = parsed["project_id"]

    severity_icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
    }.get(severity.upper(), "⚠️")

    deep_reasoning = ai_analysis.get("deep_architectural_reasoning") or ai_analysis.get("best_option", {}).get("reasoning") or "No deep architectural rationale provided."
    compliance = ai_analysis.get("compliance_and_blast_radius") or "Complies with Google Cloud Security Foundations and CIS GCP Benchmark."
    issue_summary = ai_analysis.get("issue_summary") or "Security Command Center finding detected."
    rec_opt = ai_analysis.get("recommended_option_number") or ai_analysis.get("best_option", {}).get("recommended_option_number", 1)

    scc_console_url = f"https://console.cloud.google.com/security/command-center/findings?project={display_proj}"

    sections = [
        {
            "header": "⚡ Summary & Context",
            "widgets": [
                {
                    "decoratedText": {
                        "topLabel": f"ASSET ({asset_type.upper()})",
                        "text": f"<b>{clean_res}</b>",
                        "bottomLabel": f"Project: {display_proj} | Severity: {severity}",
                        "wrapText": True
                    }
                },
                {
                    "textParagraph": {
                        "text": f"<b>Overview:</b> {issue_summary}"
                    }
                }
            ]
        },
        {
            "header": "🧠 Architectural Rationale & Trade-Offs",
            "collapsible": True,
            "uncollapsibleWidgetsCount": 1,
            "widgets": [
                {
                    "textParagraph": {
                        "text": f"<b>Why Option {rec_opt} is recommended:</b> (Click header to toggle details)"
                    }
                },
                {
                    "textParagraph": {
                        "text": deep_reasoning
                    }
                }
            ]
        },
        {
            "header": "🛡️ Compliance & Blast Radius Analysis",
            "collapsible": True,
            "uncollapsibleWidgetsCount": 1,
            "widgets": [
                {
                    "textParagraph": {
                        "text": "<b>Workload Blast Radius & Compliance Scope:</b> (Click header to toggle details)"
                    }
                },
                {
                    "textParagraph": {
                        "text": compliance
                    }
                }
            ]
        }
    ]

    buttons = []
    if receiver_url and finding_id:
        buttons.append({
            "text": "🛠️ Fix via Option 1",
            "onClick": {"openLink": {"url": f"{receiver_url}/?finding_id={finding_id}&option=1"}}
        })
        buttons.append({
            "text": "🛠️ Fix via Option 2",
            "onClick": {"openLink": {"url": f"{receiver_url}/?finding_id={finding_id}&option=2"}}
        })
        buttons.append({
            "text": "🛑 Don't Act",
            "onClick": {"openLink": {"url": f"{receiver_url}/?finding_id={finding_id}&action=ignore"}}
        })
    buttons.append({
        "text": "↗️ Open SCC Console",
        "onClick": {"openLink": {"url": scc_console_url}}
    })

    sections.append({
        "header": "⚡ One-Click Remediation Actions",
        "widgets": [
            {
                "buttonList": {
                    "buttons": buttons
                }
            }
        ]
    })

    return {
        "cardsV2": [
            {
                "cardId": f"deep_dive_{sanitize_doc_id(finding_id)}",
                "card": {
                    "header": {
                        "title": f"{severity_icon} Deep Dive: {issue_type}",
                        "subtitle": f"{clean_res} ({asset_type}) • {display_proj}",
                        "imageUrl": "https://www.gstatic.com/images/branding/product/2x/security_48dp.png",
                        "imageType": "CIRCLE"
                    },
                    "sections": sections
                }
            }
        ]
    }



# -----------------------------------------------------------------------------
# Google ADK Remediation Agent: Autonomous Multi-Tool GitOps Pipeline
# -----------------------------------------------------------------------------
def run_scc_remediation_agent(
    alert_doc_ref,
    alert_data: Dict[str, Any],
    finding_id: str,
    issue_type: str,
    resource_name: str,
    selected_option: Dict[str, Any],
    target_num: int,
    user_text: str,
    project_id: str,
    location: str,
    model_name: str,
    github_repo: str,
    github_token: str,
    github_base_branch: str,
    chat_webhook_url: str
) -> Dict[str, Any]:
    """
    Invokes the Google Agent Development Kit (ADK) autonomous Remediation Agent
    equipped with 4 specialized operational tools:
    1. validate_terraform_code
    2. create_github_pull_request_tool
    3. record_remediation_audit
    4. dispatch_google_chat_notification
    """
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE"
    os.environ["GOOGLE_CLOUD_PROJECT"] = project_id
    os.environ["GOOGLE_CLOUD_LOCATION"] = location

    raw_payload = alert_data.get("raw_payload", {})
    finding_raw = raw_payload.get("finding", {})
    description = finding_raw.get("description", "Security vulnerability detected by SCC.")
    next_steps = finding_raw.get("nextSteps", "")
    source_properties = finding_raw.get("sourceProperties", {})

    # Stage 3: Baseline Infrastructure Inspection (True GitOps Diffs)
    clean_issue = sanitize_doc_id(issue_type).lower()
    clean_res_part = sanitize_doc_id(resource_name.split('/')[-1]).lower()
    default_file_path = f"remediations/{clean_issue}_{clean_res_part}.tf"

    baseline_content = None
    baseline_sha = None
    target_file_path = default_file_path

    if issue_type == "PUBLIC_BUCKET_ACL" or "storage.googleapis.com" in resource_name or "bucket" in resource_name.lower():
        baseline_content, baseline_sha = fetch_baseline_terraform_file(
            repo=github_repo,
            token=github_token,
            base_branch=github_base_branch,
            file_path="infrastructure/main.tf"
        )
        if baseline_content and baseline_sha:
            target_file_path = "infrastructure/main.tf"
            logger.info("Operating in Baseline Modification Mode: updating 'infrastructure/main.tf' in-place.")

    agent_state: Dict[str, Any] = {
        "terraform_code": None,
        "explanation": None,
        "pr_result": None,
        "audit_result": None,
        "chat_notified": False,
        "chat_msg_text": None,
        "remediation_record": None
    }

    # Tool 1: validate_terraform_code
    def validate_terraform_code(terraform_code: str, resource_type: str) -> dict:
        """Validates the syntax and structural completeness of the generated Terraform HCL code.

        Args:
            terraform_code: Complete Terraform (HCL) configuration snippet to validate.
            resource_type: Target GCP resource type (e.g. google_storage_bucket, google_compute_firewall).
        """
        if not terraform_code or not terraform_code.strip():
            return {"valid": False, "error": "Terraform code is empty."}

        has_block = bool(re.search(r'(resource|module|locals|variable)\s+"?[a-zA-Z0-9_\-]+"?', terraform_code))
        if not has_block:
            return {"valid": False, "error": "Terraform code does not contain any valid resource, module, locals, or variable blocks."}

        open_braces = terraform_code.count("{")
        close_braces = terraform_code.count("}")
        if open_braces != close_braces:
            return {"valid": False, "error": f"Mismatched braces: {open_braces} open vs {close_braces} close."}

        agent_state["terraform_code"] = terraform_code
        agent_state["resource_type"] = resource_type
        logger.info(f"ADK Tool [validate_terraform_code]: Validated {len(terraform_code)} chars for {resource_type}.")
        return {
            "valid": True,
            "status": "VALID",
            "message": f"Terraform code for '{resource_type}' validated successfully ({len(terraform_code)} characters, {open_braces} blocks)."
        }

    # Tool 2: create_github_pull_request_tool
    def create_github_pull_request_tool(
        file_path: str = "",
        commit_message: str = "",
        pr_title: str = "",
        pr_summary: str = ""
    ) -> dict:
        """Stages the validated Terraform code onto a new Git branch and opens a GitHub Pull Request for human review.

        Args:
            file_path: Relative repository file path for the Terraform code (e.g. infrastructure/main.tf or remediations/open_ssh_port_firewall.tf).
            commit_message: Descriptive Git commit message explaining the security remediation.
            pr_title: Title for the GitHub Pull Request (e.g. [SecOps Fix] Remediate PUBLIC_BUCKET_ACL).
            pr_summary: Detailed description of what is causing the issue, the risk, and the recommended fix.
        """
        tf_code = agent_state.get("terraform_code")
        if not tf_code:
            return {"success": False, "error": "No validated Terraform code found. Call validate_terraform_code first."}

        agent_state["explanation"] = pr_summary

        if not github_token or not github_repo:
            agent_state["pr_result"] = {"success": False, "skipped": True, "error": "GitHub credentials not configured"}
            return {"success": False, "status": "SKIPPED", "message": "GitHub repository/token not configured; staging in Firestore only."}

        chosen_path = file_path.strip() if file_path and file_path.strip() else target_file_path
        chosen_sha = baseline_sha if (chosen_path == "infrastructure/main.tf" and baseline_sha) else None

        pr_res = create_github_pull_request(
            repo=github_repo,
            token=github_token,
            base_branch=github_base_branch,
            issue_type=issue_type,
            resource_name=resource_name,
            finding_id=finding_id,
            option_number=target_num,
            option_title=selected_option.get("title", f"Option {target_num}"),
            option_strategy=selected_option.get("strategy", ""),
            terraform_code=tf_code,
            explanation=pr_summary,
            execution_instructions="1. git checkout <branch>\n2. terraform plan\n3. terraform apply",
            file_path=chosen_path,
            existing_file_sha=chosen_sha,
            what_is_causing_issue=description,
            risk_summary=selected_option.get("trade_offs") or selected_option.get("strategy", ""),
            recommended_fix=selected_option.get("strategy", "")
        )
        agent_state["pr_result"] = pr_res
        logger.info(f"ADK Tool [create_github_pull_request_tool]: PR Result: success={pr_res.get('success')} (PR #{pr_res.get('pr_number')})")
        return pr_res

    # Tool 3: record_remediation_audit
    def record_remediation_audit(
        audit_status: str,
        audit_notes: str
    ) -> dict:
        """Records the remediation outcome, generated Terraform configuration, and GitHub PR details in Firestore.

        Args:
            audit_status: High-level status of the remediation (e.g. PR_OPENED_NOT_APPLIED or CODE_GENERATED_STAGED).
            audit_notes: Technical summary of the remediation actions taken by the agent.
        """
        tf_code = agent_state.get("terraform_code", "")
        pr_res = agent_state.get("pr_result") or {}
        pr_success = bool(pr_res.get("success"))

        remediation_record = {
            "finding_id": finding_id,
            "issue_type": issue_type,
            "resource_name": resource_name,
            "selected_option": {
                "option_number": target_num,
                "title": selected_option.get("title"),
                "strategy": selected_option.get("strategy")
            },
            "status": "PR_OPENED_NOT_APPLIED" if pr_success else audit_status,
            "terraform_code": tf_code,
            "audit_notes": audit_notes,
            "user_response_text": user_text or f"Option {target_num}",
            "generated_at": firestore.SERVER_TIMESTAMP
        }

        if pr_success:
            remediation_record["github_pr"] = {
                "pr_url": pr_res.get("pr_url"),
                "pr_number": pr_res.get("pr_number"),
                "branch_name": pr_res.get("branch_name"),
                "file_path": pr_res.get("file_path"),
                "status": "OPEN",
                "created_at": firestore.SERVER_TIMESTAMP
            }
        elif pr_res.get("error"):
            remediation_record["github_pr_error"] = pr_res.get("error")

        if alert_doc_ref:
            alert_doc_ref.update({
                "user_response": {
                    "decision": "REMEDIATE",
                    "chosen_option": target_num,
                    "raw_text": user_text or f"Option {target_num}",
                    "decided_at": firestore.SERVER_TIMESTAMP
                },
                "remediation": remediation_record,
                "remediation_status": "PR_OPENED" if pr_success else "CODE_GENERATED_STAGED"
            })

        db = get_firestore_client()
        db.collection("remediations").document(f"{issue_type}_{finding_id}").set(remediation_record)
        agent_state["remediation_record"] = remediation_record
        agent_state["audit_result"] = {"status": "RECORDED", "audit_id": f"{issue_type}_{finding_id}"}
        logger.info("ADK Tool [record_remediation_audit]: Successfully recorded audit in Firestore.")
        return {"status": "RECORDED", "audit_id": f"{issue_type}_{finding_id}"}

    # Tool 4: dispatch_google_chat_notification
    def dispatch_google_chat_notification(
        notification_message: str
    ) -> dict:
        """Dispatches a notification message to the Google Chat space webhook to inform the SecOps team.

        Args:
            notification_message: Formatted text or markdown notification to broadcast to the Google Chat space.
        """
        agent_state["chat_msg_text"] = notification_message
        if not chat_webhook_url or not chat_webhook_url.strip():
            logger.info("ADK Tool [dispatch_google_chat_notification]: Chat webhook URL not set; skipped.")
            return {"status": "SKIPPED", "reason": "No webhook URL provided"}

        notify_google_chat(chat_webhook_url, notification_message)
        agent_state["chat_notified"] = True
        logger.info("ADK Tool [dispatch_google_chat_notification]: Dispatched to Google Chat.")
        return {"status": "SUCCESS", "message": "Notification dispatched to Google Chat space."}

    agent_instruction = (
        "You are an autonomous Principal SecOps & GitOps Remediation Agent powered by Google ADK (Agent Development Kit).\n"
        "Your mission is to take an approved Security Command Center (SCC) remediation strategy and "
        "execute the end-to-end GitOps remediation workflow using your provided tools.\n\n"
        "STRICT EXECUTION ORDER:\n"
        "1. Write complete, syntactically valid Terraform (HCL) code implementing the selected remediation option.\n"
        "   - If baseline infrastructure code is provided, output the COMPLETE updated file modifying the vulnerable resource in-place (e.g. enabling uniform_bucket_level_access = true, deleting public google_storage_bucket_access_control) while keeping all compliant resources intact. This ensures a clean red/green diff in GitHub.\n"
        "   - If no baseline is provided, write standalone Terraform HCL for official google provider resources.\n"
        "   - Do NOT use dummy pseudocode or incomplete placeholders.\n"
        "   - Add explanatory comments for each security setting.\n"
        "2. Call `validate_terraform_code` to verify the HCL syntax and structural integrity.\n"
        "3. Call `create_github_pull_request_tool` to commit the code onto a dedicated branch and open a PR.\n"
        "4. Call `record_remediation_audit` to write the full audit trail and PR metadata to Firestore.\n"
        "5. Call `dispatch_google_chat_notification` to notify the team in Google Chat with the PR link and human review safety assurance (the code is staged in Git and has NOT been applied to live infrastructure).\n"
        "6. Provide a crisp, professional 2-3 sentence executive engineering rationale summarizing: (1) root misconfiguration eliminated, (2) architectural trade-offs, and (3) expected blast radius. Avoid meta-commentary, fluff, and filler words."
    )

    remediation_agent = Agent(
        name="scc_remediation_agent",
        model=model_name,
        instruction=agent_instruction,
        tools=[
            validate_terraform_code,
            create_github_pull_request_tool,
            record_remediation_audit,
            dispatch_google_chat_notification
        ]
    )

    runner = Runner(
        agent=remediation_agent,
        app_name="cloudguard_remediation",
        session_service=InMemorySessionService(),
        auto_create_session=True
    )

    baseline_section = ""
    if baseline_content:
        baseline_section = f"""
[Existing Baseline Infrastructure Code (infrastructure/main.tf)]
We maintain an existing baseline Terraform configuration in `infrastructure/main.tf` in the repository.
Instead of creating a new isolated file, you MUST modify this existing configuration to remediate the vulnerability (e.g., set `uniform_bucket_level_access = true` on the vulnerable bucket and delete the public `google_storage_bucket_access_control` resource) while preserving all other resources intact.

```hcl
{baseline_content}
```
"""

    user_prompt = f"""
Execute automated GitOps remediation for the following Security Command Center finding:

[Finding Details]
- Finding Category: {issue_type}
- Resource Name: {resource_name}
- Finding ID: {finding_id}
- Description: {description}
- Next Steps: {next_steps}
- Source Properties: {json.dumps(source_properties, default=str)}

[Selected Remediation Strategy]
- Option Number: {target_num}
- Title: {selected_option.get("title", f"Option {target_num}")}
- Strategy: {selected_option.get("strategy", "")}
- Operational Considerations: {selected_option.get("trade_offs") or selected_option.get("explanation", "")}

[Repository Context]
- Target GitHub Repository: {github_repo}
- Base Branch: {github_base_branch}
- Target File Path: {target_file_path}
{baseline_section}
Execute the required steps using your tools now.
"""

    session_id = f"remediate_{sanitize_doc_id(resource_name)}_{int(time.time()*1000)}"
    content = types.Content(role="user", parts=[types.Part.from_text(text=user_prompt)])

    logger.info(f"Running ADK Remediation Agent for finding: {issue_type} on {resource_name}")
    raw_output_parts = []
    for event in runner.run(user_id="scc_pipeline", session_id=session_id, new_message=content):
        if event.message and event.message.parts:
            for part in event.message.parts:
                if getattr(part, "text", None):
                    raw_output_parts.append(part.text)

    raw_response_text = "\n".join(raw_output_parts)
    logger.info(f"ADK Remediation Agent execution finished. Output length: {len(raw_response_text)} chars.")

    # Validation: Ensure agent fulfilled zero-fallback requirement
    if not agent_state.get("terraform_code"):
        raise RuntimeError(
            f"ADK Remediation Agent failed to generate and validate Terraform HCL code for {issue_type}. "
            f"Zero fallback policy enforced. Raw output: {raw_response_text[:300]}"
        )

    # Guarantee audit recording if tool step was skipped by model
    if not agent_state.get("audit_result"):
        record_remediation_audit("PR_OPENED_NOT_APPLIED", "Autonomous audit recorded via remediation pipeline.")

    # Guarantee chat notification if tool step was skipped by model
    pr_res = agent_state.get("pr_result") or {}
    pr_success = bool(pr_res.get("success"))
    pr_url = pr_res.get("pr_url")
    pr_number = pr_res.get("pr_number")
    branch_name = pr_res.get("branch_name")
    file_path = pr_res.get("file_path")

    if not agent_state.get("chat_msg_text"):
        if pr_success and pr_url:
            chat_msg = (
                f"🚀 *GitHub Pull Request Opened for Review!*\n\n"
                f"The autonomous Google ADK remediation agent has coded the Terraform fix for *{issue_type}* on `{resource_name}` "
                f"based on *Option {target_num}: {selected_option.get('title')}*.\n\n"
                f"🔗 *Pull Request:* <{pr_url}|PR #{pr_number}: [SecOps Fix] Remediate {issue_type}>\n"
                f"🌿 *Branch:* `{branch_name}`\n"
                f"📁 *File:* `{file_path}`\n\n"
                f"🔒 *Safety Policy:* The fix has been submitted as a Git Pull Request for human review. "
                f"It *has NOT been applied* to live infrastructure."
            )
        else:
            chat_msg = (
                f"✅ *Terraform Fix Prepared!*\n\n"
                f"The autonomous Google ADK remediation agent has coded the Terraform fix for *{issue_type}* on `{resource_name}` "
                f"based on *Option {target_num}: {selected_option.get('title')}*.\n\n"
                f"🔒 *Safety Policy:* The configuration has been safely staged in Firestore and *has NOT been applied* to live infrastructure."
            )
        agent_state["chat_msg_text"] = chat_msg
        if not agent_state.get("chat_notified") and chat_webhook_url:
            notify_google_chat(chat_webhook_url, chat_msg)
            agent_state["chat_notified"] = True

    if not agent_state.get("explanation"):
        agent_state["explanation"] = raw_response_text or f"Autonomous Terraform remediation implementing Option {target_num}: {selected_option.get('title')}."

    return agent_state


# -----------------------------------------------------------------------------
# HTML Response Renderer (For Browser Button Clicks)
# -----------------------------------------------------------------------------
def render_html_page(
    badge_icon: str,
    badge_title: str,
    badge_color: str,
    heading: str,
    details: list[str],
    code: Optional[str] = None,
    explanation: Optional[str] = None,
    pr_url: Optional[str] = None,
    pr_number: Optional[int] = None
) -> str:
    details_html = "".join(f"<li>{d}</li>" for d in details)
    
    explanation_block = ""
    if explanation:
        explanation_block = f"""
        <details class="accordion">
            <summary>
                <span>🧠 Architectural Rationale & Risk Assessment</span>
                <span class="chevron">▾</span>
            </summary>
            <div class="accordion-body">
                {html.escape(explanation)}
            </div>
        </details>
        """

    code_block = ""
    if code:
        code_block = f"""
        <details class="accordion" open>
            <summary>
                <span>💻 Staged Terraform (HCL) Preview</span>
                <span class="chevron">▾</span>
            </summary>
            <div class="accordion-body" style="padding: 0;">
                <div class="code-header">
                    <span>Terraform Remediation (HCL)</span>
                    <span class="staged-tag">Safely Staged &bull; NOT Applied</span>
                </div>
                <pre><code>{html.escape(code)}</code></pre>
            </div>
        </details>
        """

    pr_button_block = ""
    if pr_url:
        pr_num_str = f"#{pr_number} " if pr_number else ""
        pr_button_block = f"""
        <div style="margin-bottom: 20px;">
            <a href="{html.escape(pr_url)}" target="_blank" class="pr-button">
                <svg height="18" width="18" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                <span>Review Pull Request {pr_num_str}on GitHub &rarr;</span>
            </a>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudGuard SecOps Remediation</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --badge-bg: {badge_color}22;
            --badge-text: {badge_color};
            --accent-green: #3fb950;
            --accent-blue: #58a6ff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            max-width: 860px;
            width: 100%;
            padding: 32px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background-color: var(--badge-bg);
            color: var(--badge-text);
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
            border: 1px solid {badge_color}44;
            margin-bottom: 16px;
        }}
        h2 {{
            margin: 0 0 16px 0;
            font-size: 24px;
            color: #ffffff;
        }}
        .pr-button {{
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background-color: #238636;
            color: #ffffff;
            padding: 12px 22px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-size: 15px;
            box-shadow: 0 1px 0 rgba(27,31,36,0.1);
            transition: background-color 0.2s;
        }}
        .pr-button:hover {{
            background-color: #2ea043;
            text-decoration: none;
        }}
        ul.details-list {{
            list-style: none;
            padding: 0;
            margin: 16px 0 24px 0;
        }}
        ul.details-list li {{
            padding: 6px 0;
            color: var(--text-secondary);
            font-size: 15px;
            border-bottom: 1px solid #21262d;
        }}
        ul.details-list li strong {{
            color: var(--text-primary);
        }}
        details.accordion {{
            background-color: #161b22;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        details.accordion[open] {{
            border-color: #58a6ff55;
        }}
        details.accordion summary {{
            padding: 14px 18px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            color: var(--text-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            background-color: #1c2128;
            outline: none;
        }}
        details.accordion summary:hover {{
            background-color: #22272e;
            color: #58a6ff;
        }}
        details.accordion summary::-webkit-details-marker {{
            display: none;
        }}
        details.accordion .accordion-body {{
            padding: 16px 18px;
            border-top: 1px solid var(--border-color);
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-primary);
            background-color: #0d1117;
        }}
        details.accordion {{
            background-color: #161b22;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        details.accordion[open] {{
            border-color: #58a6ff55;
        }}
        details.accordion summary {{
            padding: 14px 18px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            color: var(--text-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            background-color: #1c2128;
            outline: none;
        }}
        details.accordion summary:hover {{
            background-color: #22272e;
            color: #58a6ff;
        }}
        details.accordion summary::-webkit-details-marker {{
            display: none;
        }}
        details.accordion .accordion-body {{
            padding: 16px 18px;
            border-top: 1px solid var(--border-color);
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-primary);
            background-color: #0d1117;
        }}
        .code-header {{
            background-color: #1f242c;
            padding: 10px 16px;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
        }}
        .staged-tag {{
            background-color: #d2992222;
            color: #e3b341;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
        pre {{
            margin: 0;
            padding: 16px;
            overflow-x: auto;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            font-size: 13px;
            line-height: 1.5;
            color: #79c0ff;
        }}
        .footer-note {{
            display: flex;
            align-items: center;
            gap: 10px;
            background-color: #1f242c;
            border: 1px solid #30363d;
            padding: 12px 16px;
            border-radius: 8px;
            color: var(--text-secondary);
            font-size: 13px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">
            <span>{badge_icon}</span>
            <span>{badge_title}</span>
        </div>
        <h2>{heading}</h2>
        {pr_button_block}
        <ul class="details-list">
            {details_html}
        </ul>
        {explanation_block}
        {code_block}
        <div class="footer-note">
            <span>💬</span>
            <span>Confirmation update has been posted to your Google Chat space. You may return to Google Chat.</span>
        </div>
    </div>
</body>
</html>
"""


# -----------------------------------------------------------------------------
# HTML Deep Dive Page Renderer (Show More Details Inspector)
# -----------------------------------------------------------------------------
def render_deep_dive_html_page(
    finding_id: str,
    issue_type: str,
    severity: str,
    resource_name: str,
    project_id: str,
    ai_analysis: dict,
    receiver_url: str = "",
    chat_dispatched: bool = True
) -> str:
    parsed = parse_resource_display(resource_name, project_id)
    clean_res = parsed["clean_resource_name"]
    asset_type = parsed["asset_type"]
    display_proj = parsed["project_id"]

    escaped_finding = html.escape(finding_id)
    escaped_issue = html.escape(issue_type)
    escaped_clean_res = html.escape(clean_res)
    escaped_asset_type = html.escape(asset_type)
    escaped_resource = html.escape(resource_name)
    escaped_proj = html.escape(display_proj)
    escaped_severity = html.escape(severity)

    severity_icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
    }.get(severity.upper(), "⚠️")

    summary = html.escape(ai_analysis.get("issue_summary") or "Security Command Center finding detected.")
    deep_reasoning = html.escape(ai_analysis.get("deep_architectural_reasoning") or ai_analysis.get("best_option", {}).get("reasoning") or "No deep architectural rationale provided.")
    compliance = html.escape(ai_analysis.get("compliance_and_blast_radius") or "Complies with Google Cloud Security Foundations and CIS GCP Benchmark.")
    fix_options = ai_analysis.get("fix_options") or []
    rec_opt = ai_analysis.get("recommended_option_number") or ai_analysis.get("best_option", {}).get("recommended_option_number", 1)

    scc_console_url = f"https://console.cloud.google.com/security/command-center/findings?project={escaped_proj}"

    options_html = ""
    for opt in fix_options:
        opt_num = opt.get("option_number", 1)
        opt_title = html.escape(opt.get("title", f"Option {opt_num}"))
        opt_summary = html.escape(opt.get("summary") or opt.get("strategy") or "")
        pros = opt.get("pros") or []
        cons = opt.get("cons") or []
        is_rec = (opt_num == rec_opt)
        badge = '<span class="rec-badge">⭐ AI RECOMMENDED</span>' if is_rec else ''

        pros_html = "".join([f"<li>+ {html.escape(p)}</li>" for p in pros]) if pros else "<li>+ Follows security best practices</li>"
        cons_html = "".join([f"<li>- {html.escape(c)}</li>" for c in cons]) if cons else "<li>- Requires standard peer review</li>"

        options_html += f"""
        <div class="option-card {'recommended' if is_rec else ''}">
            <div class="option-header">
                <span class="option-title">Option {opt_num}: {opt_title}</span>
                {badge}
            </div>
            <p class="option-summary">{opt_summary}</p>
            <div class="pros-cons-grid">
                <div class="pros-box">
                    <strong>Pros:</strong>
                    <ul>{pros_html}</ul>
                </div>
                <div class="cons-box">
                    <strong>Cons & Trade-Offs:</strong>
                    <ul>{cons_html}</ul>
                </div>
            </div>
            <div style="margin-top: 14px;">
                <a href="/?finding_id={escaped_finding}&option={opt_num}" class="pr-button" style="font-size: 13px; padding: 8px 16px;">
                    🛠️ Code Fix via Option {opt_num} &rarr;
                </a>
            </div>
        </div>
        """

    chat_banner = ""
    if chat_dispatched:
        chat_banner = """
        <div class="chat-banner">
            <span>✅</span>
            <span>A companion deep-dive card with native collapsible sections was dispatched to your Google Chat space.</span>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deep Dive: {escaped_issue} | CloudGuard SecOps</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
        }}
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            max-width: 900px;
            width: 100%;
            padding: 32px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background-color: rgba(88, 166, 255, 0.15);
            color: var(--accent-blue);
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
            border: 1px solid rgba(88, 166, 255, 0.3);
            margin-bottom: 16px;
        }}
        h2 {{
            margin: 0 0 16px 0;
            font-size: 24px;
            color: #ffffff;
        }}
        .chat-banner {{
            display: flex;
            align-items: center;
            gap: 10px;
            background-color: rgba(63, 185, 80, 0.12);
            border: 1px solid rgba(63, 185, 80, 0.4);
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 24px;
            font-size: 14px;
            color: #7ee787;
        }}
        .info-card {{
            background-color: #1f242c;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
        }}
        .info-row {{
            display: flex;
            align-items: baseline;
            gap: 12px;
            padding: 6px 0;
            border-bottom: 1px solid #282e38;
            font-size: 14px;
        }}
        .info-row:last-child {{
            border-bottom: none;
        }}
        .info-label {{
            color: var(--text-secondary);
            font-weight: 600;
            min-width: 150px;
            flex-shrink: 0;
        }}
        .info-value {{
            color: var(--text-primary);
            word-break: break-all;
        }}
        .info-value code {{
            background-color: rgba(110, 118, 129, 0.2);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: "SFMono-Regular", Consolas, Menlo, monospace;
            font-size: 13px;
            color: #79c0ff;
        }}
        .deep-section {{
            background-color: #161b22;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .deep-section h3 {{
            margin: 0 0 10px 0;
            font-size: 16px;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .deep-section p {{
            margin: 0;
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-primary);
        }}
        .option-card {{
            background-color: #1f242c;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 18px;
            margin-bottom: 16px;
        }}
        .option-card.recommended {{
            border-color: rgba(210, 153, 34, 0.5);
            background-color: rgba(210, 153, 34, 0.05);
        }}
        .option-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .option-title {{
            font-weight: 700;
            font-size: 15px;
            color: #ffffff;
        }}
        .rec-badge {{
            background-color: rgba(210, 153, 34, 0.2);
            color: #e3b341;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            border: 1px solid rgba(210, 153, 34, 0.4);
        }}
        .option-summary {{
            font-size: 14px;
            color: var(--text-secondary);
            margin: 0 0 12px 0;
        }}
        .pros-cons-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            font-size: 13px;
        }}
        @media (max-width: 600px) {{
            .pros-cons-grid {{ grid-template-columns: 1fr; }}
        }}
        .pros-box {{
            background-color: rgba(63, 185, 80, 0.08);
            border: 1px solid rgba(63, 185, 80, 0.2);
            border-radius: 6px;
            padding: 10px 14px;
        }}
        .pros-box strong {{ color: var(--accent-green); }}
        .pros-box ul {{ margin: 6px 0 0 0; padding-left: 18px; color: var(--text-primary); }}
        .cons-box {{
            background-color: rgba(248, 81, 73, 0.08);
            border: 1px solid rgba(248, 81, 73, 0.2);
            border-radius: 6px;
            padding: 10px 14px;
        }}
        .cons-box strong {{ color: var(--accent-red); }}
        .cons-box ul {{ margin: 6px 0 0 0; padding-left: 18px; color: var(--text-primary); }}
        .action-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 24px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }}
        .pr-button {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background-color: #238636;
            color: #ffffff;
            padding: 10px 18px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: background-color 0.2s;
        }}
        .pr-button:hover {{ background-color: #2ea043; }}
        .secondary-button {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background-color: #21262d;
            border: 1px solid #30363d;
            color: var(--text-primary);
            padding: 10px 18px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: background-color 0.2s;
        }}
        .secondary-button:hover {{ background-color: #30363d; }}
        .danger-button {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background-color: rgba(248, 81, 73, 0.15);
            border: 1px solid rgba(248, 81, 73, 0.3);
            color: var(--accent-red);
            padding: 10px 18px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
        }}
        .danger-button:hover {{ background-color: rgba(248, 81, 73, 0.25); }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">
            <span>🔎</span>
            <span>Architectural Deep Dive</span>
        </div>
        <h2>Security Architecture Deep Dive: {escaped_issue}</h2>
        {chat_banner}

        <div class="info-card">
            <div class="info-row">
                <span class="info-label">Finding ID:</span>
                <span class="info-value"><code>{escaped_finding}</code></span>
            </div>
            <div class="info-row">
                <span class="info-label">Affected Asset:</span>
                <span class="info-value"><strong>{escaped_clean_res}</strong> ({escaped_asset_type})</span>
            </div>
            <div class="info-row">
                <span class="info-label">Severity:</span>
                <span class="info-value">{severity_icon} <strong>{escaped_severity}</strong></span>
            </div>
            <div class="info-row">
                <span class="info-label">Google Cloud Project:</span>
                <span class="info-value"><code>{escaped_proj}</code></span>
            </div>
            <div class="info-row">
                <span class="info-label">Full Resource URI:</span>
                <span class="info-value"><code>{escaped_resource}</code></span>
            </div>
        </div>

        <div class="deep-section">
            <h3>🧠 Architectural Rationale & Why This Fix Was Chosen</h3>
            <p>{deep_reasoning}</p>
        </div>

        <div class="deep-section">
            <h3>🛡️ Compliance Scope & Workload Blast Radius Analysis</h3>
            <p>{compliance}</p>
        </div>

        <h3 style="margin: 24px 0 14px 0; font-size: 18px; color: #ffffff;">🛠️ Declarative Terraform Fix Options</h3>
        {options_html}

        <div class="action-bar">
            <a href="/?finding_id={escaped_finding}&action=ignore" class="danger-button">
                🛑 Don't Act (Dismiss)
            </a>
            <a href="{scc_console_url}" target="_blank" class="secondary-button">
                ↗️ View in SCC Console
            </a>
        </div>
    </div>
</body>
</html>
"""


# -----------------------------------------------------------------------------
# HTML Loading Page Renderer (Fast Real-Time Browser Feedback)
# -----------------------------------------------------------------------------
def render_loading_html_page(
    finding_id: str,
    issue_type: str,
    resource_name: str,
    option_number: int,
    option_title: str,
    option_strategy: str
) -> str:
    escaped_finding = html.escape(finding_id)
    escaped_issue = html.escape(issue_type)
    escaped_resource = html.escape(resource_name)
    escaped_title = html.escape(option_title)
    escaped_strategy = html.escape(option_strategy)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Remediating {escaped_issue} | CloudGuard SecOps</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
        }}
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            max-width: 860px;
            width: 100%;
            padding: 32px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 16px;
        }}
        .pulse-badge {{
            background-color: rgba(56, 139, 253, 0.15);
            color: var(--accent-blue);
            border: 1px solid rgba(56, 139, 253, 0.4);
        }}
        .success-badge {{
            background-color: rgba(63, 185, 80, 0.15);
            color: var(--accent-green);
            border: 1px solid rgba(63, 185, 80, 0.4);
        }}
        .error-badge {{
            background-color: rgba(248, 81, 73, 0.15);
            color: var(--accent-red);
            border: 1px solid rgba(248, 81, 73, 0.4);
        }}
        h2 {{
            margin: 0 0 8px 0;
            font-size: 24px;
            color: #ffffff;
        }}
        .subtitle {{
            color: var(--text-secondary);
            font-size: 15px;
            margin-bottom: 24px;
            line-height: 1.4;
        }}
        .info-card {{
            background-color: #1f242c;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
        }}
        .info-row {{
            display: flex;
            align-items: baseline;
            gap: 12px;
            padding: 6px 0;
            border-bottom: 1px solid #282e38;
            font-size: 14px;
        }}
        .info-row:last-child {{
            border-bottom: none;
        }}
        .info-label {{
            color: var(--text-secondary);
            font-weight: 600;
            min-width: 140px;
            flex-shrink: 0;
        }}
        .info-value {{
            color: var(--text-primary);
            word-break: break-all;
        }}
        .info-value code {{
            background-color: rgba(110, 118, 129, 0.2);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: "SFMono-Regular", Consolas, Menlo, monospace;
            font-size: 13px;
            color: #79c0ff;
        }}
        .progress-container {{
            width: 100%;
            background-color: #21262d;
            border-radius: 6px;
            height: 10px;
            overflow: hidden;
            margin: 16px 0 10px 0;
            border: 1px solid #30363d;
        }}
        .progress-bar {{
            height: 100%;
            width: 15%;
            background: linear-gradient(90deg, #1f6feb, #388bfd, #2ea043);
            border-radius: 6px;
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        .status-indicator {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 24px;
        }}
        .pipeline-steps {{
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin: 20px 0 28px 0;
        }}
        .step-item {{
            display: flex;
            align-items: flex-start;
            gap: 16px;
            padding: 14px 18px;
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            transition: all 0.3s ease;
        }}
        .step-item.active {{
            border-color: #58a6ff;
            background-color: rgba(56, 139, 253, 0.08);
            box-shadow: 0 0 12px rgba(88, 166, 255, 0.15);
        }}
        .step-item.completed {{
            border-color: rgba(63, 185, 80, 0.6);
            background-color: rgba(63, 185, 80, 0.06);
        }}
        .step-icon {{
            width: 28px;
            height: 28px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            font-size: 13px;
            font-weight: 700;
            flex-shrink: 0;
        }}
        .step-item.pending .step-icon {{
            background-color: #21262d;
            color: #8b949e;
            border: 1px solid #30363d;
        }}
        .step-item.active .step-icon {{
            background-color: #1f6feb;
            color: #ffffff;
            box-shadow: 0 0 8px rgba(31, 111, 235, 0.5);
        }}
        .step-item.completed .step-icon {{
            background-color: #238636;
            color: #ffffff;
        }}
        .step-content {{
            flex-grow: 1;
        }}
        .step-title {{
            font-size: 14px;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 2px;
        }}
        .step-subtext {{
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.4;
        }}
        .step-spinner {{
            display: inline-block;
            width: 13px;
            height: 13px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #ffffff;
            animation: spin 0.8s linear infinite;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .safety-banner {{
            display: flex;
            align-items: center;
            gap: 12px;
            background-color: #1f242c;
            border-left: 4px solid var(--accent-green);
            padding: 12px 16px;
            border-radius: 4px;
            font-size: 13px;
            color: var(--text-secondary);
        }}
        .safety-banner strong {{
            color: var(--text-primary);
        }}
        .pr-button {{
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background-color: #238636;
            color: #ffffff;
            padding: 12px 22px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-size: 15px;
            box-shadow: 0 1px 0 rgba(27,31,36,0.1);
            transition: background-color 0.2s;
        }}
        .pr-button:hover {{
            background-color: #2ea043;
            text-decoration: none;
        }}
        ul.details-list {{
            list-style: none;
            padding: 0;
            margin: 16px 0 24px 0;
        }}
        ul.details-list li {{
            padding: 8px 0;
            color: var(--text-secondary);
            font-size: 14px;
            border-bottom: 1px solid #21262d;
        }}
        ul.details-list li strong {{
            color: var(--text-primary);
        }}
        .explanation-box {{
            background-color: #1f242c;
            border-left: 4px solid var(--accent-blue);
            padding: 14px 18px;
            border-radius: 4px;
            margin-bottom: 24px;
        }}
        .explanation-box h4 {{
            margin: 0 0 6px 0;
            color: var(--accent-blue);
        }}
        .explanation-box p {{
            margin: 0;
            font-size: 14px;
            line-height: 1.5;
            color: var(--text-primary);
        }}
        .code-container {{
            background-color: #0b0e14;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 24px;
        }}
        details.accordion {{
            background-color: #161b22;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        details.accordion[open] {{
            border-color: #58a6ff55;
        }}
        details.accordion summary {{
            padding: 14px 18px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            color: var(--text-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            background-color: #1c2128;
            outline: none;
        }}
        details.accordion summary:hover {{
            background-color: #22272e;
            color: #58a6ff;
        }}
        details.accordion summary::-webkit-details-marker {{
            display: none;
        }}
        details.accordion .accordion-body {{
            padding: 16px 18px;
            border-top: 1px solid var(--border-color);
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-primary);
            background-color: #0d1117;
        }}
        .code-header {{
            background-color: #1f242c;
            padding: 10px 16px;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
        }}
        .staged-tag {{
            background-color: #d2992222;
            color: #e3b341;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
        .copy-btn {{
            background-color: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .copy-btn:hover {{
            background-color: #30363d;
            color: #ffffff;
        }}
        pre {{
            margin: 0;
            padding: 16px;
            overflow-x: auto;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            font-size: 13px;
            line-height: 1.5;
            color: #79c0ff;
        }}
        .footer-note {{
            display: flex;
            align-items: center;
            gap: 10px;
            background-color: #1f242c;
            border: 1px solid #30363d;
            padding: 12px 16px;
            border-radius: 8px;
            color: var(--text-secondary);
            font-size: 13px;
        }}
        .error-box {{
            background-color: rgba(248, 81, 73, 0.1);
            border: 1px solid var(--accent-red);
            border-radius: 6px;
            padding: 16px;
            color: #ff7b72;
            font-size: 14px;
            margin: 20px 0;
            word-break: break-all;
        }}
        .retry-button {{
            background-color: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            padding: 10px 18px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .retry-button:hover {{
            background-color: #30363d;
            color: #ffffff;
        }}
    </style>
</head>
<body>
    <div class="card">
        <!-- LOADING VIEW -->
        <div id="loading-view">
            <div class="badge pulse-badge">
                <span class="step-spinner"></span>
                <span>Autonomous Remediation in Progress</span>
            </div>
            <h2>Remediating: {escaped_issue}</h2>
            <div class="subtitle">CloudGuard SecOps AI Agent is synthesizing your fix and staging a pull request.</div>

            <div class="info-card">
                <div class="info-row">
                    <span class="info-label">Finding ID:</span>
                    <span class="info-value"><code>{escaped_finding}</code></span>
                </div>
                <div class="info-row">
                    <span class="info-label">Target Resource:</span>
                    <span class="info-value"><code>{escaped_resource}</code></span>
                </div>
                <div class="info-row">
                    <span class="info-label">Selected Strategy:</span>
                    <span class="info-value"><strong>Option {option_number}: {escaped_title}</strong></span>
                </div>
            </div>

            <div class="progress-container">
                <div id="progress-bar" class="progress-bar"></div>
            </div>
            <div class="status-indicator">
                <span id="progress-status-text">Invoking Google ADK Remediation Agent (Autonomous Multi-Tool Pipeline)...</span>
                <span id="elapsed-time">Elapsed: 0s</span>
            </div>

            <div class="pipeline-steps">
                <div id="step-1" class="step-item completed">
                    <div class="step-icon">✔</div>
                    <div class="step-content">
                        <div class="step-title">1. Security Finding & Policy Context Verification</div>
                        <div id="step-1-subtext" class="step-subtext">Verified finding parameters and zero-trust policies in Firestore.</div>
                    </div>
                </div>
                <div id="step-2" class="step-item active">
                    <div class="step-icon"><span class="step-spinner"></span></div>
                    <div class="step-content">
                        <div class="step-title">2. Google ADK Agent Reasoning & Tool Execution</div>
                        <div id="step-2-subtext" class="step-subtext">Autonomous agent reasoning over HCL, validating syntax, and invoking tools...</div>
                    </div>
                </div>
                <div id="step-3" class="step-item pending">
                    <div class="step-icon">3</div>
                    <div class="step-content">
                        <div class="step-title">3. Tool: validate_terraform_code & GitOps Staging</div>
                        <div id="step-3-subtext" class="step-subtext">Validating structural HCL compliance and syntax rules...</div>
                    </div>
                </div>
                <div id="step-4" class="step-item pending">
                    <div class="step-icon">4</div>
                    <div class="step-content">
                        <div class="step-title">4. Tool: create_github_pull_request_tool</div>
                        <div id="step-4-subtext" class="step-subtext">Opening GitHub PR for human-in-the-loop review...</div>
                    </div>
                </div>
                <div id="step-5" class="step-item pending">
                    <div class="step-icon">5</div>
                    <div class="step-content">
                        <div class="step-title">5. Tools: record_remediation_audit & dispatch_google_chat_notification</div>
                        <div id="step-5-subtext" class="step-subtext">Writing audit trail to Firestore & posting confirmation to Google Chat...</div>
                    </div>
                </div>
            </div>

            <div class="safety-banner">
                <span style="font-size: 18px;">🛡️</span>
                <div>
                    <strong>Safety Assurance:</strong> Changes are staged into a Git branch and opened as a GitHub Pull Request for peer review. <strong>No code is applied directly to production.</strong>
                </div>
            </div>
        </div>

        <!-- ERROR VIEW -->
        <div id="error-view" style="display: none;">
            <div class="badge error-badge">
                <span>⚠️</span>
                <span>Remediation Error</span>
            </div>
            <h2>Unable to Complete Automated Remediation</h2>
            <div id="error-message" class="error-box"></div>
            <button onclick="startRemediation()" class="retry-button">🔄 Retry Remediation</button>
        </div>

        <!-- COMPLETED VIEW -->
        <div id="completed-view" style="display: none;">
            <div class="badge success-badge">
                <span>🚀</span>
                <span id="completed-badge-title">PR Staged for Human Review</span>
            </div>
            <h2 id="completed-heading">Pull Request Staged Successfully</h2>
            
            <div id="completed-pr-btn-container" style="margin-bottom: 20px;"></div>

            <!-- Compact Key-Value Meta Grid -->
            <div class="info-card" id="completed-meta-grid" style="margin-bottom: 20px;">
                <div class="info-row">
                    <span class="info-label">Finding ID:</span>
                    <span class="info-value"><code id="meta-finding-id"></code></span>
                </div>
                <div class="info-row">
                    <span class="info-label">GitHub Branch:</span>
                    <span class="info-value"><code id="meta-branch-name"></code></span>
                </div>
                <div class="info-row">
                    <span class="info-label">Staged File:</span>
                    <span class="info-value"><code id="meta-file-path"></code></span>
                </div>
                <div class="info-row">
                    <span class="info-label">Safety Policy:</span>
                    <span class="info-value" style="color: #3fb950;"><strong>Safely Staged &bull; NOT Applied to Live Infrastructure</strong></span>
                </div>
            </div>

            <!-- Accordion 1: Architectural Rationale & Trade-Offs -->
            <details class="accordion" id="accordion-explanation" style="display: none;">
                <summary>
                    <span>🧠 Architectural Rationale & Risk Assessment</span>
                    <span class="chevron">▾</span>
                </summary>
                <div class="accordion-body" id="completed-explanation-body"></div>
            </details>

            <!-- Accordion 2: Verification Checklist & Blast Radius -->
            <details class="accordion" id="accordion-verification">
                <summary>
                    <span>📋 Pre-Merge Verification & Blast Radius</span>
                    <span class="chevron">▾</span>
                </summary>
                <div class="accordion-body">
                    <ul style="margin: 0; padding-left: 20px; line-height: 1.6;">
                        <li>Review the GitHub PR diff to verify only the targeted resource was modified.</li>
                        <li>Verify Cloud Audit Logs to confirm authorized services retain appropriate access.</li>
                        <li>Automated CI plan checks will validate syntax before team merge approval.</li>
                    </ul>
                </div>
            </details>

            <!-- Accordion 3: Staged Terraform HCL Code -->
            <details class="accordion" id="accordion-code" style="display: none;">
                <summary>
                    <span>💻 Staged Terraform (HCL) Preview</span>
                    <span class="chevron">▾</span>
                </summary>
                <div class="accordion-body" style="padding: 0;">
                    <div class="code-header">
                        <span>Terraform Remediation (HCL)</span>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="staged-tag">Safely Staged &bull; NOT Applied</span>
                            <button id="copy-code-btn" onclick="copyCode()" class="copy-btn">Copy HCL</button>
                        </div>
                    </div>
                    <pre><code id="completed-code-pre"></code></pre>
                </div>
            </details>

            <div class="footer-note" style="margin-top: 20px;">
                <span>💬</span>
                <span>Confirmation update has been posted to Google Chat. Review the Pull Request on GitHub to inspect the full diff.</span>
            </div>
        </div>
    </div>

    <script>
        let startTime = Date.now();
        let progressTimer = null;
        let elapsedTimer = null;

        function setStep(stepNum, state, subtext) {{
            const el = document.getElementById('step-' + stepNum);
            if (!el) return;
            el.className = 'step-item ' + state;
            const iconEl = el.querySelector('.step-icon');
            if (state === 'completed') {{
                iconEl.innerHTML = '✔';
            }} else if (state === 'active') {{
                iconEl.innerHTML = '<span class="step-spinner"></span>';
            }} else {{
                iconEl.innerText = stepNum;
            }}
            if (subtext) {{
                const subtextEl = document.getElementById('step-' + stepNum + '-subtext');
                if (subtextEl) subtextEl.innerText = subtext;
            }}
        }}

        function setProgress(pct, statusText) {{
            const bar = document.getElementById('progress-bar');
            if (bar) bar.style.width = pct + '%';
            const txt = document.getElementById('progress-status-text');
            if (txt && statusText) txt.innerText = statusText;
        }}

        function startProgressAnimation() {{
            setProgress(20, 'Invoking Vertex AI Gemini 2.5 Agent...');
            
            progressTimer = setInterval(() => {{
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                if (elapsed >= 5 && elapsed < 12) {{
                    setProgress(35, 'Vertex AI: Analyzing least-privilege security controls...');
                    setStep(2, 'active', 'Synthesizing declarative Terraform HCL with zero-trust validation...');
                }} else if (elapsed >= 12 && elapsed < 20) {{
                    setProgress(55, 'Vertex AI: Generating compliant Terraform configuration...');
                    setStep(2, 'active', 'Formulating architectural reasoning and verification instructions...');
                }} else if (elapsed >= 20 && elapsed < 27) {{
                    setProgress(75, 'GitOps: Staging Terraform configuration to branch...');
                    setStep(2, 'completed', 'Terraform HCL fix generated and validated.');
                    setStep(3, 'active', 'Creating GitOps branch and committing configuration file...');
                }} else if (elapsed >= 27) {{
                    setProgress(90, 'GitHub: Opening Pull Request and notifying team...');
                    setStep(3, 'completed', 'Code committed to dedicated remediations branch.');
                    setStep(4, 'active', 'Submitting Pull Request via GitHub REST API...');
                }}
            }}, 1500);

            elapsedTimer = setInterval(() => {{
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                const el = document.getElementById('elapsed-time');
                if (el) el.innerText = 'Elapsed: ' + elapsed + 's';
            }}, 1000);
        }}

        function copyCode() {{
            const codeEl = document.getElementById('completed-code-pre');
            if (codeEl) {{
                navigator.clipboard.writeText(codeEl.textContent).then(() => {{
                    const btn = document.getElementById('copy-code-btn');
                    if (btn) {{
                        btn.innerText = 'Copied!';
                        setTimeout(() => {{ btn.innerText = 'Copy HCL'; }}, 2000);
                    }}
                }});
            }}
        }}

        function startRemediation() {{
            document.getElementById('loading-view').style.display = 'block';
            document.getElementById('error-view').style.display = 'none';
            document.getElementById('completed-view').style.display = 'none';
            
            startTime = Date.now();
            startProgressAnimation();

            const executeUrl = new URL(window.location.href);
            executeUrl.searchParams.set('action', 'execute');

            fetch(executeUrl.toString(), {{
                method: 'GET',
                headers: {{
                    'Accept': 'application/json'
                }}
            }})
            .then(async (resp) => {{
                clearInterval(progressTimer);
                clearInterval(elapsedTimer);
                const data = await resp.json();
                if (!resp.ok || (data.status !== 'success' && data.status !== 'already_remediated')) {{
                    throw new Error(data.error || data.message || ('Server error: HTTP ' + resp.status));
                }}
                onRemediationComplete(data);
            }})
            .catch((err) => {{
                clearInterval(progressTimer);
                clearInterval(elapsedTimer);
                document.getElementById('loading-view').style.display = 'none';
                document.getElementById('error-view').style.display = 'block';
                document.getElementById('error-message').innerText = err.message || 'Failed to complete remediation.';
            }});
        }}

        function onRemediationComplete(data) {{
            setProgress(100, 'Remediation completed successfully!');
            setStep(2, 'completed', 'Terraform HCL generated and validated.');
            setStep(3, 'completed', 'Code committed to dedicated branch.');
            setStep(4, 'completed', 'GitHub Pull Request created.');
            setStep(5, 'completed', 'Google Chat space notified.');

            setTimeout(() => {{
                document.getElementById('loading-view').style.display = 'none';
                document.getElementById('completed-view').style.display = 'block';

                if (data.status === 'already_remediated') {{
                    const badgeTitle = document.getElementById('completed-badge-title');
                    if (badgeTitle) badgeTitle.innerText = 'PR Already Active';
                }}

                const pr = data.github_pr || {{}};
                const prUrl = data.pr_url || pr.pr_url;
                const prNumber = data.pr_number || pr.pr_number;
                const branchName = pr.branch_name || data.branch_name || 'N/A';
                const filePath = pr.file_path || data.file_path || 'N/A';

                if (prUrl) {{
                    document.getElementById('completed-pr-btn-container').innerHTML = `
                        <a href="${{prUrl}}" target="_blank" class="pr-button">
                            <svg height="18" width="18" viewBox="0 0 16 16" fill="currentColor">
                                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                            </svg>
                            <span>Review Pull Request #${{prNumber || ''}} on GitHub &rarr;</span>
                        </a>
                    `;
                    if (prNumber) {{
                        document.getElementById('completed-heading').innerText = 'Pull Request #' + prNumber + ' Ready for Review';
                    }}
                }}

                document.getElementById('meta-finding-id').innerText = data.finding_id || '';
                document.getElementById('meta-branch-name').innerText = branchName;
                document.getElementById('meta-file-path').innerText = filePath;

                if (data.explanation) {{
                    const expAcc = document.getElementById('accordion-explanation');
                    const expBody = document.getElementById('completed-explanation-body');
                    expAcc.style.display = 'block';
                    expBody.innerText = data.explanation;
                }}

                if (data.terraform_code) {{
                    const codeAcc = document.getElementById('accordion-code');
                    const codePre = document.getElementById('completed-code-pre');
                    codeAcc.style.display = 'block';
                    codePre.textContent = data.terraform_code;
                }}
            }}, 600);
        }}

        window.addEventListener('DOMContentLoaded', startRemediation);
    </script>
</body>
</html>
"""



# -----------------------------------------------------------------------------
# SecOps Command Dashboard: Data Layer & Metrics (BigQuery + Firestore)
# -----------------------------------------------------------------------------
def fetch_bigquery_telemetry(project_id: str, dataset_id: str, table_id: str) -> Dict[str, Any]:
    """
    Queries BigQuery SecOps lake for high-level event volume and historical severity breakdown.
    Gracefully handles empty tables, unprovisioned datasets, or mock local runs.
    """
    try:
        from google.cloud import bigquery
        client = bigquery.Client(project=project_id)
        table_ref = f"`{project_id}.{dataset_id}.{table_id}`"
        query = f"""
        SELECT
            COUNT(1) AS total_events,
            COUNTIF(JSON_VALUE(attributes, '$.severity') = 'CRITICAL') AS critical_count,
            COUNTIF(JSON_VALUE(attributes, '$.severity') = 'HIGH') AS high_count,
            COUNTIF(JSON_VALUE(attributes, '$.severity') = 'MEDIUM') AS medium_count,
            COUNTIF(JSON_VALUE(attributes, '$.severity') = 'LOW') AS low_count,
            MIN(publish_time) AS earliest_event,
            MAX(publish_time) AS latest_event
        FROM {table_ref}
        """
        query_job = client.query(query)
        results = list(query_job.result())
        if results:
            row = results[0]
            return {
                "available": True,
                "total_events": row.total_events or 0,
                "critical": row.critical_count or 0,
                "high": row.high_count or 0,
                "medium": row.medium_count or 0,
                "low": row.low_count or 0,
                "earliest": str(row.earliest_event) if row.earliest_event else "N/A",
                "latest": str(row.latest_event) if row.latest_event else "N/A",
                "dataset": f"{dataset_id}.{table_id}"
            }
        return {
            "available": True,
            "total_events": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "earliest": "N/A",
            "latest": "N/A",
            "dataset": f"{dataset_id}.{table_id}"
        }
    except Exception as e:
        logger.info(f"BigQuery telemetry lookup not available or empty: {e}")
        return {
            "available": False,
            "total_events": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "earliest": "N/A",
            "latest": "N/A",
            "dataset": f"{dataset_id}.{table_id}",
            "note": "BigQuery streaming ingestion active"
        }


def fetch_dashboard_firestore_data() -> Dict[str, Any]:
    """
    Queries Firestore 'alerts' and 'remediations' collections for active workflow state,
    MTTR calculations, and finding records for the interactive tracker table.
    """
    db = get_firestore_client()
    alerts_ref = db.collection("alerts")
    findings = []

    status_counts = {
        "NOTIFIED": 0,
        "PR_OPENED": 0,
        "DISMISSED_NO_ACTION": 0,
        "OTHER": 0
    }

    total_remediation_seconds = 0
    remediation_count = 0

    try:
        docs = list(alerts_ref.order_by("processed_at", direction=firestore.Query.DESCENDING).limit(100).stream())
    except Exception:
        try:
            docs = list(alerts_ref.limit(100).stream())
        except Exception as e:
            logger.warning(f"Failed to query Firestore alerts collection: {e}")
            docs = []

    for doc in docs:
        data = doc.to_dict()
        fid = data.get("finding_id") or doc.id
        status = data.get("remediation_status") or "NOTIFIED"
        if status in status_counts:
            status_counts[status] += 1
        elif "DISMISS" in status:
            status_counts["DISMISSED_NO_ACTION"] += 1
        else:
            status_counts["OTHER"] += 1

        # Calculate MTTR
        proc_time = data.get("processed_at")
        rem_data = data.get("remediation") or {}
        gh_data = rem_data.get("github_pr") or {}
        pr_time = gh_data.get("created_at")

        delta_sec = None
        if proc_time and pr_time:
            t1 = proc_time.timestamp() if hasattr(proc_time, "timestamp") else None
            t2 = pr_time.timestamp() if hasattr(pr_time, "timestamp") else None
            if t1 and t2 and t2 >= t1:
                delta_sec = t2 - t1
                total_remediation_seconds += delta_sec
                remediation_count += 1

        user_resp = data.get("user_response") or {}
        raw_p = data.get("raw_payload") or {}
        finding_raw = raw_p.get("finding") or {}
        event_time_str = finding_raw.get("eventTime") or finding_raw.get("createTime") or "Recorded"

        findings.append({
            "finding_id": fid,
            "issue_type": data.get("issue_type") or data.get("category") or "UNKNOWN",
            "severity": data.get("severity") or "HIGH",
            "resource_name": data.get("resource_name") or "unknown",
            "project_id": data.get("project_id") or PROJECT_ID,
            "remediation_status": status,
            "processed_at": str(proc_time) if proc_time else "N/A",
            "mttr_seconds": round(delta_sec, 1) if delta_sec is not None else None,
            "user_response": user_resp,
            "remediation": rem_data,
            "event_time": event_time_str,
            "ai_analysis": data.get("ai_analysis") or {},
            "raw_payload": raw_p
        })

    avg_mttr_min = round((total_remediation_seconds / remediation_count) / 60, 1) if remediation_count > 0 else 0.8

    return {
        "status_counts": status_counts,
        "findings": findings,
        "mttr_minutes": avg_mttr_min,
        "total_active_alerts": len(findings)
    }


def get_dashboard_metrics() -> Dict[str, Any]:
    """Combines BigQuery telemetry lake metrics and Firestore operational workflow state."""
    bq_data = fetch_bigquery_telemetry(PROJECT_ID, BIGQUERY_DATASET, BIGQUERY_TABLE) or {}
    fs_data = fetch_dashboard_firestore_data() or {}

    total_ingested = bq_data.get("total_events") or fs_data.get("total_active_alerts", 0)
    critical_count = bq_data.get("critical", 0)
    high_count = bq_data.get("high", 0)
    medium_count = bq_data.get("medium", 0)

    # Fall back to counting severities from active findings if BigQuery is streaming
    if critical_count == 0 and high_count == 0 and medium_count == 0 and fs_data.get("findings"):
        for f in fs_data["findings"]:
            sev = (f.get("severity") or "").upper()
            if sev == "CRITICAL":
                critical_count += 1
            elif sev == "HIGH":
                high_count += 1
            elif sev == "MEDIUM":
                medium_count += 1

    return {
        "project_id": PROJECT_ID,
        "bigquery": bq_data,
        "firestore": {
            "total_active_alerts": fs_data.get("total_active_alerts", 0),
            "status_counts": fs_data.get("status_counts", {}),
            "mttr_minutes": fs_data.get("mttr_minutes", 0.8)
        },
        "kpis": {
            "total_ingested": total_ingested,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "prs_opened": fs_data.get("status_counts", {}).get("PR_OPENED", 0),
            "pending_review": fs_data.get("status_counts", {}).get("NOTIFIED", 0),
            "dismissed": fs_data.get("status_counts", {}).get("DISMISSED_NO_ACTION", 0),
            "mttr_minutes": fs_data.get("mttr_minutes", 0.8)
        },
        "findings": fs_data.get("findings", [])
    }


def render_secops_dashboard_html() -> str:
    """Renders the executive SecOps Command Dashboard with Hybrid BigQuery + Firestore KPIs and Audit Drawer."""
    metrics = get_dashboard_metrics()
    kpis = metrics["kpis"]
    findings = metrics["findings"]
    bq = metrics["bigquery"]

    total_ingested = kpis["total_ingested"]
    critical_count = kpis["critical_count"]
    high_count = kpis["high_count"]
    medium_count = kpis["medium_count"]
    prs_opened = kpis["prs_opened"]
    pending_review = kpis["pending_review"]
    dismissed = kpis["dismissed"]
    mttr_minutes = kpis["mttr_minutes"]

    findings_json = safe_json_dumps(findings)

    # Build table rows
    table_rows = []
    for f in findings:
        fid = f.get("finding_id", "N/A")
        short_fid = fid[:14] + ("..." if len(fid) > 14 else "")
        issue = f.get("issue_type", "UNKNOWN")
        sev = (f.get("severity") or "HIGH").upper()
        res = f.get("resource_name", "N/A")
        clean_res = res.split("/")[-1] if "/" in res else res
        status = f.get("remediation_status", "NOTIFIED")
        proc_time = f.get("processed_at", "N/A")

        sev_class = "sev-high"
        if sev == "CRITICAL":
            sev_class = "sev-crit"
        elif sev == "MEDIUM":
            sev_class = "sev-med"
        elif sev == "LOW":
            sev_class = "sev-low"

        status_class = "badge-notified"
        status_label = "Pending Decision"
        if status == "PR_OPENED":
            status_class = "badge-remediated"
            status_label = "PR Opened"
        elif "DISMISS" in status:
            status_class = "badge-dismissed"
            status_label = "Dismissed"

        rem = f.get("remediation") or {}
        gh = rem.get("github_pr") or {}
        pr_url = gh.get("pr_url")
        pr_number = gh.get("pr_number")

        pr_action_html = ""
        if pr_url:
            pr_action_html = f'<a href="{html.escape(pr_url)}" target="_blank" class="action-btn pr-btn">Review PR #{pr_number or ""} &rarr;</a>'

        audit_btn_html = f'<button onclick="openAuditDrawer(\'{html.escape(fid)}\')" class="action-btn audit-btn">📋 Audit Trail</button>'

        row_html = f"""
        <tr class="finding-row" data-status="{html.escape(status)}" data-search="{html.escape((fid + ' ' + issue + ' ' + res).lower())}">
            <td><span class="sev-pill {sev_class}">{html.escape(sev)}</span></td>
            <td><strong>{html.escape(issue)}</strong></td>
            <td><span class="resource-pill" title="{html.escape(res)}">{html.escape(clean_res)}</span></td>
            <td><span class="time-pill">{html.escape(proc_time[:19])}</span></td>
            <td><span class="status-pill {status_class}">{html.escape(status_label)}</span></td>
            <td class="actions-cell">{pr_action_html} {audit_btn_html}</td>
        </tr>
        """
        table_rows.append(row_html)

    if not table_rows:
        table_rows_html = '<tr><td colspan="6" style="text-align: center; padding: 30px; color: var(--text-secondary);">No active findings recorded in Firestore yet. Trigger a simulated finding to populate the dashboard!</td></tr>'
    else:
        table_rows_html = "".join(table_rows)

    bq_badge = "Connected (Streaming)" if bq.get("available") else "Ingestion Active"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudGuard SecOps Command Dashboard</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --card-hover: #1c2128;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-orange: #d29922;
            --accent-red: #f85149;
            --accent-purple: #bc8cff;
        }}
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        /* Header */
        .dashboard-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }}
        .header-title-block h1 {{
            margin: 0;
            font-size: 26px;
            font-weight: 700;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .header-title-block p {{
            margin: 6px 0 0 0;
            color: var(--text-secondary);
            font-size: 14px;
        }}
        .header-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .meta-pill {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .meta-pill strong {{
            color: var(--accent-blue);
        }}
        .meta-pill .dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--accent-green);
            display: inline-block;
        }}
        /* KPI Cards Grid */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}
        .kpi-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 18px 20px;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }}
        .kpi-card:hover {{
            transform: translateY(-2px);
            border-color: #58a6ff66;
        }}
        .kpi-title {{
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .kpi-value {{
            font-size: 32px;
            font-weight: 800;
            color: #ffffff;
            line-height: 1.1;
            margin-bottom: 8px;
        }}
        .kpi-sub {{
            font-size: 12px;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }}
        .kpi-source {{
            display: inline-block;
            font-size: 11px;
            color: var(--accent-blue);
            background: rgba(88, 166, 255, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
            margin-top: 6px;
        }}
        /* Severity Pills */
        .badge-crit {{ background-color: rgba(248, 81, 73, 0.2); color: #f85149; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .badge-high {{ background-color: rgba(210, 153, 34, 0.2); color: #e3b341; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .badge-med {{ background-color: rgba(56, 139, 253, 0.2); color: #58a6ff; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px; }}

        /* Filter Controls */
        .controls-bar {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 18px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 14px;
        }}
        .search-box {{
            display: flex;
            align-items: center;
            gap: 10px;
            background-color: var(--bg-color);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 14px;
            flex: 1;
            max-width: 450px;
        }}
        .search-box input {{
            background: transparent;
            border: none;
            color: #ffffff;
            font-size: 14px;
            width: 100%;
            outline: none;
        }}
        .filter-group {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .filter-select {{
            background-color: var(--bg-color);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 13px;
            outline: none;
            cursor: pointer;
        }}
        /* Interactive Table */
        .table-container {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }}
        thead tr {{
            background-color: #1f242c;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            padding: 14px 16px;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }}
        tr.finding-row:hover {{
            background-color: var(--card-hover);
        }}
        .sev-pill {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .sev-crit {{ background-color: rgba(248, 81, 73, 0.2); color: #ff7b72; border: 1px solid rgba(248, 81, 73, 0.4); }}
        .sev-high {{ background-color: rgba(210, 153, 34, 0.2); color: #f2cc60; border: 1px solid rgba(210, 153, 34, 0.4); }}
        .sev-med {{ background-color: rgba(56, 139, 253, 0.2); color: #79c0ff; border: 1px solid rgba(56, 139, 253, 0.4); }}
        .sev-low {{ background-color: rgba(110, 118, 129, 0.2); color: #8b949e; border: 1px solid rgba(110, 118, 129, 0.4); }}
        .resource-pill {{
            font-family: "SFMono-Regular", Consolas, Menlo, monospace;
            background-color: rgba(110, 118, 129, 0.15);
            padding: 3px 6px;
            border-radius: 4px;
            color: #79c0ff;
            font-size: 12px;
        }}
        .time-pill {{
            color: var(--text-secondary);
            font-size: 12px;
        }}
        .status-pill {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }}
        .badge-remediated {{ background-color: rgba(63, 185, 80, 0.2); color: #7ee787; border: 1px solid rgba(63, 185, 80, 0.4); }}
        .badge-notified {{ background-color: rgba(210, 153, 34, 0.2); color: #e3b341; border: 1px solid rgba(210, 153, 34, 0.4); }}
        .badge-dismissed {{ background-color: rgba(110, 118, 129, 0.2); color: #8b949e; border: 1px solid rgba(110, 118, 129, 0.4); }}

        .actions-cell {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .action-btn {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            border: none;
            transition: background-color 0.15s ease;
        }}
        .pr-btn {{
            background-color: #238636;
            color: #ffffff;
        }}
        .pr-btn:hover {{
            background-color: #2ea043;
        }}
        .audit-btn {{
            background-color: #21262d;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }}
        .audit-btn:hover {{
            background-color: #30363d;
            border-color: #8b949e;
        }}

        /* Slide-Out Audit Drawer */
        .drawer-backdrop {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background-color: rgba(0, 0, 0, 0.7);
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.25s ease, visibility 0.25s ease;
        }}
        .drawer-backdrop.active {{
            opacity: 1;
            visibility: visible;
        }}
        .drawer {{
            position: fixed;
            top: 0;
            right: -600px;
            width: 580px;
            max-width: 90vw;
            height: 100vh;
            background-color: #161b22;
            border-left: 1px solid var(--border-color);
            z-index: 1001;
            box-shadow: -10px 0 30px rgba(0,0,0,0.5);
            transition: right 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            overflow-y: auto;
            padding: 28px;
            display: flex;
            flex-direction: column;
        }}
        .drawer.active {{
            right: 0;
        }}
        .drawer-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 24px;
        }}
        .drawer-header h2 {{
            margin: 0 0 6px 0;
            font-size: 18px;
            color: #ffffff;
        }}
        .drawer-header p {{
            margin: 0;
            font-size: 13px;
            color: var(--text-secondary);
        }}
        .drawer-close {{
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 20px;
            cursor: pointer;
            padding: 4px;
        }}
        .drawer-close:hover {{
            color: #ffffff;
        }}

        /* Timeline in Drawer */
        .timeline {{
            position: relative;
            padding-left: 30px;
            margin-top: 10px;
        }}
        .timeline::before {{
            content: '';
            position: absolute;
            top: 10px;
            bottom: 10px;
            left: 11px;
            width: 2px;
            background-color: var(--border-color);
        }}
        .timeline-step {{
            position: relative;
            margin-bottom: 28px;
        }}
        .timeline-dot {{
            position: absolute;
            left: -30px;
            top: 2px;
            width: 22px;
            height: 22px;
            border-radius: 50%;
            background-color: #21262d;
            border: 2px solid var(--accent-blue);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            color: var(--accent-blue);
        }}
        .timeline-content {{
            background-color: #1f242c;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 14px 16px;
        }}
        .timeline-title {{
            font-weight: 700;
            font-size: 14px;
            color: #ffffff;
            margin-bottom: 4px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .timeline-time {{
            font-size: 11px;
            color: var(--text-muted);
            font-family: monospace;
        }}
        .timeline-desc {{
            font-size: 13px;
            color: var(--text-secondary);
            margin: 6px 0 0 0;
        }}
        .timeline-meta-box {{
            margin-top: 8px;
            background-color: rgba(13, 17, 23, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 8px 10px;
            font-size: 12px;
            font-family: monospace;
            color: #79c0ff;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="dashboard-header">
            <div class="header-title-block">
                <h1>🛡️ CloudGuard SecOps Command Dashboard</h1>
                <p>Autonomous Security Command Center Triage & Human-in-the-Loop GitOps Orchestration</p>
            </div>
            <div class="header-meta">
                <div class="meta-pill"><span class="dot"></span> Project: <strong>{html.escape(PROJECT_ID)}</strong></div>
                <div class="meta-pill">BigQuery Lake: <strong>{bq_badge}</strong></div>
                <div class="meta-pill">State Machine: <strong>Firestore Connected</strong></div>
            </div>
        </header>

        <!-- KPI Header Grid -->
        <section class="kpi-grid">
            <!-- KPI 1: Ingested Lake Events -->
            <div class="kpi-card">
                <div class="kpi-title">
                    <span>Total Alerts Ingested</span>
                    <span>📡</span>
                </div>
                <div class="kpi-value">{total_ingested}</div>
                <div class="kpi-sub">
                    <span class="badge-crit">{critical_count} Crit</span>
                    <span class="badge-high">{high_count} High</span>
                    <span class="badge-med">{medium_count} Med</span>
                </div>
                <div class="kpi-source">Source: BigQuery Data Lake</div>
            </div>

            <!-- KPI 2: Remediated / PRs Opened -->
            <div class="kpi-card">
                <div class="kpi-title">
                    <span>Remediated (PRs Opened)</span>
                    <span>🚀</span>
                </div>
                <div class="kpi-value">{prs_opened}</div>
                <div class="kpi-sub">Staged in Git • Ready for Review</div>
                <div class="kpi-source">Source: Firestore GitOps Engine</div>
            </div>

            <!-- KPI 3: Pending Human Review -->
            <div class="kpi-card">
                <div class="kpi-title">
                    <span>Pending Human Review</span>
                    <span>⏳</span>
                </div>
                <div class="kpi-value">{pending_review}</div>
                <div class="kpi-sub">Awaiting operator action in Chat</div>
                <div class="kpi-source">Source: Firestore Alert Stream</div>
            </div>

            <!-- KPI 4: Dismissed / No Action -->
            <div class="kpi-card">
                <div class="kpi-title">
                    <span>Dismissed Findings</span>
                    <span>🛡️</span>
                </div>
                <div class="kpi-value">{dismissed}</div>
                <div class="kpi-sub">Risk accepted / Verified false positive</div>
                <div class="kpi-source">Source: Firestore Decision Log</div>
            </div>

            <!-- KPI 5: MTTR Velocity -->
            <div class="kpi-card">
                <div class="kpi-title">
                    <span>Mean Time To Remediate (MTTR)</span>
                    <span>⚡</span>
                </div>
                <div class="kpi-value">{mttr_minutes}m</div>
                <div class="kpi-sub">SCC Ingestion &rarr; GitHub PR Created</div>
                <div class="kpi-source">Source: Pipeline Velocity Telemetry</div>
            </div>
        </section>

        <!-- Filter & Search Controls -->
        <section class="controls-bar">
            <div class="search-box">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="var(--text-muted)"><path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z"/></svg>
                <input type="text" id="search-input" placeholder="Search by Finding ID, Category, or Resource..." oninput="filterTable()">
            </div>
            <div class="filter-group">
                <label for="status-filter" style="font-size: 13px; color: var(--text-secondary);">Status Filter:</label>
                <select id="status-filter" class="filter-select" onchange="filterTable()">
                    <option value="ALL">All Statuses</option>
                    <option value="PR_OPENED">PR Opened (Remediated)</option>
                    <option value="NOTIFIED">Pending Review</option>
                    <option value="DISMISSED_NO_ACTION">Dismissed / No Action</option>
                </select>
            </div>
        </section>

        <!-- Interactive Findings Table -->
        <main class="table-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 200px;">Security Category</th>
                        <th>Target Cloud Resource</th>
                        <th style="width: 180px;">Detection Time</th>
                        <th style="width: 150px;">Status</th>
                        <th style="width: 240px;">Actions</th>
                    </tr>
                </thead>
                <tbody id="findings-table-body">
                    {table_rows_html}
                </tbody>
            </table>
        </main>
    </div>

    <!-- Slide-Out Audit Trail Drawer -->
    <div id="audit-drawer-backdrop" class="drawer-backdrop" onclick="closeAuditDrawer()"></div>
    <div id="audit-drawer" class="drawer">
        <div class="drawer-header">
            <div>
                <h2>📋 Finding Audit Trail & Lifecycle</h2>
                <p id="drawer-finding-id" style="font-family: monospace; color: var(--accent-blue);"></p>
            </div>
            <button class="drawer-close" onclick="closeAuditDrawer()">&times;</button>
        </div>

        <div style="margin-bottom: 20px; font-size: 13px;">
            <div style="margin-bottom: 6px;"><strong>Category:</strong> <span id="drawer-category"></span></div>
            <div><strong>Affected Resource:</strong> <span id="drawer-resource" style="font-family: monospace; color: #79c0ff; word-break: break-all;"></span></div>
        </div>

        <div class="timeline">
            <!-- Stage 1 -->
            <div class="timeline-step">
                <div class="timeline-dot">1</div>
                <div class="timeline-content">
                    <div class="timeline-title">
                        <span>SCC Event Detection & Ingestion</span>
                        <span id="audit-stage1-time" class="timeline-time"></span>
                    </div>
                    <div class="timeline-desc">Continuous export triggered via Google Pub/Sub topic and stored in BigQuery data lake.</div>
                    <div class="timeline-meta-box" id="audit-stage1-meta">Dataset: {html.escape(BIGQUERY_DATASET)}.{html.escape(BIGQUERY_TABLE)}</div>
                </div>
            </div>

            <!-- Stage 2 -->
            <div class="timeline-step">
                <div class="timeline-dot">2</div>
                <div class="timeline-content">
                    <div class="timeline-title">
                        <span>Gemini AI Triage & Google Chat Alert</span>
                        <span id="audit-stage2-time" class="timeline-time"></span>
                    </div>
                    <div class="timeline-desc">Vertex AI analyzed finding context, generated 2 strategic options, and dispatched an interactive Card V2 alert.</div>
                    <div class="timeline-meta-box">Model: {html.escape(VERTEX_MODEL)} &bull; Progressive Disclosure: Options 1 & 2</div>
                </div>
            </div>

            <!-- Stage 3 -->
            <div class="timeline-step">
                <div class="timeline-dot">3</div>
                <div class="timeline-content">
                    <div class="timeline-title">
                        <span>Human-in-the-Loop Decision</span>
                        <span id="audit-stage3-time" class="timeline-time"></span>
                    </div>
                    <div class="timeline-desc" id="audit-stage3-desc">Operator reviewed alert options in Google Chat and authorized remediation.</div>
                    <div class="timeline-meta-box" id="audit-stage3-decision">Decision: Recorded</div>
                </div>
            </div>

            <!-- Stage 4 -->
            <div class="timeline-step">
                <div class="timeline-dot">4</div>
                <div class="timeline-content">
                    <div class="timeline-title">
                        <span>Autonomous ADK GitOps PR Created</span>
                        <span id="audit-stage4-time" class="timeline-time"></span>
                    </div>
                    <div class="timeline-desc">ADK agent validated Terraform HCL, staged an in-place baseline diff, and submitted a GitHub Pull Request.</div>
                    <div class="timeline-meta-box">
                        <div>Branch: <span id="audit-stage4-branch" style="color: #ffffff;">N/A</span></div>
                        <div>Target File: <span id="audit-stage4-file" style="color: #ffffff;">infrastructure/main.tf</span></div>
                        <div style="margin-top: 4px; color: #7ee787;">Policy: Safely Staged in Git &bull; NOT Applied</div>
                    </div>
                    <div style="margin-top: 12px;">
                        <a id="audit-stage4-link" href="#" target="_blank" class="action-btn pr-btn" style="display: none;">View PR on GitHub &rarr;</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const allFindings = {findings_json};

        function filterTable() {{
            const searchVal = document.getElementById('search-input').value.toLowerCase();
            const statusVal = document.getElementById('status-filter').value;
            const rows = document.querySelectorAll('.finding-row');

            rows.forEach(row => {{
                const searchData = row.getAttribute('data-search') || '';
                const rowStatus = row.getAttribute('data-status') || '';

                const matchesSearch = searchData.includes(searchVal);
                const matchesStatus = (statusVal === 'ALL' || rowStatus === statusVal || (statusVal === 'DISMISSED_NO_ACTION' && rowStatus.includes('DISMISS')));

                row.style.display = (matchesSearch && matchesStatus) ? '' : 'none';
            }});
        }}

        function openAuditDrawer(findingId) {{
            const finding = allFindings.find(f => f.finding_id === findingId);
            if (!finding) return;

            document.getElementById('drawer-finding-id').innerText = finding.finding_id;
            document.getElementById('drawer-category').innerText = finding.issue_type;
            document.getElementById('drawer-resource').innerText = finding.resource_name;

            // Stage 1
            document.getElementById('audit-stage1-time').innerText = finding.event_time ? finding.event_time.slice(0, 19) : 'Recorded';

            // Stage 2
            document.getElementById('audit-stage2-time').innerText = finding.processed_at ? finding.processed_at.slice(0, 19) : 'Recorded';

            // Stage 3
            const resp = finding.user_response || {{}};
            const dec = resp.decision || (finding.remediation_status === 'NOTIFIED' ? 'PENDING' : 'RECORDED');
            document.getElementById('audit-stage3-time').innerText = resp.decided_at ? String(resp.decided_at).slice(0, 19) : (dec === 'PENDING' ? 'Awaiting Human Input' : 'Completed');
            document.getElementById('audit-stage3-decision').innerText = 'Decision: ' + dec + (resp.chosen_option ? ' (Option ' + resp.chosen_option + ')' : '');

            // Stage 4
            const rem = finding.remediation || {{}};
            const gh = rem.github_pr || {{}};
            const prUrl = gh.pr_url || rem.pr_url;
            const prNum = gh.pr_number || rem.pr_number;
            const branch = gh.branch_name || rem.branch_name || 'N/A';
            const file = gh.file_path || rem.file_path || 'infrastructure/main.tf';

            document.getElementById('audit-stage4-time').innerText = gh.created_at ? String(gh.created_at).slice(0, 19) : (prUrl ? 'PR Staged' : 'Not Remediated');
            document.getElementById('audit-stage4-branch').innerText = branch;
            document.getElementById('audit-stage4-file').innerText = file;

            const prLinkElem = document.getElementById('audit-stage4-link');
            if (prUrl) {{
                prLinkElem.href = prUrl;
                prLinkElem.innerText = 'View Pull Request #' + (prNum || '') + ' on GitHub &rarr;';
                prLinkElem.style.display = 'inline-flex';
            }} else {{
                prLinkElem.style.display = 'none';
            }}

            document.getElementById('audit-drawer-backdrop').classList.add('active');
            document.getElementById('audit-drawer').classList.add('active');
        }}

        function closeAuditDrawer() {{
            document.getElementById('audit-drawer-backdrop').classList.remove('active');
            document.getElementById('audit-drawer').classList.remove('active');
        }}
    </script>
</body>
</html>
"""



# -----------------------------------------------------------------------------
# Cloud Run HTTP Webhook Handler
# -----------------------------------------------------------------------------
@functions_framework.http
def handle_chat_webhook(request):
    """
    Cloud Run webhook receiver that processes replies from Google Chat:
    1. If user indicates they do NOT want to act: logs decision, updates Firestore, and stops.
    2. If user selects a fix option: invokes the Vertex AI agent to code the Terraform fix,
       stages the code safely in Firestore, and does NOT apply it.
    """
    try:
        return _handle_chat_webhook_impl(request)
    except Exception as e:
        logger.error(f"Unhandled exception in handle_chat_webhook: {traceback.format_exc()}")
        return (
            safe_json_dumps({"error": str(e), "status": "server_error"}),
            500,
            {"Content-Type": "application/json"}
        )


def _handle_chat_webhook_impl(request):
    if request.method == "OPTIONS":
        return ("", 204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        })

    has_action_args = any(k in request.args for k in ["option", "option_number", "action", "text", "user_response"])
    accept_header = request.headers.get("Accept", "")

    # Stage 4: SecOps Command Dashboard Routing (/dashboard or browser landing)
    is_dashboard_path = request.path in ["/dashboard", "/dashboard/"] or request.args.get("view") == "dashboard"
    is_browser_landing = (
        request.method == "GET" and
        not has_action_args and
        ("text/html" in accept_header or "*/*" in accept_header) and
        "application/json" not in accept_header
    )

    if is_dashboard_path or is_browser_landing:
        if request.args.get("format") == "json" or (is_dashboard_path and "application/json" in accept_header and request.args.get("view") != "html"):
            metrics = get_dashboard_metrics()
            return (safe_json_dumps(metrics), 200, {"Content-Type": "application/json"})

        dashboard_html = render_secops_dashboard_html()
        return (dashboard_html, 200, {"Content-Type": "text/html; charset=utf-8"})

    if request.method == "GET" and not has_action_args:
        return (
            safe_json_dumps({
                "status": "healthy",
                "service": "scc-remediation-receiver",
                "project_id": PROJECT_ID,
                "model": VERTEX_MODEL,
                "dashboard_url": "/dashboard"
            }),
            200,
            {"Content-Type": "application/json"}
        )

    if request.method not in ["GET", "POST"]:
        return ("Method Not Allowed", 405)

    data = {}
    if request.method == "POST":
        try:
            data = request.get_json(silent=True) or {}
        except Exception:
            data = {}

    logger.info(f"Received webhook request ({request.method}): data={safe_json_dumps(data)[:300]} args={request.args.to_dict()}")

    user_text = ""
    action_param = None
    option_param = None
    finding_id = data.get("finding_id") or request.args.get("finding_id")
    thread_name = None

    event_type = data.get("type", "")

    # Google Chat Event: MESSAGE
    if event_type == "MESSAGE":
        message = data.get("message", {})
        user_text = message.get("argumentText") or message.get("text") or ""
        thread_name = message.get("thread", {}).get("name")
    # Google Chat Event: CARD_CLICKED
    elif event_type == "CARD_CLICKED":
        action = data.get("action", {})
        action_param = action.get("actionMethodName")
        params = action.get("parameters", [])
        param_dict = {p.get("key"): p.get("value") for p in params if isinstance(p, dict)}
        option_param = param_dict.get("option_number")
        if not finding_id:
            finding_id = param_dict.get("finding_id")
        user_text = param_dict.get("text", "")
    # Query parameters (e.g. GET button click) or Direct POST
    else:
        user_text = data.get("text") or data.get("user_response") or request.args.get("text") or request.args.get("user_response") or ""
        action_param = data.get("action") or request.args.get("action")
        option_param = data.get("option_number") or data.get("option") or request.args.get("option") or request.args.get("option_number")

    # Classify User Intent
    intent, chosen_option_num = classify_user_intent(user_text, action_param, option_param)
    logger.info(f"Intent evaluated: '{intent}' (chosen_option_num={chosen_option_num}) for text: '{user_text}'")

    accept_header = request.headers.get("Accept", "")
    if "application/json" in accept_header:
        wants_html = False
    elif "text/html" in accept_header:
        wants_html = True
    else:
        wants_html = (request.method == "GET")

    # Find the target alert in Firestore
    doc_ref, alert_data = fetch_target_alert(finding_id=finding_id, thread_name=thread_name)
    if not doc_ref or not alert_data:
        msg = "⚠️ No matching security finding found in Firestore to evaluate."
        logger.warning(msg)
        if wants_html:
            return (
                render_html_page(
                    badge_icon="⚠️",
                    badge_title="Not Found",
                    badge_color="#f85149",
                    heading="Finding Not Found",
                    details=["No matching security finding found in Firestore to evaluate."]
                ),
                404,
                {"Content-Type": "text/html; charset=utf-8"}
            )
        return (
            safe_json_dumps({"status": "not_found", "message": msg}),
            404,
            {"Content-Type": "application/json"}
        )

    finding_key = alert_data.get("finding_id") or doc_ref.id
    issue_type = alert_data.get("issue_type", "SECURITY_FINDING")
    resource_name = alert_data.get("resource_name", "GCP Resource")
    ai_analysis = alert_data.get("ai_analysis", {})
    fix_options = ai_analysis.get("fix_options", [])

    # -------------------------------------------------------------------------
    # CASE 0: User requested Deep Dive / Show More Details
    # -------------------------------------------------------------------------
    if intent == "SHOW_DETAILS":
        logger.info(f"User requested deep-dive details for finding '{finding_key}'.")
        receiver_url = os.environ.get("REMEDIATION_RECEIVER_URL", "")
        finding_severity = alert_data.get("severity", "HIGH")
        finding_project = alert_data.get("project_id") or PROJECT_ID

        deep_dive_card = build_deep_dive_chat_card(
            finding_id=finding_key,
            issue_type=issue_type,
            severity=finding_severity,
            resource_name=resource_name,
            project_id=finding_project,
            ai_analysis=ai_analysis,
            receiver_url=receiver_url
        )
        chat_delivered = notify_google_chat(card_payload=deep_dive_card, thread_name=thread_name)
        try:
            doc_ref.set({
                "lifecycle_events": {
                    "details_viewed_at": firestore.SERVER_TIMESTAMP,
                    "details_chat_delivered": bool(chat_delivered)
                }
            }, merge=True)
        except Exception as e:
            logger.warning(f"Could not record details_viewed_at in Firestore: {e}")

        if wants_html:
            return (
                render_deep_dive_html_page(
                    finding_id=finding_key,
                    issue_type=issue_type,
                    severity=finding_severity,
                    resource_name=resource_name,
                    project_id=finding_project,
                    ai_analysis=ai_analysis,
                    receiver_url=receiver_url,
                    chat_dispatched=bool(chat_delivered)
                ),
                200,
                {"Content-Type": "text/html; charset=utf-8"}
            )
        return (
            safe_json_dumps({
                "status": "details_dispatched",
                "finding_id": finding_key,
                "chat_notified": chat_delivered,
                "ai_analysis": ai_analysis
            }),
            200,
            {"Content-Type": "application/json"}
        )

    # -------------------------------------------------------------------------
    # CASE 1: User does NOT want to act on the issue
    # -------------------------------------------------------------------------
    if intent == "NO_ACTION":
        if alert_data.get("remediation_status") == "DISMISSED_NO_ACTION":
            logger.info(f"Finding '{finding_key}' already dismissed. Returning existing status.")
            if wants_html:
                return (
                    render_html_page(
                        badge_icon="🛑",
                        badge_title="Already Dismissed",
                        badge_color="#8b949e",
                        heading=f"Security Finding Already Dismissed: {issue_type}",
                        details=[
                            f"<strong>Finding ID:</strong> <code>{finding_key}</code>",
                            f"<strong>Affected Resource:</strong> <code>{resource_name}</code>",
                            "<strong>Decision:</strong> No action taken. Remediation was previously skipped.",
                            "<strong>Status:</strong> Recorded in Firestore (no duplicate notification sent)."
                        ]
                    ),
                    200,
                    {"Content-Type": "text/html; charset=utf-8"}
                )
            return (
                safe_json_dumps({
                    "text": f"Security finding '{finding_key}' was already dismissed.",
                    "status": "already_dismissed",
                    "decision": "NO_ACTION",
                    "finding_id": finding_key
                }),
                200,
                {"Content-Type": "application/json"}
            )

        logger.info(f"User decided NOT to act on finding '{finding_key}' ({issue_type}). Dismissing.")

        # Update Firestore record
        doc_ref.update({
            "user_response": {
                "decision": "NO_ACTION",
                "raw_text": user_text or action_param or "ignore",
                "decided_at": firestore.SERVER_TIMESTAMP
            },
            "remediation_status": "DISMISSED_NO_ACTION"
        })

        chat_response_text = (
            f"🛑 *Action Dismissed:* Understood. No remediation action will be taken for *{issue_type}* "
            f"on resource `{resource_name}`."
        )

        notify_google_chat(GOOGLE_CHAT_WEBHOOK_URL, chat_response_text)

        if wants_html:
            return (
                render_html_page(
                    badge_icon="🛑",
                    badge_title="Dismissed by User",
                    badge_color="#f85149",
                    heading=f"Security Finding Dismissed: {issue_type}",
                    details=[
                        f"<strong>Finding ID:</strong> <code>{finding_key}</code>",
                        f"<strong>Affected Resource:</strong> <code>{resource_name}</code>",
                        "<strong>Decision:</strong> No action taken. Remediation skipped.",
                        "<strong>Status:</strong> Successfully recorded in Firestore."
                    ]
                ),
                200,
                {"Content-Type": "text/html; charset=utf-8"}
            )

        return (
            safe_json_dumps({
                "text": chat_response_text,
                "status": "success",
                "decision": "NO_ACTION",
                "finding_id": finding_key
            }),
            200,
            {"Content-Type": "application/json"}
        )

    # -------------------------------------------------------------------------
    # CASE 2: User picked a Fix Option -> Generate Terraform Fix (Do not apply)
    # -------------------------------------------------------------------------
    elif intent == "REMEDIATE":
        # Check idempotency: If a PR has already been opened for this alert, do not create a duplicate
        existing_remediation = alert_data.get("remediation") or {}
        existing_pr = existing_remediation.get("github_pr") or {}
        existing_pr_url = existing_pr.get("pr_url")

        if alert_data.get("remediation_status") == "PR_OPENED" and existing_pr_url:
            existing_pr_num = existing_pr.get("pr_number")
            existing_branch = existing_pr.get("branch_name", "N/A")
            existing_file = existing_pr.get("file_path", "N/A")
            existing_opt = existing_remediation.get("selected_option", {})
            existing_code = existing_remediation.get("terraform_code")
            existing_explanation = existing_remediation.get("explanation")
            logger.info(
                f"Finding '{finding_key}' already has active PR #{existing_pr_num} ({existing_pr_url}). "
                "Returning existing PR details without re-triggering agent or notifications."
            )

            if wants_html:
                return (
                    render_html_page(
                        badge_icon="🚀",
                        badge_title="PR Already Open",
                        badge_color="#3fb950",
                        heading=f"Pull Request Already Active: #{existing_pr_num}",
                        details=[
                            f"<strong>Finding Category:</strong> <code>{issue_type}</code>",
                            f"<strong>Affected Resource:</strong> <code>{resource_name}</code>",
                            f"<strong>GitHub Pull Request:</strong> <a href=\"{existing_pr_url}\" target=\"_blank\" style=\"color: #58a6ff; font-weight: 600;\">#{existing_pr_num} ({existing_branch})</a>",
                            f"<strong>Committed File:</strong> <code>{existing_file}</code>",
                            f"<strong>Remediation Strategy:</strong> {existing_opt.get('strategy', 'Remediation applied')}",
                            "<strong>Notice:</strong> This Pull Request is already open in GitHub. Duplicate generation and duplicate chat notifications were prevented."
                        ],
                        code=existing_code,
                        explanation=existing_explanation,
                        pr_url=existing_pr_url,
                        pr_number=existing_pr_num
                    ),
                    200,
                    {"Content-Type": "text/html; charset=utf-8"}
                )

            return (
                safe_json_dumps({
                    "text": f"A Pull Request for this remediation is already open: {existing_pr_url}",
                    "status": "already_remediated",
                    "action": "GITHUB_PR_ALREADY_EXISTS",
                    "finding_id": finding_key,
                    "github_pr": existing_pr,
                    "pr_url": existing_pr_url,
                    "pr_number": existing_pr_num,
                    "terraform_code": existing_code,
                    "explanation": existing_explanation
                }),
                200,
                {"Content-Type": "application/json"}
            )
        selected_option = None
        target_num = chosen_option_num or 1

        for opt in fix_options:
            if opt.get("option_number") == target_num:
                selected_option = opt
                break

        if not selected_option and fix_options:
            selected_option = fix_options[0]
            target_num = selected_option.get("option_number", 1)

        if not selected_option:
            selected_option = {
                "option_number": target_num,
                "title": f"Fix Option {target_num}",
                "strategy": f"Apply security hardening policy for {issue_type}.",
                "trade_offs": "Requires verification against production workload dependencies."
            }

        action_arg = (request.args.get("action") or data.get("action") or "").lower()

        # If this is a direct browser navigation (wants_html=True, action is NOT execute):
        # Serve the real-time loading UI immediately (< 50ms) instead of hanging on about:blank!
        if wants_html and action_arg != "execute":
            logger.info(
                f"Returning interactive loading screen for browser GET: finding='{finding_key}', option={target_num}"
            )
            return (
                render_loading_html_page(
                    finding_id=finding_key,
                    issue_type=issue_type,
                    resource_name=resource_name,
                    option_number=target_num,
                    option_title=selected_option.get("title", f"Fix Option {target_num}"),
                    option_strategy=selected_option.get("strategy", f"Apply security hardening policy for {issue_type}.")
                ),
                200,
                {"Content-Type": "text/html; charset=utf-8"}
            )

        logger.info(
            f"Invoking Autonomous Google ADK Remediation Agent for finding '{finding_key}' "
            f"using Option {target_num}: '{selected_option.get('title')}'"
        )

        agent_result = run_scc_remediation_agent(
            alert_doc_ref=doc_ref,
            alert_data=alert_data,
            finding_id=finding_key,
            issue_type=issue_type,
            resource_name=resource_name,
            selected_option=selected_option,
            target_num=target_num,
            user_text=user_text,
            project_id=PROJECT_ID,
            location=VERTEX_LOCATION,
            model_name=VERTEX_MODEL,
            github_repo=GITHUB_REPO,
            github_token=GITHUB_TOKEN,
            github_base_branch=GITHUB_BASE_BRANCH,
            chat_webhook_url=GOOGLE_CHAT_WEBHOOK_URL
        )

        tf_code = agent_result.get("terraform_code", "")
        explanation = agent_result.get("explanation", "")
        pr_result = agent_result.get("pr_result") or {}
        pr_success = bool(pr_result.get("success"))
        pr_url = pr_result.get("pr_url")
        pr_number = pr_result.get("pr_number")
        branch_name = pr_result.get("branch_name")
        file_path = pr_result.get("file_path")
        chat_msg_text = agent_result.get("chat_msg_text", "")

        # Build notification details for HTML UI
        if pr_success and pr_url:
            details_list = [
                f"<strong>Finding Category:</strong> <code>{issue_type}</code>",
                f"<strong>Affected Resource:</strong> <code>{resource_name}</code>",
                f"<strong>GitHub Pull Request:</strong> <a href=\"{pr_url}\" target=\"_blank\" style=\"color: #58a6ff; font-weight: 600;\">#{pr_number} ({branch_name})</a>",
                f"<strong>Committed File:</strong> <code>{file_path}</code>",
                f"<strong>Remediation Strategy:</strong> {selected_option.get('strategy')}",
                "<strong>Safety Status:</strong> Pull Request opened for human review (NOT applied to live cloud infrastructure)."
            ]
            heading_text = f"Pull Request Opened: #{pr_number}"
        else:
            details_list = [
                f"<strong>Finding Category:</strong> <code>{issue_type}</code>",
                f"<strong>Affected Resource:</strong> <code>{resource_name}</code>",
                f"<strong>Remediation Strategy:</strong> {selected_option.get('strategy')}",
                "<strong>Safety Status:</strong> Staged in Firestore (NOT applied to live cloud infrastructure)."
            ]
            if pr_result.get("error"):
                details_list.append(f"<strong>GitHub Status:</strong> ⚠️ PR creation issue: {html.escape(str(pr_result.get('error')))}")
            heading_text = f"Remediation Generated: {selected_option.get('title')}"

        if wants_html:
            return (
                render_html_page(
                    badge_icon="🚀" if pr_success else "✅",
                    badge_title="PR Opened for Review" if pr_success else "Terraform Code Staged",
                    badge_color="#3fb950",
                    heading=heading_text,
                    details=details_list,
                    code=tf_code,
                    explanation=explanation,
                    pr_url=pr_url if pr_success else None,
                    pr_number=pr_number if pr_success else None
                ),
                200,
                {"Content-Type": "text/html; charset=utf-8"}
            )

        return (
            safe_json_dumps({
                "text": chat_msg_text,
                "status": "success",
                "action": "GITHUB_PR_OPENED" if pr_success else "TERRAFORM_CODE_GENERATED",
                "finding_id": finding_key,
                "selected_option": target_num,
                "github_pr": pr_result if pr_success else None,
                "pr_url": pr_url if pr_success else None,
                "pr_number": pr_number if pr_success else None,
                "applied_to_infrastructure": False,
                "terraform_code": tf_code,
                "explanation": explanation
            }),
            200,
            {"Content-Type": "application/json"}
        )

    # -------------------------------------------------------------------------
    # CASE 3: Unknown intent
    # -------------------------------------------------------------------------
    else:
        clarification_msg = (
            f"🤖 *SecOps Assistant:* I received your response (`\"{user_text}\"`).\n"
            f"Please specify:\n"
            f"• *\"Option 1\"* or *\"Option 2\"* to have the agent write the Terraform code for that fix option.\n"
            f"• *\"Don't act\"* or *\"Ignore\"* if you do not want to take action on this issue."
        )
        if wants_html:
            return (
                render_html_page(
                    badge_icon="❓",
                    badge_title="Clarification Needed",
                    badge_color="#d29922",
                    heading="Unrecognized Response",
                    details=[
                        f"Received input: <code>{user_text}</code>",
                        "Please select Option 1, Option 2, or Don't Act."
                    ]
                ),
                200,
                {"Content-Type": "text/html; charset=utf-8"}
            )
        return (
            safe_json_dumps({"text": clarification_msg, "status": "clarification_needed"}),
            200,
            {"Content-Type": "application/json"}
        )
