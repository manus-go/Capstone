import base64
import json
import logging
import os
import re
import sys
import time
import traceback
import urllib.parse
from datetime import datetime, timezone
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("scc_alert_router")
logger.setLevel(logging.INFO)

_db_client = None


def get_firestore_client():
    """Lazily initializes and returns the Firestore client."""
    global _db_client
    if _db_client is None:
        project_id = os.environ.get("PROJECT_ID")
        _db_client = firestore.Client(project=project_id)
        logger.info(f"Initialized Firestore client for project: {project_id}")
    return _db_client


def sanitize_doc_id(raw_id: str) -> str:
    """Sanitizes strings to create valid, URL-safe Firestore document IDs."""
    if not raw_id:
        return "unknown"
    sanitized = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", raw_id)
    return sanitized[:200]


def parse_resource_display(resource_name: str, project_id: str = "") -> Dict[str, str]:
    """
    Parses an SCC resourceName URI into a clean resource name, asset type, and project ID.
    Examples:
      //storage.googleapis.com/projects/_/buckets/my-bucket -> my-bucket (Cloud Storage Bucket)
      //compute.googleapis.com/projects/p/global/firewalls/allow-ssh -> allow-ssh (VPC Firewall Rule)
      //iam.googleapis.com/projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com -> sa@p... (IAM Service Account)
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


def run_scc_triage_agent(payload: dict, project_id: str, location: str, model_name: str) -> dict:
    """
    Invokes the Google Agent Development Kit (ADK) autonomous Triage Agent equipped with
    the `publish_triage_assessment` tool to:
    1. Write a 1-sentence technical issue and breach risk summary.
    2. Formulate declarative Terraform remediation options with concise summaries, pros, and cons.
    3. Provide deep architectural rationale and compliance/blast radius analysis for on-demand inspection.
    """
    finding = payload.get("finding", {})
    if not isinstance(finding, dict):
        finding = {}

    issue_type = (
        finding.get("category")
        or payload.get("category")
        or payload.get("issue_type")
        or finding.get("findingClass")
        or "GENERAL_SECURITY_FINDING"
    )
    severity = finding.get("severity") or payload.get("severity") or "HIGH"
    resource_name = (
        finding.get("resourceName")
        or payload.get("resourceName")
        or payload.get("resource")
        or "UNKNOWN_RESOURCE"
    )
    description = (
        finding.get("description")
        or payload.get("description")
        or "Security Command Center finding detected."
    )
    source_properties = finding.get("sourceProperties", {})
    next_steps = finding.get("nextSteps", "")

    # Configure Vertex AI backend for ADK
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE"
    os.environ["GOOGLE_CLOUD_PROJECT"] = project_id
    os.environ["GOOGLE_CLOUD_LOCATION"] = location

    triage_result: Dict[str, Any] = {}

    def normalize_str_list(val: Any) -> List[str]:
        if isinstance(val, list):
            return [str(x).strip("-* \t\n") for x in val if str(x).strip()]
        if isinstance(val, str):
            return [line.strip("-* \t\n") for line in val.split("\n") if line.strip()]
        return []

    def publish_triage_assessment(
        one_sentence_summary: str,
        recommended_option_number: int,
        option_1_title: str,
        option_1_summary: str,
        option_1_pros: List[str],
        option_1_cons: List[str],
        option_2_title: str,
        option_2_summary: str,
        option_2_pros: List[str],
        option_2_cons: List[str],
        deep_architectural_reasoning: str,
        compliance_and_blast_radius: str
    ) -> dict:
        """Publishes the structured triage assessment and Terraform remediation options for the security finding.

        Args:
            one_sentence_summary: Exactly one concise, punchy sentence summarizing the vulnerability, affected resource, and breach/exploit risk. No filler words.
            recommended_option_number: Integer 1 or 2 identifying which option is objectively recommended.
            option_1_title: Short descriptive title for Option 1 (e.g. Enforce Uniform Bucket-Level Access).
            option_1_summary: Exactly one clear sentence explaining what Terraform changes this option applies.
            option_1_pros: 2 to 3 concise bullet points highlighting key security and operational benefits.
            option_1_cons: 1 to 2 concise bullet points highlighting limitations, operational trade-offs, or migration impact.
            option_2_title: Short descriptive title for Option 2 (e.g. Enforce Private IP & IAM Restriction).
            option_2_summary: Exactly one clear sentence explaining what alternative Terraform changes this option applies.
            option_2_pros: 2 to 3 concise bullet points highlighting benefits.
            option_2_cons: 1 to 2 concise bullet points highlighting trade-offs.
            deep_architectural_reasoning: In-depth technical rationale and architecture justification explaining why the recommended option was chosen.
            compliance_and_blast_radius: Analysis of CIS/NIST compliance alignment, production blast radius, and workload dependencies.
        """
        opt1_p = normalize_str_list(option_1_pros)
        opt1_c = normalize_str_list(option_1_cons)
        opt2_p = normalize_str_list(option_2_pros)
        opt2_c = normalize_str_list(option_2_cons)

        try:
            rec_num = int(recommended_option_number)
            if rec_num not in [1, 2]:
                rec_num = 1
        except Exception:
            rec_num = 1

        triage_result["issue_summary"] = one_sentence_summary.strip()
        triage_result["recommended_option_number"] = rec_num
        triage_result["deep_architectural_reasoning"] = deep_architectural_reasoning.strip()
        triage_result["compliance_and_blast_radius"] = compliance_and_blast_radius.strip()

        opt1_tradeoffs = f"Pros: {'; '.join(opt1_p)} | Cons: {'; '.join(opt1_c)}" if (opt1_p or opt1_c) else ""
        opt2_tradeoffs = f"Pros: {'; '.join(opt2_p)} | Cons: {'; '.join(opt2_c)}" if (opt2_p or opt2_c) else ""

        triage_result["fix_options"] = [
            {
                "option_number": 1,
                "title": option_1_title.strip(),
                "summary": option_1_summary.strip(),
                "strategy": option_1_summary.strip(),
                "pros": opt1_p,
                "cons": opt1_c,
                "trade_offs": opt1_tradeoffs
            },
            {
                "option_number": 2,
                "title": option_2_title.strip(),
                "summary": option_2_summary.strip(),
                "strategy": option_2_summary.strip(),
                "pros": opt2_p,
                "cons": opt2_c,
                "trade_offs": opt2_tradeoffs
            }
        ]
        best_title = option_1_title if rec_num == 1 else option_2_title
        triage_result["best_option"] = {
            "recommended_option_number": rec_num,
            "recommended_title": best_title.strip(),
            "reasoning": deep_architectural_reasoning.strip()
        }
        return {"status": "published", "title": best_title, "recommended_option": rec_num}

    agent_instruction = (
        "You are an elite Principal Cloud Security Architect specializing in Infrastructure as Code (Terraform) on Google Cloud Platform.\n"
        "Your role is to analyze Google Cloud Security Command Center (SCC) findings and formulate "
        "declarative Infrastructure-as-Code (Terraform) remediation strategies for platform and security engineering teams.\n\n"
        "STRICT MANDATORY RULES:\n"
        "1. ALL remediation strategies and fix options MUST represent Infrastructure-as-Code (Terraform) configuration changes "
        "(e.g., enabling uniform bucket-level access, enforcing restrictive IAM policy bindings, configuring private Google access or firewall rules, enabling encryption).\n"
        "2. NEVER mention or suggest manual Google Cloud Console clicks, GUI instructions, or imperative CLI commands "
        "(such as `gcloud`, `gsutil`, `bq`, `kubectl`, or shell scripts).\n"
        "3. High-density, concise communication: The initial alert summary must be exactly ONE punchy sentence. Keep option summaries to single sentences and pros/cons to brief bullets.\n"
        "4. Place comprehensive technical rationale, workload blast radius, and CIS/NIST compliance impacts into deep_architectural_reasoning and compliance_and_blast_radius for on-demand inspection.\n"
        "5. Do NOT include code snippets, backtick code fences, or raw Terraform HCL syntax in summaries or titles.\n"
        "6. Explicitly designate which option (1 or 2) is recommended.\n"
        "7. You MUST call the `publish_triage_assessment` tool to deliver your structured findings.\n"
        "8. No fallbacks: perform precise and authoritative analysis."
    )

    triage_agent = Agent(
        name="scc_triage_agent",
        model=model_name,
        instruction=agent_instruction,
        tools=[publish_triage_assessment]
    )

    session_service = InMemorySessionService()
    runner = Runner(
        agent=triage_agent,
        app_name="cloudguard_triage",
        session_service=session_service,
        auto_create_session=True
    )

    user_prompt = f"""
Analyze the following Google Cloud Security Command Center (SCC) finding:

[Finding Details]
- Category/Type: {issue_type}
- Severity: {severity}
- Affected Resource: {resource_name}
- SCC Description: {description}
- SCC Next Steps Guidance: {next_steps}
- Source Properties: {json.dumps(source_properties, default=str)}

Execute the publish_triage_assessment tool with your analysis.
"""

    session_id = f"triage_{sanitize_doc_id(resource_name)}_{int(time.time()*1000)}"
    content = types.Content(role="user", parts=[types.Part.from_text(text=user_prompt)])

    logger.info(f"Running ADK Triage Agent for finding: {issue_type} on {resource_name}")
    raw_output_parts = []
    for event in runner.run(user_id="scc_pipeline", session_id=session_id, new_message=content):
        if event.message and event.message.parts:
            for part in event.message.parts:
                if getattr(part, "text", None):
                    raw_output_parts.append(part.text)

    raw_response_text = "\n".join(raw_output_parts)
    if not triage_result:
        raise RuntimeError(
            f"ADK Triage Agent completed without publishing triage assessment for {issue_type} on {resource_name}. "
            f"Raw output: {raw_response_text[:300]}"
        )

    triage_result["raw_output"] = raw_response_text
    logger.info(f"ADK Triage Agent completed successfully. Recommended: {triage_result.get('best_option', {}).get('recommended_title')}")
    return triage_result


def build_google_chat_payload(
    issue_type: str,
    severity: str,
    resource_name: str,
    ai_analysis: dict,
    project_id: str,
    finding_id: str = "",
    receiver_url: str = ""
) -> Tuple[dict, str]:
    """
    Constructs an interactive Google Chat Card V2 message adhering strictly to:
    - 5-second scannable header and executive summary
    - Clean Option 1 and Option 2 cards with ⭐ AI Recommended badge and concise Pros/Cons
    - Card Exclusivity (contains ONLY 'cardsV2', never top-level 'text')
    - No raw code blocks in chat
    - Interactive links: Fix Option 1, Fix Option 2, Don't Act, Show More Details, and SCC Console
    """
    summary = ai_analysis.get("issue_summary", "No summary provided.")
    fix_options = ai_analysis.get("fix_options", [])
    rec_opt_num = ai_analysis.get("recommended_option_number") or ai_analysis.get("best_option", {}).get("recommended_option_number", 1)
    best_option = ai_analysis.get("best_option", {})
    best_title = best_option.get("recommended_title", "Recommended Option")

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

    scc_console_url = f"https://console.cloud.google.com/security/command-center/findings?project={display_proj}"

    action_buttons = []
    if receiver_url and finding_id:
        action_buttons.append({
            "text": "🛠️ Fix via Option 1",
            "onClick": {
                "openLink": {
                    "url": f"{receiver_url}/?finding_id={finding_id}&option=1"
                }
            }
        })
        action_buttons.append({
            "text": "🛠️ Fix via Option 2",
            "onClick": {
                "openLink": {
                    "url": f"{receiver_url}/?finding_id={finding_id}&option=2"
                }
            }
        })
        action_buttons.append({
            "text": "🛑 Don't Act",
            "onClick": {
                "openLink": {
                    "url": f"{receiver_url}/?finding_id={finding_id}&action=ignore"
                }
            }
        })
        action_buttons.append({
            "text": "🔎 Show More Details",
            "onClick": {
                "openLink": {
                    "url": f"{receiver_url}/?finding_id={finding_id}&action=show_details"
                }
            }
        })
    action_buttons.append({
        "text": "↗️ Open SCC Console",
        "onClick": {
            "openLink": {
                "url": scc_console_url
            }
        }
    })

    # Companion fallback text (USED ONLY IF Card V2 fails after retries)
    fallback_lines = [
        f"{severity_icon} *SecOps Alert:* `{issue_type}` ({severity})",
        f"*Asset:* `{clean_res}` ({asset_type}) | *Project:* `{display_proj}`",
        "",
        f"*Issue & Risk:* {summary}",
        "",
        f"⭐ *Recommended Fix (Option {rec_opt_num}):* *{best_title}*",
        f"_{ai_analysis.get('deep_architectural_reasoning', '')[:200]}..._",
        "",
        "⚡ *Take Action:*"
    ]
    if receiver_url and finding_id:
        fallback_lines.append(f"• [🛠️ Fix via Option 1]({receiver_url}/?finding_id={finding_id}&option=1)")
        fallback_lines.append(f"• [🛠️ Fix via Option 2]({receiver_url}/?finding_id={finding_id}&option=2)")
        fallback_lines.append(f"• [🛑 Don't Act]({receiver_url}/?finding_id={finding_id}&action=ignore)")
        fallback_lines.append(f"• [🔎 Show More Details]({receiver_url}/?finding_id={finding_id}&action=show_details)")
        fallback_lines.append(f"• [↗️ Open SCC Console]({scc_console_url})")
    fallback_markdown_text = "\n".join(fallback_lines)

    # Google Chat Card V2
    card_sections = []

    # Section 1: Executive Overview
    card_sections.append({
        "header": "⚡ Security Issue Overview",
        "widgets": [
            {
                "decoratedText": {
                    "topLabel": f"AFFECTED {asset_type.upper()}",
                    "text": f"<b>{clean_res}</b>",
                    "bottomLabel": f"Project: {display_proj} &nbsp;|&nbsp; Severity: {severity}",
                    "wrapText": True
                }
            },
            {
                "textParagraph": {
                    "text": f"<b>Risk:</b> {summary}"
                }
            }
        ]
    })

    # Section 2: Remediation Options
    option_widgets = []
    for opt in fix_options:
        opt_num = opt.get("option_number", 1)
        opt_title = opt.get("title", f"Option {opt_num}")
        opt_summary = opt.get("summary") or opt.get("strategy") or ""
        pros = opt.get("pros") or []
        cons = opt.get("cons") or []

        is_recommended = (opt_num == rec_opt_num)
        rec_badge = " ⭐ <b>[AI RECOMMENDED]</b>" if is_recommended else ""

        lines = [f"<b>Option {opt_num}: {opt_title}</b>{rec_badge}"]
        if opt_summary:
            lines.append(f"<i>{opt_summary}</i>")
        if pros:
            pros_str = " • " + " • ".join(pros)
            lines.append(f"<font color=\"#2da44e\"><b>Pros:</b></font> {pros_str}")
        if cons:
            cons_str = " • " + " • ".join(cons)
            lines.append(f"<font color=\"#cf222e\"><b>Cons:</b></font> {cons_str}")

        option_widgets.append({
            "textParagraph": {
                "text": "<br>".join(lines)
            }
        })

    card_sections.append({
        "header": "🛠️ Terraform Fix Options",
        "widgets": option_widgets
    })

    # Section 3: One-Click Actions
    card_sections.append({
        "header": "⚡ Take Action",
        "widgets": [
            {
                "buttonList": {
                    "buttons": action_buttons
                }
            }
        ]
    })

    card_v2_payload = {
        "cardsV2": [
            {
                "cardId": f"scc_alert_{sanitize_doc_id(issue_type)}_{finding_id}",
                "card": {
                    "header": {
                        "title": f"{severity_icon} {issue_type}",
                        "subtitle": f"{clean_res} ({asset_type}) • {display_proj}",
                        "imageUrl": "https://www.gstatic.com/images/branding/product/2x/security_48dp.png",
                        "imageType": "CIRCLE"
                    },
                    "sections": card_sections
                }
            }
        ]
    }

    return card_v2_payload, fallback_markdown_text


def dispatch_to_google_chat(webhook_url: str, payload: dict, fallback_text: Optional[str] = None) -> tuple[str, str]:
    """
    Sends the formatted Card V2 message to Google Chat via Incoming Webhook.
    Retries transient 5xx errors so the sleek interactive card is prioritized.
    If the card payload fails after retries, falls back to plain-text markdown.
    Returns (status, details).
    """
    if not webhook_url or not webhook_url.strip():
        logger.info("GOOGLE_CHAT_WEBHOOK_URL is not configured. Notification dispatch skipped.")
        return ("SKIPPED_NOT_CONFIGURED", "Webhook URL empty or not set in environment.")

    last_error = ""
    # Attempt card dispatch with retry for transient webhook/server issues
    for attempt in range(1, 3):
        try:
            resp = requests.post(
                webhook_url.strip(),
                json=payload,
                headers={"Content-Type": "application/json; charset=UTF-8"},
                timeout=10
            )
            if resp.status_code == 200:
                logger.info(f"Successfully dispatched alert card to Google Chat (attempt {attempt})!")
                return ("SUCCESS", "Card posted to Google Chat successfully.")

            last_error = f"HTTP {resp.status_code}: {resp.text[:300]}"
            logger.warning(f"Card post attempt {attempt} failed ({last_error}). Retrying...")
            if resp.status_code >= 500 and attempt < 2:
                time.sleep(2)
                continue
            break
        except Exception as e:
            last_error = str(e)
            logger.warning(f"Card post attempt {attempt} encountered exception: {e}")
            if attempt < 2:
                time.sleep(2)
                continue
            break

    # If card posting failed after retries and fallback text is provided, attempt fallback
    if fallback_text:
        logger.warning(f"Card post failed ({last_error}). Attempting plain-text fallback as backup...")
        try:
            fallback_resp = requests.post(
                webhook_url.strip(),
                json={"text": fallback_text},
                headers={"Content-Type": "application/json; charset=UTF-8"},
                timeout=10
            )
            if fallback_resp.status_code == 200:
                logger.info("Successfully dispatched plain-text fallback to Google Chat!")
                return ("SUCCESS_FALLBACK_TEXT", "Card rejected; fallback plain text posted.")
        except Exception as e:
            logger.error(f"Fallback plain-text post also failed: {e}")

    logger.error(f"Failed to post to Google Chat webhook: {last_error}")
    return ("FAILED", last_error)


@functions_framework.cloud_event
def process_scc_alert(cloud_event):
    """
    Cloud Function (Gen 2) triggered by Pub/Sub messages containing
    Security Command Center (SCC) findings.
    
    1. Parses the incoming Pub/Sub message payload.
    2. Identifies the issue type / category.
    3. Checks user preferences in Firestore ('issue_preferences').
       - If status == 'IGNORED', suppresses alert, skips AI and chat notification.
       - If status == 'NOTIFIED' (or newly auto-registered):
         a) Invokes Vertex AI (Gemini) to generate:
            - Issue summary
            - Terraform remediation options (avoiding gcloud CLI)
            - Best option recommendation & rationale
         b) Dispatches formatted Card V2 message to Google Chat webhook.
         c) Stores enriched alert document with AI plan in Firestore 'alerts'.
    """
    logger.info(f"Received CloudEvent ID: {cloud_event.get('id', 'N/A')}")
    
    # Extract Pub/Sub message data
    event_data = cloud_event.data or {}
    message_wrapper = event_data.get("message", {})
    
    message_id = (
        message_wrapper.get("messageId")
        or cloud_event.get("id")
        or f"msg_{datetime.now(timezone.utc).timestamp()}"
    )
    publish_time = message_wrapper.get("publishTime") or datetime.now(timezone.utc).isoformat()
    raw_b64_data = message_wrapper.get("data")
    
    if not raw_b64_data:
        logger.warning("Pub/Sub message contains no data payload. Skipping.")
        return ("No data in message", 200)

    try:
        decoded_str = base64.b64decode(raw_b64_data).decode("utf-8")
        payload = json.loads(decoded_str)
    except Exception as e:
        logger.error(f"Failed to decode or parse JSON from Pub/Sub payload: {e}")
        return ("Invalid JSON payload", 400)

    # Extract finding attributes
    finding = payload.get("finding", {})
    if not isinstance(finding, dict):
        finding = {}

    issue_type = (
        finding.get("category")
        or payload.get("category")
        or payload.get("issue_type")
        or finding.get("findingClass")
        or "GENERAL_SECURITY_FINDING"
    )
    issue_type = str(issue_type).strip().upper()

    severity = (
        finding.get("severity")
        or payload.get("severity")
        or "HIGH"
    )

    resource_name = (
        finding.get("resourceName")
        or payload.get("resourceName")
        or payload.get("resource")
        or "UNKNOWN_RESOURCE"
    )

    finding_name = finding.get("name", "")
    finding_id = finding_name.split("/")[-1] if finding_name else message_id

    project_id = os.environ.get("PROJECT_ID", "")
    vertex_location = os.environ.get("VERTEX_AI_LOCATION", "europe-west2")
    vertex_model = os.environ.get("VERTEX_AI_MODEL", "gemini-2.5-flash")
    chat_webhook_url = os.environ.get("GOOGLE_CHAT_WEBHOOK_URL", "")

    db = get_firestore_client()

    # Step 1: Check or initialize user preferences in Firestore 'issue_preferences'
    pref_doc_id = sanitize_doc_id(issue_type)
    pref_ref = db.collection("issue_preferences").document(pref_doc_id)
    pref_snapshot = pref_ref.get()

    if pref_snapshot.exists:
        pref_data = pref_snapshot.to_dict() or {}
        configured_status = str(pref_data.get("status", "NOTIFIED")).strip().upper()
        effective_status = "IGNORED" if configured_status == "IGNORED" else "NOTIFIED"
        
        pref_ref.update({
            "total_findings_count": firestore.Increment(1),
            "last_seen_at": firestore.SERVER_TIMESTAMP,
            "last_message_id": message_id
        })
        status_reason = f"Issue type '{issue_type}' is configured as '{effective_status}' in user preferences."
    else:
        # Auto-register new issue type with default status NOTIFIED
        effective_status = "NOTIFIED"
        new_pref = {
            "issue_type": issue_type,
            "status": effective_status,
            "description": f"Security alert preference for issue type '{issue_type}'",
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP,
            "last_seen_at": firestore.SERVER_TIMESTAMP,
            "total_findings_count": 1,
            "last_message_id": message_id
        }
        pref_ref.set(new_pref)
        status_reason = f"New issue type '{issue_type}' auto-registered in preferences with default status 'NOTIFIED'."
        logger.info(f"Auto-registered new issue preference: {issue_type} -> NOTIFIED")

    # Step 2: Handle IGNORED findings
    alert_doc_id = sanitize_doc_id(f"{issue_type}_{finding_id}")
    alert_ref = db.collection("alerts").document(alert_doc_id)

    if effective_status == "IGNORED":
        logger.info(
            f"ALERT IGNORED: Issue '{issue_type}' on '{resource_name}' is set to IGNORED. "
            "Skipping Vertex AI and Google Chat dispatch."
        )
        alert_record = {
            "message_id": message_id,
            "finding_id": finding_id,
            "issue_type": issue_type,
            "severity": severity,
            "resource_name": resource_name,
            "status": "IGNORED",
            "status_reason": status_reason,
            "notification_sent": False,
            "publish_time": publish_time,
            "processed_at": firestore.SERVER_TIMESTAMP,
            "raw_payload": payload
        }
        alert_ref.set(alert_record)
        return (json.dumps({"status": "ignored", "alert_id": alert_doc_id}), 200)

    # Step 3: Enriched Workflow for NOTIFIED Findings via ADK Triage Agent
    logger.info(f"Generating ADK Triage Agent analysis for NOTIFIED finding: {issue_type}")
    ai_analysis = run_scc_triage_agent(
        payload=payload,
        project_id=project_id,
        location=vertex_location,
        model_name=vertex_model
    )

    # Step 4: Build Google Chat Card V2 and dispatch
    receiver_url = os.environ.get("REMEDIATION_RECEIVER_URL", "")
    chat_payload, fallback_text = build_google_chat_payload(
        issue_type=issue_type,
        severity=severity,
        resource_name=resource_name,
        ai_analysis=ai_analysis,
        project_id=project_id,
        finding_id=finding_id,
        receiver_url=receiver_url
    )

    chat_status, chat_details = dispatch_to_google_chat(
        webhook_url=chat_webhook_url,
        payload=chat_payload,
        fallback_text=fallback_text
    )

    # Step 5: Save enriched alert in Firestore 'alerts' collection
    alert_record = {
        "message_id": message_id,
        "finding_id": finding_id,
        "issue_type": issue_type,
        "severity": severity,
        "resource_name": resource_name,
        "status": "NOTIFIED",
        "status_reason": status_reason,
        "notification_sent": True,
        "publish_time": publish_time,
        "processed_at": firestore.SERVER_TIMESTAMP,
        "raw_payload": payload,
        "ai_analysis": {
            "model": vertex_model,
            "location": vertex_location,
            "issue_summary": ai_analysis.get("issue_summary"),
            "recommended_option_number": ai_analysis.get("recommended_option_number", 1),
            "deep_architectural_reasoning": ai_analysis.get("deep_architectural_reasoning"),
            "compliance_and_blast_radius": ai_analysis.get("compliance_and_blast_radius"),
            "fix_options": ai_analysis.get("fix_options"),
            "best_option": ai_analysis.get("best_option"),
            "raw_output": ai_analysis.get("raw_output")
        },
        "google_chat": {
            "dispatch_status": chat_status,
            "dispatch_details": chat_details,
            "message_payload": chat_payload
        }
    }

    alert_ref.set(alert_record)

    logger.info(
        f"ALERT PROCESSED [NOTIFIED]: Issue '{issue_type}' (Severity: {severity}) on '{resource_name}'. "
        f"Stored in alerts/{alert_doc_id}. Chat dispatch: {chat_status}."
    )

    return (
        json.dumps({
            "status": "success",
            "alert_id": alert_doc_id,
            "evaluated_status": "NOTIFIED",
            "chat_dispatch": chat_status
        }),
        200
    )
