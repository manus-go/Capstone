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


def run_scc_triage_agent(payload: dict, project_id: str, location: str, model_name: str) -> dict:
    """
    Invokes the Google Agent Development Kit (ADK) autonomous Triage Agent equipped with
    the `publish_triage_assessment` tool to:
    1. Write a technical issue summary.
    2. Formulate declarative Terraform remediation options (strictly avoiding CLI commands).
    3. Determine and justify the objectively best fix option.
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

    def publish_triage_assessment(
        issue_summary: str,
        option_1_title: str,
        option_1_strategy: str,
        option_1_trade_offs: str,
        option_2_title: str,
        option_2_strategy: str,
        option_2_trade_offs: str,
        best_option_title: str,
        best_option_reasoning: str
    ) -> dict:
        """Publishes the structured triage assessment and Terraform remediation options for the security finding.

        Args:
            issue_summary: Concise 2-3 sentence technical overview of the vulnerability, affected resource, and exploit/breach risk.
            option_1_title: Clear descriptive name for the primary Terraform remediation strategy.
            option_1_strategy: Description of the architectural and policy configuration changes in Terraform (no CLI commands or raw code blocks).
            option_1_trade_offs: Operational considerations, pros/cons, and impact on workload or connectivity.
            option_2_title: Alternative Terraform remediation strategy name.
            option_2_strategy: Alternative approach describing the policy or configuration changes in Terraform (no CLI commands or raw code blocks).
            option_2_trade_offs: Operational considerations, pros/cons, and comparison to Option 1.
            best_option_title: Exact title of the fix option considered best.
            best_option_reasoning: Detailed justification explaining why this option is objectively superior.
        """
        triage_result["issue_summary"] = issue_summary
        triage_result["fix_options"] = [
            {
                "option_number": 1,
                "title": option_1_title,
                "strategy": option_1_strategy,
                "trade_offs": option_1_trade_offs
            },
            {
                "option_number": 2,
                "title": option_2_title,
                "strategy": option_2_strategy,
                "trade_offs": option_2_trade_offs
            }
        ]
        triage_result["best_option"] = {
            "recommended_title": best_option_title,
            "reasoning": best_option_reasoning
        }
        return {"status": "published", "title": best_option_title}

    agent_instruction = (
        "You are an elite Principal Cloud Security Architect specializing in Infrastructure as Code (Terraform) on Google Cloud Platform.\n"
        "Your role is to analyze Google Cloud Security Command Center (SCC) findings and formulate "
        "declarative Infrastructure-as-Code (Terraform) remediation strategies for platform and security engineering teams.\n\n"
        "STRICT MANDATORY RULES:\n"
        "1. ALL remediation strategies and fix options MUST represent Infrastructure-as-Code (Terraform) configuration changes "
        "(e.g., enabling uniform bucket-level access, enforcing restrictive IAM policy bindings, configuring private Google access or firewall rules, enabling encryption).\n"
        "2. NEVER mention or suggest manual Google Cloud Console clicks, GUI instructions, or imperative CLI commands "
        "(such as `gcloud`, `gsutil`, `bq`, `kubectl`, or shell scripts).\n"
        "3. In the fix option descriptions and summaries, describe what the architectural and policy changes do in clear, high-level technical terms. "
        "Do NOT include code snippets, backtick code fences, or raw Terraform HCL syntax.\n"
        "4. Explicitly recommend which Terraform fix option is best and provide rigorous security, operational, and architectural reasoning.\n"
        "5. You MUST call the `publish_triage_assessment` tool to deliver your structured findings.\n"
        "6. No fallbacks: perform precise and authoritative analysis."
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
) -> dict:
    """
    Constructs a Google Chat message containing both a rich Card V2
    and companion Markdown text with:
    1. Issue Summary
    2. Remediation Fix Options
    3. Explicit Best Option Recommendation
    4. One-Click Interactive Buttons and Links
    """
    summary = ai_analysis.get("issue_summary", "No summary provided.")
    fix_options = ai_analysis.get("fix_options", [])
    best_option = ai_analysis.get("best_option", {})
    best_title = best_option.get("recommended_title", "Recommended Option")
    best_reason = best_option.get("reasoning", "Adheres to security best practices and least privilege.")

    severity_icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
    }.get(severity.upper(), "⚠️")

    # Plaintext / markdown companion text for push alerts and mobile previews
    markdown_lines = [
        f"{severity_icon} *SecOps Alert:* `{issue_type}` ({severity})",
        f"*Resource:* `{resource_name}`",
        f"*Project:* `{project_id}`",
        "",
        "📋 *Issue Summary:*",
        summary,
        "",
        f"⭐ *Recommended Fix (AI Choice):* *{best_title}*",
        f"_{best_reason}_",
        "",
        "🛠️ *Fix Options:*"
    ]

    for idx, opt in enumerate(fix_options, 1):
        opt_title = opt.get("title", f"Option {idx}")
        strategy = opt.get("strategy", "")
        trade_offs = opt.get("trade_offs") or opt.get("explanation") or ""
        markdown_lines.append(f"\n*{idx}. {opt_title}*")
        if strategy:
            markdown_lines.append(strategy)
        if trade_offs:
            markdown_lines.append(f"_Trade-offs & Considerations:_ {trade_offs}")

    markdown_lines.append("\n⚡ *Take Action (Click below or reply):*")
    if receiver_url and finding_id:
        for idx, opt in enumerate(fix_options, 1):
            opt_num = opt.get("option_number", idx)
            opt_title = opt.get("title", f"Option {opt_num}")
            markdown_lines.append(f"• [🛠️ Code Fix Option {opt_num} ({opt_title})]({receiver_url}/?finding_id={finding_id}&option={opt_num})")
        markdown_lines.append(f"• [🛑 Don't Act (Ignore Finding)]({receiver_url}/?finding_id={finding_id}&action=ignore)")
    else:
        markdown_lines.append("• Reply *\"Option 1\"* or *\"Option 2\"* to have the agent code the Terraform fix (safely staged).")
        markdown_lines.append("• Reply *\"Don't act\"* or *\"Ignore\"* if you do not want to take action on this issue.")

    full_markdown_text = "\n".join(markdown_lines)

    # Google Chat Card V2
    card_sections = []

    # Section 1: Executive Summary
    card_sections.append({
        "header": "📋 Issue Summary",
        "widgets": [
            {
                "textParagraph": {
                    "text": f"<b>Resource:</b> <code>{resource_name}</code><br><br>{summary}"
                }
            }
        ]
    })

    # Section 2: Best Fix Recommendation (Highlighted)
    card_sections.append({
        "header": "⭐ Best Fix Recommendation (AI Choice)",
        "widgets": [
            {
                "decoratedText": {
                    "topLabel": "AI RECOMMENDED REMEDIATION",
                    "text": f"<b>{best_title}</b>",
                    "wrapText": True
                }
            },
            {
                "textParagraph": {
                    "text": f"<b>Why this is best:</b><br>{best_reason}"
                }
            }
        ]
    })

    # Section 3: Fix Options
    option_widgets = []
    for idx, opt in enumerate(fix_options, 1):
        opt_title = opt.get("title", f"Option {idx}")
        strategy = opt.get("strategy", "")
        trade_offs = opt.get("trade_offs") or opt.get("explanation") or ""

        text_content = f"<b>Option {idx}: {opt_title}</b>"
        if strategy:
            text_content += f"<br>{strategy}"
        if trade_offs:
            text_content += f"<br><font color=\"#555555\"><i>Trade-offs:</i> {trade_offs}</font>"

        option_widgets.append({
            "textParagraph": {
                "text": text_content
            }
        })

    card_sections.append({
        "header": "🛠️ Fix Options",
        "widgets": option_widgets
    })

    # Section 4: Reply Instructions
    card_sections.append({
        "header": "⚡ Next Steps / Reply Options",
        "widgets": [
            {
                "textParagraph": {
                    "text": (
                        "💬 <b>How to respond:</b><br>"
                        "• Click a button below or reply with <b>\"Option 1\"</b> / <b>\"Option 2\"</b> to have the agent write the Terraform code.<br>"
                        "• Click <b>\"Don't Act\"</b> or reply with <b>\"Don't act\"</b> to dismiss."
                    )
                }
            }
        ]
    })

    # Section 5: Action Buttons (Interactive Links)
    scc_console_url = f"https://console.cloud.google.com/security/command-center/findings?project={project_id}"
    action_buttons = []
    if receiver_url and finding_id:
        for idx, opt in enumerate(fix_options, 1):
            opt_num = opt.get("option_number", idx)
            action_buttons.append({
                "text": f"🛠️ Code Option {opt_num}",
                "onClick": {
                    "openLink": {
                        "url": f"{receiver_url}/?finding_id={finding_id}&option={opt_num}"
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
        "text": "View in SCC Console",
        "onClick": {
            "openLink": {
                "url": scc_console_url
            }
        }
    })

    card_sections.append({
        "header": "🔗 One-Click Actions",
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
                "cardId": f"scc_alert_{sanitize_doc_id(issue_type)}",
                "card": {
                    "header": {
                        "title": f"{severity_icon} Security Alert: {issue_type}",
                        "subtitle": f"Severity: {severity} | Project: {project_id}",
                        "imageUrl": "https://www.gstatic.com/images/branding/product/2x/security_48dp.png",
                        "imageType": "CIRCLE"
                    },
                    "sections": card_sections
                }
            }
        ]
    }

    return card_v2_payload, full_markdown_text


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
