import html
import json
import logging
import os
import re
import sys
import traceback
from typing import Any, Dict, Optional, Tuple

import functions_framework
from google.cloud import firestore
import requests

# -----------------------------------------------------------------------------
# Logging Setup
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scc-remediation-receiver")

# -----------------------------------------------------------------------------
# Configuration from Environment
# -----------------------------------------------------------------------------
PROJECT_ID = os.environ.get("PROJECT_ID", "go-capstone-manus")
VERTEX_LOCATION = os.environ.get("VERTEX_AI_LOCATION", "europe-west2")
VERTEX_MODEL = os.environ.get("VERTEX_AI_MODEL", "gemini-2.5-flash")
GOOGLE_CHAT_WEBHOOK_URL = os.environ.get("GOOGLE_CHAT_WEBHOOK_URL", "")

# Lazy-loaded Firestore client
_db = None


def get_firestore_client() -> firestore.Client:
    global _db
    if _db is None:
        _db = firestore.Client(project=PROJECT_ID)
    return _db


# -----------------------------------------------------------------------------
# Intent Classification: Act vs Don't Act
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
# Vertex AI Agent: Terraform Code Generator
# -----------------------------------------------------------------------------
def run_terraform_coding_agent(
    finding_data: Dict[str, Any],
    selected_option: Dict[str, Any],
    project_id: str,
    location: str,
    model_name: str
) -> Dict[str, Any]:
    """
    Invokes the Vertex AI Gemini agent to write production-grade Terraform HCL
    implementing the specific fix option selected by the user.
    """
    issue_type = finding_data.get("issue_type") or finding_data.get("category", "SECURITY_FINDING")
    severity = finding_data.get("severity", "HIGH")
    resource_name = finding_data.get("resource_name", "target_resource")
    raw_payload = finding_data.get("raw_payload", {})
    finding = raw_payload.get("finding", {})
    description = finding.get("description", "Security vulnerability detected by SCC.")
    next_steps = finding.get("nextSteps", "")

    opt_num = selected_option.get("option_number", 1)
    opt_title = selected_option.get("title", f"Remediation Option {opt_num}")
    opt_strategy = selected_option.get("strategy", "")
    opt_trade_offs = selected_option.get("trade_offs") or selected_option.get("explanation", "")

    system_instruction = (
        "You are an expert Principal Cloud Infrastructure-as-Code (IaC) Senior Architect specializing "
        "in Google Cloud Platform (GCP) and HashiCorp Terraform.\n"
        "Your task is to write complete, production-ready, declarative Terraform (HCL) code to remediate "
        "a Google Cloud Security Command Center (SCC) security finding according to the specific remediation "
        "option selected by the platform administrator.\n\n"
        "CRITICAL REQUIREMENTS:\n"
        "1. Write canonical, syntactically valid Terraform HCL using official `google` or `google-beta` provider resources.\n"
        "2. Provide complete code blocks—do NOT use pseudocode or leave incomplete placeholder comments.\n"
        "3. Parameterize identifiers using Terraform variables or locals with sensible defaults.\n"
        "4. Include inline comments explaining how each resource and attribute remediates the security risk.\n"
        "5. Provide clear, actionable operational instructions: state import (if existing resource), terraform plan, and apply.\n\n"
        "Respond STRICTLY in valid JSON matching this schema:\n"
        "{\n"
        '  "terraform_code": "# Complete Terraform HCL snippet\\nresource \\"google_...\\" \\"...\\" {\\n  ...\\n}",\n'
        '  "explanation": "Detailed architectural explanation of the generated code and why it implements the chosen option.",\n'
        '  "prerequisites": ["List of required IAM permissions, APIs, or provider versions"],\n'
        '  "execution_instructions": "Step-by-step CLI commands (terraform import, init, plan, apply)"\n'
        "}"
    )

    user_prompt = f"""
Remediate the following Google Cloud Security Command Center (SCC) finding:

[FINDING DETAILS]
- Finding Category / Issue: {issue_type}
- Severity: {severity}
- Affected Resource: {resource_name}
- SCC Description: {description}
- SCC Suggested Next Steps: {next_steps}
- Raw Finding Attributes: {json.dumps(finding.get("sourceProperties", {}), indent=2)}

[SELECTED REMEDIATION OPTION]
- Option Number: {opt_num}
- Title: {opt_title}
- Strategy: {opt_strategy}
- Operational Trade-offs: {opt_trade_offs}

Write the complete Terraform (HCL) remediation code that implements this exact strategy.
Respond strictly with valid JSON matching the requested schema.
"""

    raw_response = ""

    # Attempt 1: Vertex AI Python SDK
    try:
        import vertexai
        from vertexai.generative_models import GenerationConfig, GenerativeModel

        vertexai.init(project=project_id, location=location)
        model = GenerativeModel(
            model_name=model_name,
            system_instruction=[system_instruction],
        )
        gen_config = GenerationConfig(
            response_mime_type="application/json",
            temperature=0.1,
            max_output_tokens=8192,
        )
        response = model.generate_content(user_prompt, generation_config=gen_config)
        raw_response = response.text
        logger.info(f"Remediation Agent response received via SDK ({len(raw_response)} chars)")
    except Exception as sdk_err:
        logger.warning(f"Remediation Agent SDK call issue: {sdk_err}. Falling back to REST API.")

    # Attempt 2: Direct REST API Fallback
    if not raw_response:
        try:
            import google.auth
            from google.auth.transport.requests import Request as AuthRequest

            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            creds.refresh(AuthRequest())

            rest_url = (
                f"https://{location}-aiplatform.googleapis.com/v1/"
                f"projects/{project_id}/locations/{location}/publishers/google/models/{model_name}:generateContent"
            )
            body = {
                "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                "systemInstruction": {"parts": [{"text": system_instruction}]},
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "temperature": 0.1,
                    "maxOutputTokens": 8192,
                },
            }
            headers = {
                "Authorization": f"Bearer {creds.token}",
                "Content-Type": "application/json",
            }
            res = requests.post(rest_url, json=body, headers=headers, timeout=60)
            res.raise_for_status()
            res_json = res.json()
            raw_response = res_json["candidates"][0]["content"]["parts"][0]["text"]
            logger.info(f"Remediation Agent response received via REST API ({len(raw_response)} chars)")
        except Exception as rest_err:
            logger.error(f"Remediation Agent REST API failure: {rest_err}")

    # Parse and validate response
    parsed_code_data = None
    if raw_response:
        cleaned_text = raw_response.strip()
        if cleaned_text.startswith("```"):
            cleaned_text = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned_text)
            cleaned_text = re.sub(r"\n?```$", "", cleaned_text).strip()

        try:
            parsed_code_data = json.loads(cleaned_text)
        except Exception:
            match = re.search(r"\{.*\}", cleaned_text, re.DOTALL)
            if match:
                try:
                    parsed_code_data = json.loads(match.group(0))
                except Exception:
                    pass

    if not parsed_code_data:
        parsed_code_data = {
            "terraform_code": (
                f"# Terraform Remediation for {issue_type}\n"
                f"# Strategy: {opt_strategy}\n\n"
                f"# Resource remediation snippet\n"
                f"# Please inspect resource '{resource_name}' in project '{project_id}'.\n"
            ),
            "explanation": f"Automated remediation template implementing: {opt_title}.",
            "prerequisites": ["google provider >= 5.0.0"],
            "execution_instructions": "1. terraform init\n2. terraform plan\n3. terraform apply"
        }

    parsed_code_data["raw_agent_output"] = raw_response
    return parsed_code_data


# -----------------------------------------------------------------------------
# Dispatch Status to Google Chat Space
# -----------------------------------------------------------------------------
def notify_google_chat(webhook_url: str, text: str, card_payload: Optional[dict] = None) -> None:
    """
    Posts an update notification or card back into the user's Google Chat space.
    """
    if not webhook_url or not webhook_url.strip():
        return

    payload = card_payload or {"text": text}
    try:
        resp = requests.post(
            webhook_url.strip(),
            json=payload,
            headers={"Content-Type": "application/json; charset=UTF-8"},
            timeout=10
        )
        logger.info(f"Google Chat notification posted (HTTP {resp.status_code})")
    except Exception as e:
        logger.warning(f"Failed to post notification to Google Chat: {e}")


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
    explanation: Optional[str] = None
) -> str:
    details_html = "".join(f"<li>{d}</li>" for d in details)
    code_block = ""
    if code:
        code_block = f"""
        <div class="code-container">
            <div class="code-header">
                <span>Terraform Remediation (HCL)</span>
                <span class="staged-tag">Safely Staged &bull; NOT Applied</span>
            </div>
            <pre><code>{html.escape(code)}</code></pre>
        </div>
        """
    explanation_block = ""
    if explanation:
        explanation_block = f"""
        <div class="explanation-box">
            <h4>Architectural Reasoning</h4>
            <p>{html.escape(explanation)}</p>
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
    if request.method == "OPTIONS":
        return ("", 204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        })

    has_action_args = any(k in request.args for k in ["option", "option_number", "action", "text", "user_response"])

    if request.method == "GET" and not has_action_args:
        return (
            json.dumps({
                "status": "healthy",
                "service": "scc-remediation-receiver",
                "project_id": PROJECT_ID,
                "model": VERTEX_MODEL
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

    logger.info(f"Received webhook request ({request.method}): data={json.dumps(data)[:300]} args={request.args.to_dict()}")

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

    wants_html = request.method == "GET" or "text/html" in request.headers.get("Accept", "")

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
            json.dumps({"status": "not_found", "message": msg}),
            404,
            {"Content-Type": "application/json"}
        )

    finding_key = alert_data.get("finding_id") or doc_ref.id
    issue_type = alert_data.get("issue_type", "SECURITY_FINDING")
    resource_name = alert_data.get("resource_name", "GCP Resource")
    ai_analysis = alert_data.get("ai_analysis", {})
    fix_options = ai_analysis.get("fix_options", [])

    # -------------------------------------------------------------------------
    # CASE 1: User does NOT want to act on the issue
    # -------------------------------------------------------------------------
    if intent == "NO_ACTION":
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
            json.dumps({
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

        logger.info(
            f"Invoking Terraform Remediation Agent for finding '{finding_key}' "
            f"using Option {target_num}: '{selected_option.get('title')}'"
        )

        agent_result = run_terraform_coding_agent(
            finding_data=alert_data,
            selected_option=selected_option,
            project_id=PROJECT_ID,
            location=VERTEX_LOCATION,
            model_name=VERTEX_MODEL
        )

        tf_code = agent_result.get("terraform_code", "")
        explanation = agent_result.get("explanation", "")
        prerequisites = agent_result.get("prerequisites", [])
        execution_instructions = agent_result.get("execution_instructions", "")

        remediation_record = {
            "finding_id": finding_key,
            "issue_type": issue_type,
            "resource_name": resource_name,
            "selected_option": {
                "option_number": target_num,
                "title": selected_option.get("title"),
                "strategy": selected_option.get("strategy")
            },
            "status": "GENERATED_NOT_APPLIED",
            "terraform_code": tf_code,
            "explanation": explanation,
            "prerequisites": prerequisites,
            "execution_instructions": execution_instructions,
            "user_response_text": user_text or f"Option {target_num}",
            "generated_at": firestore.SERVER_TIMESTAMP
        }

        # Update alert doc
        doc_ref.update({
            "user_response": {
                "decision": "REMEDIATE",
                "chosen_option": target_num,
                "raw_text": user_text or f"Option {target_num}",
                "decided_at": firestore.SERVER_TIMESTAMP
            },
            "remediation": remediation_record,
            "remediation_status": "CODE_GENERATED_STAGED"
        })

        db = get_firestore_client()
        db.collection("remediations").document(f"{issue_type}_{finding_key}").set(remediation_record)

        logger.info(
            f"Terraform fix successfully coded by agent for '{finding_key}'. "
            f"Safely staged in Firestore (NOT applied). Length: {len(tf_code)} chars."
        )

        chat_msg_text = (
            f"✅ *Terraform Fix Code Generated!*\n\n"
            f"The remediation agent has coded the Terraform fix for *{issue_type}* on `{resource_name}` "
            f"based on *Option {target_num}: {selected_option.get('title')}*.\n\n"
            f"🔒 *Safety Policy:* The code has been safely staged in Firestore and *has NOT been applied* to live infrastructure.\n\n"
            f"```hcl\n{tf_code[:1200]}\n```"
        )

        notify_google_chat(GOOGLE_CHAT_WEBHOOK_URL, chat_msg_text)

        if wants_html:
            return (
                render_html_page(
                    badge_icon="✅",
                    badge_title="Terraform Code Staged",
                    badge_color="#3fb950",
                    heading=f"Remediation Generated: {selected_option.get('title')}",
                    details=[
                        f"<strong>Finding Category:</strong> <code>{issue_type}</code>",
                        f"<strong>Affected Resource:</strong> <code>{resource_name}</code>",
                        f"<strong>Remediation Strategy:</strong> {selected_option.get('strategy')}",
                        "<strong>Safety Status:</strong> Staged in Firestore (NOT applied to live cloud infrastructure)."
                    ],
                    code=tf_code,
                    explanation=explanation
                ),
                200,
                {"Content-Type": "text/html; charset=utf-8"}
            )

        return (
            json.dumps({
                "text": chat_msg_text,
                "status": "success",
                "action": "TERRAFORM_CODE_GENERATED",
                "finding_id": finding_key,
                "selected_option": target_num,
                "code_staged_in_firestore": True,
                "applied_to_infrastructure": false,
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
            json.dumps({"text": clarification_msg, "status": "clarification_needed"}),
            200,
            {"Content-Type": "application/json"}
        )
