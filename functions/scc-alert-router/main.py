import base64
import json
import logging
import os
import re
import sys
import traceback
import urllib.parse
from datetime import datetime, timezone

import functions_framework
import requests
from google.cloud import firestore

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
        project_id = os.environ.get("PROJECT_ID", "go-capstone-manus")
        _db_client = firestore.Client(project=project_id)
        logger.info(f"Initialized Firestore client for project: {project_id}")
    return _db_client


def sanitize_doc_id(raw_id: str) -> str:
    """Sanitizes strings to create valid, URL-safe Firestore document IDs."""
    if not raw_id:
        return "unknown"
    sanitized = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", raw_id)
    return sanitized[:200]


def call_vertex_ai(payload: dict, project_id: str, location: str, model_name: str) -> dict:
    """
    Invokes Vertex AI Gemini model to:
    1. Write an issue summary.
    2. Generate Terraform remediation options (avoiding imperative gcloud commands).
    3. Explicitly state which fix option it thinks is best and why.
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

    system_instruction = (
        "You are an elite Principal Cloud Security Architect and GitOps Infrastructure Engineer. "
        "Your role is to analyze Google Cloud Security Command Center (SCC) findings and provide "
        "actionable remediation plans for platform engineering teams. "
        "CRITICAL REQUIREMENT: For all fix options, you MUST generate production-ready, declarative "
        "Terraform (HCL) code snippets (using appropriate google provider resource/data blocks) "
        "instead of imperative gcloud CLI commands where possible. "
        "You must explicitly recommend which fix option is best and provide rigorous GitOps and security reasoning."
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

Respond strictly in JSON matching this exact structure:
{{
  "issue_summary": "Concise 2-3 sentence technical overview of the vulnerability, affected resource, and exploit/breach risk.",
  "fix_options": [
    {{
      "option_number": 1,
      "title": "Clear descriptive name for this remediation option",
      "strategy": "Summary of the approach and architecture change",
      "terraform_code": "# Terraform HCL snippet implementing this fix\\nresource \\"...\\" \\"...\\" {{\\n  ...\\n}}",
      "explanation": "Why this fixes the vulnerability, operational considerations, and trade-offs."
    }},
    {{
      "option_number": 2,
      "title": "Alternative remediation option name",
      "strategy": "Alternative approach summary",
      "terraform_code": "# Terraform HCL snippet implementing this fix\\nresource \\"...\\" \\"...\\" {{\\n  ...\\n}}",
      "explanation": "Why this fixes the vulnerability and how it compares to Option 1."
    }}
  ],
  "best_option": {{
    "recommended_title": "Exact title of the fix option you consider best",
    "reasoning": "Detailed justification explaining why this option is objectively superior (e.g. least privilege, GitOps state immutability, blast-radius containment, defense-in-depth)."
  }}
}}
"""

    raw_response_text = ""

    # Attempt 1: Vertex AI SDK
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
            temperature=0.2,
            max_output_tokens=8192,
        )
        response = model.generate_content(user_prompt, generation_config=gen_config)
        raw_response_text = response.text
        print(f"Vertex AI response received via SDK ({len(raw_response_text)} chars)", flush=True)
    except Exception as sdk_err:
        print(f"Vertex AI SDK call issue: {sdk_err}", file=sys.stderr, flush=True)
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()

    # Attempt 2: Direct Vertex AI REST API (fallback)
    if not raw_response_text:
        try:
            import google.auth
            from google.auth.transport.requests import Request as AuthRequest

            creds, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
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
                    "temperature": 0.2,
                    "maxOutputTokens": 8192,
                },
            }
            req_headers = {
                "Authorization": f"Bearer {creds.token}",
                "Content-Type": "application/json",
            }
            res = requests.post(rest_url, json=body, headers=req_headers, timeout=45)
            if not res.ok:
                print(f"Vertex AI REST error: status={res.status_code}, response={res.text}", file=sys.stderr, flush=True)
            res.raise_for_status()
            res_json = res.json()
            raw_response_text = res_json["candidates"][0]["content"]["parts"][0]["text"]
            print(f"Vertex AI response received via REST API ({len(raw_response_text)} chars)", flush=True)
        except Exception as rest_err:
            print(f"Vertex AI REST exception: {rest_err}", file=sys.stderr, flush=True)
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()

    # Parse JSON structure
    parsed_analysis = None
    if raw_response_text:
        try:
            parsed_analysis = json.loads(raw_response_text)
        except Exception as json_err:
            # Fallback regex extraction if model returned wrapped markdown block
            match = re.search(r"\{.*\}", raw_response_text, re.DOTALL)
            if match:
                try:
                    parsed_analysis = json.loads(match.group(0))
                except Exception:
                    pass

    # Safety fallback if model was unreachable or malformed
    if not parsed_analysis or not isinstance(parsed_analysis, dict):
        logger.warning("Using rule-based fallback analysis structure.")
        parsed_analysis = {
            "issue_summary": (
                f"Security finding '{issue_type}' with severity '{severity}' detected on resource '{resource_name}'. "
                f"{description}"
            ),
            "fix_options": [
                {
                    "option_number": 1,
                    "title": "Declarative Policy Hardening",
                    "strategy": "Apply principle of least privilege using Terraform resource bindings.",
                    "terraform_code": (
                        "# Remediation via Terraform\n"
                        "# Define explicit, restrictive IAM or resource configurations:\n"
                        "resource \"google_storage_bucket_iam_binding\" \"restricted_access\" {\n"
                        f"  bucket = \"{resource_name.split('/')[-1]}\"\n"
                        "  role   = \"roles/storage.objectViewer\"\n"
                        "  members = [\"serviceAccount:app-sa@example.iam.gserviceaccount.com\"]\n"
                        "}\n"
                    ),
                    "explanation": "Removes public exposure and enforces declarative infrastructure tracking in source control."
                }
            ],
            "best_option": {
                "recommended_title": "Declarative Policy Hardening",
                "reasoning": "Enforces least-privilege access and eliminates manual configuration drift via GitOps automation."
            }
        }

    parsed_analysis["raw_output"] = raw_response_text
    return parsed_analysis


def build_google_chat_payload(
    issue_type: str,
    severity: str,
    resource_name: str,
    ai_analysis: dict,
    project_id: str
) -> dict:
    """
    Constructs a Google Chat message containing both a rich Card V2
    and companion Markdown text with:
    1. Issue Summary
    2. Terraform Fix Options
    3. Explicit Best Option Recommendation
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
        "🛠️ *Remediation Options (Terraform):*"
    ]

    for idx, opt in enumerate(fix_options, 1):
        opt_title = opt.get("title", f"Option {idx}")
        tf_code = opt.get("terraform_code", "").strip()
        explanation = opt.get("explanation", "")
        markdown_lines.append(f"\n*{idx}. {opt_title}*")
        if explanation:
            markdown_lines.append(explanation)
        if tf_code:
            markdown_lines.append(f"```hcl\n{tf_code}\n```")

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

    # Section 3: Terraform Fix Options
    option_widgets = []
    for idx, opt in enumerate(fix_options, 1):
        opt_title = opt.get("title", f"Option {idx}")
        strategy = opt.get("strategy", "")
        tf_code = opt.get("terraform_code", "").strip()
        explanation = opt.get("explanation", "")

        option_widgets.append({
            "textParagraph": {
                "text": f"<b>Option {idx}: {opt_title}</b><br><i>{strategy}</i>"
            }
        })

        if tf_code:
            # Code formatted inside pre block
            option_widgets.append({
                "textParagraph": {
                    "text": f"<pre>{tf_code}</pre>"
                }
            })

        if explanation:
            option_widgets.append({
                "textParagraph": {
                    "text": f"<font color=\"#666666\">{explanation}</font>"
                }
            })

    card_sections.append({
        "header": "🛠️ Terraform Remediation Options",
        "widgets": option_widgets
    })

    # Section 4: Quick Action Links
    scc_console_url = f"https://console.cloud.google.com/security/command-center/findings?project={project_id}"
    card_sections.append({
        "header": "🔗 Actions",
        "widgets": [
            {
                "buttonList": {
                    "buttons": [
                        {
                            "text": "View in SCC Console",
                            "onClick": {
                                "openLink": {
                                    "url": scc_console_url
                                }
                            }
                        }
                    ]
                }
            }
        ]
    })

    card_v2_payload = {
        "text": full_markdown_text,
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

    return card_v2_payload


def dispatch_to_google_chat(webhook_url: str, payload: dict) -> tuple[str, str]:
    """
    Sends the formatted message card to Google Chat via Incoming Webhook.
    Returns (status, details).
    """
    if not webhook_url or not webhook_url.strip():
        logger.info("GOOGLE_CHAT_WEBHOOK_URL is not configured. Notification dispatch skipped.")
        return ("SKIPPED_NOT_CONFIGURED", "Webhook URL empty or not set in environment.")

    try:
        resp = requests.post(
            webhook_url.strip(),
            json=payload,
            headers={"Content-Type": "application/json; charset=UTF-8"},
            timeout=10
        )
        if resp.status_code == 200:
            logger.info("Successfully dispatched alert card to Google Chat!")
            return ("SUCCESS", "Message posted to Google Chat successfully.")
        else:
            err_msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
            logger.error(f"Failed to post to Google Chat webhook: {err_msg}")
            return ("FAILED", err_msg)
    except Exception as e:
        err_msg = f"Exception during Google Chat post: {str(e)}"
        logger.error(err_msg)
        return ("ERROR", err_msg)


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

    project_id = os.environ.get("PROJECT_ID", "go-capstone-manus")
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

    # Step 3: Enriched Workflow for NOTIFIED Findings
    logger.info(f"Generating Vertex AI analysis for NOTIFIED finding: {issue_type}")
    ai_analysis = call_vertex_ai(
        payload=payload,
        project_id=project_id,
        location=vertex_location,
        model_name=vertex_model
    )

    # Step 4: Build Google Chat Card V2 and dispatch
    chat_payload = build_google_chat_payload(
        issue_type=issue_type,
        severity=severity,
        resource_name=resource_name,
        ai_analysis=ai_analysis,
        project_id=project_id
    )

    chat_status, chat_details = dispatch_to_google_chat(
        webhook_url=chat_webhook_url,
        payload=chat_payload
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
            "best_option": ai_analysis.get("best_option")
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
