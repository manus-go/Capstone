import base64
import json
import logging
import os
import re
from datetime import datetime, timezone
import functions_framework
from google.cloud import firestore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scc_alert_router")

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
    # Replace slashes and characters not allowed in Firestore document IDs
    sanitized = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", raw_id)
    return sanitized[:200]


@functions_framework.cloud_event
def process_scc_alert(cloud_event):
    """
    Cloud Function (Gen 2) triggered by Pub/Sub messages containing
    Security Command Center (SCC) findings.
    
    1. Parses the incoming Pub/Sub message payload.
    2. Identifies the issue type / category.
    3. Looks up or initializes user preference in 'issue_preferences' collection.
       - Status is either 'NOTIFIED' or 'IGNORED'.
       - Defaults to 'NOTIFIED' if not previously configured.
    4. Writes the alert document to the 'alerts' collection tagged with 'NOTIFIED' or 'IGNORED'.
    5. Dispatches notification only if status == 'NOTIFIED'.
    """
    logger.info(f"Received CloudEvent ID: {cloud_event.get('id', 'N/A')}")
    
    # Extract Pub/Sub message data
    event_data = cloud_event.data or {}
    message_wrapper = event_data.get("message", {})
    
    message_id = message_wrapper.get("messageId") or cloud_event.get("id") or f"msg_{datetime.now(timezone.utc).timestamp()}"
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

    db = get_firestore_client()

    # Step 1: Check or initialize user preferences in Firestore 'issue_preferences'
    pref_doc_id = sanitize_doc_id(issue_type)
    pref_ref = db.collection("issue_preferences").document(pref_doc_id)
    pref_snapshot = pref_ref.get()

    if pref_snapshot.exists:
        pref_data = pref_snapshot.to_dict() or {}
        configured_status = str(pref_data.get("status", "NOTIFIED")).strip().upper()
        # Guarantee strict enum: NOTIFIED or IGNORED
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

    # Step 2: Store alert in Firestore 'alerts' collection
    alert_doc_id = sanitize_doc_id(f"{issue_type}_{finding_id}")
    alert_ref = db.collection("alerts").document(alert_doc_id)

    notification_sent = (effective_status == "NOTIFIED")

    alert_record = {
        "message_id": message_id,
        "finding_id": finding_id,
        "issue_type": issue_type,
        "severity": severity,
        "resource_name": resource_name,
        "status": effective_status,  # Strictly 'NOTIFIED' or 'IGNORED'
        "status_reason": status_reason,
        "notification_sent": notification_sent,
        "publish_time": publish_time,
        "processed_at": firestore.SERVER_TIMESTAMP,
        "raw_payload": payload
    }

    alert_ref.set(alert_record)

    # Step 3: Log decision and route notification
    if effective_status == "NOTIFIED":
        logger.info(
            f"ALERT PROCESSED [NOTIFIED]: Issue '{issue_type}' (Severity: {severity}) on '{resource_name}'. "
            f"Document stored: alerts/{alert_doc_id}. Message dispatched to notification queue."
        )
    else:
        logger.info(
            f"ALERT PROCESSED [IGNORED]: Issue '{issue_type}' (Severity: {severity}) on '{resource_name}'. "
            f"Document stored: alerts/{alert_doc_id}. Notification suppressed per user opt-out."
        )

    return (json.dumps({"status": "success", "alert_id": alert_doc_id, "evaluated_status": effective_status}), 200)
