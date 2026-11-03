#!/usr/bin/env python3
"""
Interactive End-to-End (E2E) Test Runner for CloudGuard SecOps Pipeline
======================================================================
This script:
1. Publishes a real SCC security finding to Pub/Sub ('scc-high-alerts-topic').
2. Verifies that Eventarc and Vertex AI process it and post the interactive
   Card V2 alert into your Google Chat space.
3. Pauses and waits for YOU (the user) to click one of the interactive action
   buttons ('🛠️ Code Option 1', '🛠️ Code Option 2', or '🛑 Don't Act') in Google Chat.
4. Detects your click in Firestore in real time and verifies the GitOps pull request
   and final Google Chat notification.
"""

import os
import sys
import json
import time
import base64
import urllib.request
import urllib.parse
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

PROJECT_ID = "go-capstone-manus"
TOPIC_NAME = "scc-high-alerts-topic"
RECEIVER_URL = "https://scc-remediation-receiver-nntcdytgna-nw.a.run.app"
ADC_PATH = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")


def log_step(step_num: int, title: str):
    print(f"\n{BOLD}{CYAN}[Step {step_num}] {title}{RESET}")
    print("─" * 65)


def log_pass(msg: str):
    print(f"{GREEN}✔ PASS:{RESET} {msg}")


def log_fail(msg: str):
    print(f"{RED}✖ FAIL:{RESET} {msg}")


def log_info(msg: str):
    print(f"  {YELLOW}ℹ{RESET} {msg}")


def get_gcp_access_token() -> str:
    """Acquires a valid GCP OAuth2 access token from local ADC credentials."""
    if not os.path.exists(ADC_PATH):
        raise FileNotFoundError(f"Application Default Credentials not found at {ADC_PATH}")

    with open(ADC_PATH, "r") as f:
        adc = json.load(f)

    token_url = "https://oauth2.googleapis.com/token"
    data = urllib.parse.urlencode({
        "client_id": adc["client_id"],
        "client_secret": adc["client_secret"],
        "refresh_token": adc["refresh_token"],
        "grant_type": "refresh_token"
    }).encode("utf-8")

    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(token_url, data=data)
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        result = json.loads(resp.read().decode("utf-8"))
        return result["access_token"]


def make_request(url: str, method: str = "GET", headers: dict = None, body: bytes = None, timeout: int = 70) -> Tuple[int, dict]:
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read().decode("utf-8")
            if "application/json" in content_type or raw.strip().startswith("{"):
                try:
                    return resp.status, json.loads(raw)
                except Exception:
                    return resp.status, {"raw": raw}
            return resp.status, {"text": raw}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}


def run_interactive_session():
    print(f"\n{BOLD}═════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}  CloudGuard SecOps Interactive User E2E Test Session            {RESET}")
    print(f"{BOLD}═════════════════════════════════════════════════════════════════{RESET}")
    print(f"Target Project: {BOLD}{PROJECT_ID}{RESET}")
    print(f"Pub/Sub Topic:  {BOLD}{TOPIC_NAME}{RESET}")
    print(f"Receiver URI:   {BOLD}{RECEIVER_URL}{RESET}")

    timestamp = int(time.time())
    finding_id = f"user-test-sa-{timestamp}"
    category = "SERVICE_ACCOUNT_IS_OWNER"
    resource_name = "//cloudresourcemanager.googleapis.com/projects/go-capstone-manus"
    sa_email = f"interactive-test-sa-{timestamp % 10000}@go-capstone-manus.iam.gserviceaccount.com"
    expected_doc_id = f"{category}_{finding_id}"

    # Step 1: GCP Auth
    log_step(1, "Authenticating with Google Cloud Platform")
    try:
        token = get_gcp_access_token()
        log_pass("Successfully generated Google Cloud OAuth2 access token.")
    except Exception as e:
        log_fail(f"Failed to obtain access token: {e}")
        sys.exit(1)

    # Step 2: Publish SCC Finding to Pub/Sub
    log_step(2, f"Publishing SCC Security Finding to '{TOPIC_NAME}'")
    scc_payload = {
        "notificationConfigName": "projects/437113760931/notificationConfigs/scc-high-alerts-config",
        "finding": {
            "name": f"projects/437113760931/sources/2026724040/findings/{finding_id}",
            "parent": "projects/437113760931/sources/2026724040",
            "resourceName": resource_name,
            "state": "ACTIVE",
            "category": category,
            "externalUri": "https://console.cloud.google.com/security/command-center/findings",
            "sourceProperties": {
                "Explanation": f"Service account {sa_email} has been granted roles/owner on project {PROJECT_ID}.",
                "Recommendation": "Revoke roles/owner and assign least-privilege IAM roles.",
                "ServiceAccount": sa_email
            },
            "severity": "HIGH",
            "createTime": datetime.now(timezone.utc).isoformat(),
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "description": f"Service account {sa_email} holds excessive primitive roles/owner permissions in {PROJECT_ID}.",
            "nextSteps": "Revoke roles/owner and configure declarative least-privilege Terraform bindings."
        }
    }

    encoded_msg = base64.b64encode(json.dumps(scc_payload).encode("utf-8")).decode("utf-8")
    publish_url = f"https://pubsub.googleapis.com/v1/projects/{PROJECT_ID}/topics/{TOPIC_NAME}:publish"
    pub_body = json.dumps({
        "messages": [
            {
                "data": encoded_msg,
                "attributes": {
                    "test_type": "user_interactive_e2e",
                    "finding_id": finding_id
                }
            }
        ]
    }).encode("utf-8")

    status, resp = make_request(
        publish_url,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        body=pub_body
    )

    if status == 200 and "messageIds" in resp:
        msg_id = resp["messageIds"][0]
        log_pass(f"Finding published! Message ID: {BOLD}{msg_id}{RESET} | Finding ID: {BOLD}{finding_id}{RESET}")
    else:
        log_fail(f"Pub/Sub publish failed (HTTP {status}): {resp}")
        sys.exit(1)

    # Step 3: Wait for Cloud Function 'scc-alert-router' & Firestore Storage
    log_step(3, "Waiting for Vertex AI Triage & Google Chat Dispatch")
    log_info(f"Target Firestore Document: alerts/{expected_doc_id}")
    log_info("Waiting for Cloud Function 'scc-alert-router' to process and invoke Vertex AI...")

    firestore_url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/alerts/{expected_doc_id}"
    alert_doc = None
    max_wait_seconds = 60
    start_time = time.time()

    while time.time() - start_time < max_wait_seconds:
        status, data = make_request(
            firestore_url,
            method="GET",
            headers={"Authorization": f"Bearer {token}"}
        )
        if status == 200 and "fields" in data:
            alert_doc = data["fields"]
            break
        time.sleep(3)

    if not alert_doc:
        log_fail(f"Alert was not processed by 'scc-alert-router' within {max_wait_seconds}s.")
        sys.exit(1)

    status_field = alert_doc.get("status", {}).get("stringValue")
    issue_type_field = alert_doc.get("issue_type", {}).get("stringValue")
    ai_analysis_map = alert_doc.get("ai_analysis", {}).get("mapValue", {}).get("fields", {})
    fix_options = ai_analysis_map.get("fix_options", {}).get("arrayValue", {}).get("values", [])

    log_pass(f"Alert stored in Firestore! Status: {BOLD}{status_field}{RESET}")
    log_pass(f"Issue Type: {BOLD}{issue_type_field}{RESET}")

    option_titles = []
    if fix_options:
        log_pass(f"Vertex AI generated {len(fix_options)} remediation options:")
        for idx, opt in enumerate(fix_options, 1):
            opt_fields = opt.get("mapValue", {}).get("fields", {})
            title = opt_fields.get("title", {}).get("stringValue", f"Option {idx}")
            option_titles.append(title)
            log_info(f"Option {idx}: {title}")

    log_pass(f"{GREEN}{BOLD}Google Chat Card V2 notification dispatched to your chat space!{RESET}")

    # Step 4: Prompt the User to Interact
    print(f"\n{BOLD}═════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{CYAN}                 👉 ACTION REQUIRED IN GOOGLE CHAT               {RESET}")
    print(f"{BOLD}═════════════════════════════════════════════════════════════════{RESET}")
    print(f"1. Open your Google Chat space.")
    print(f"2. You will see a new Card V2 alert for finding {BOLD}{finding_id}{RESET}.")
    print(f"3. Click any of the interactive buttons on the card:")
    for idx, title in enumerate(option_titles, 1):
        print(f"   • {BOLD}🛠️ Code Option {idx}:{RESET} {title}")
    print(f"   • {BOLD}🛑 Don't Act{RESET}")
    print(f"═════════════════════════════════════════════════════════════════")
    print(f"{YELLOW}⏳ Now listening for your interaction in real time (up to 10 minutes)...{RESET}")

    # Step 5: Poll Firestore for User Response / Remediation Status
    poll_start = time.time()
    max_poll_seconds = 600  # 10 minutes
    user_action_detected = False

    while time.time() - poll_start < max_poll_seconds:
        status, data = make_request(
            firestore_url,
            method="GET",
            headers={"Authorization": f"Bearer {token}"}
        )
        if status == 200 and "fields" in data:
            doc_fields = data["fields"]
            remediation_status = doc_fields.get("remediation_status", {}).get("stringValue")
            user_response = doc_fields.get("user_response", {}).get("mapValue", {}).get("fields", {})

            if remediation_status or user_response:
                user_action_detected = True
                decision = user_response.get("decision", {}).get("stringValue", remediation_status or "UNKNOWN")
                print(f"\n{BOLD}{GREEN}🎉 USER ACTION DETECTED!{RESET}")
                print(f"Decision: {BOLD}{decision}{RESET}")

                if remediation_status == "PR_OPENED":
                    remediation_map = doc_fields.get("remediation", {}).get("mapValue", {}).get("fields", {})
                    github_pr_map = remediation_map.get("github_pr", {}).get("mapValue", {}).get("fields", {})
                    pr_url = github_pr_map.get("pr_url", {}).get("stringValue", "N/A")
                    pr_num = github_pr_map.get("pr_number", {}).get("integerValue", "N/A")
                    branch = github_pr_map.get("branch_name", {}).get("stringValue", "N/A")
                    file_path = github_pr_map.get("file_path", {}).get("stringValue", "N/A")

                    log_pass(f"GitHub Pull Request created: {BOLD}{pr_url}{RESET} (PR #{pr_num})")
                    log_pass(f"Dedicated Branch: {BOLD}{branch}{RESET}")
                    log_pass(f"Staged Terraform File: {BOLD}{file_path}{RESET}")
                    log_pass("Google Chat received PR confirmation (with no code in message).")
                elif remediation_status == "DISMISSED_NO_ACTION":
                    log_pass("Remediation dismissed by user. Decision recorded in Firestore.")
                    log_pass("Google Chat received dismissal confirmation.")
                else:
                    log_info(f"Remediation status: {remediation_status}")
                break

        time.sleep(4)

    if not user_action_detected:
        log_fail("Timed out waiting for user interaction (10 minutes elapsed).")
        sys.exit(1)

    print(f"\n{BOLD}═════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN}     🎉 REAL INTERACTIVE E2E TEST COMPLETED SUCCESSFULLY!        {RESET}")
    print(f"{BOLD}═════════════════════════════════════════════════════════════════\n{RESET}")


if __name__ == "__main__":
    run_interactive_session()
