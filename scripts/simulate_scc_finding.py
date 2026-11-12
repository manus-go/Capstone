#!/usr/bin/env python3
"""
Simulate SCC Finding (Instant Demo & Test Tool)
==============================================
Simulates a Security Command Center (SCC) security finding (e.g. PUBLIC_BUCKET_ACL)
to instantly trigger the CloudGuard SecOps pipeline (Gemini ADK triage -> Google Chat
Card V2 -> GitOps Pull Request) without waiting for Cloud Asset Inventory (CAI) batch
scanning latency.

Dual-Mode Operation:
--------------------
1. Standalone GCP Project Mode (Default):
   In standalone projects lacking an Organization node (organization_id = ""), the SCC
   v1 REST API rejects custom source creation (/v1/projects/{project_id}/sources -> 404).
   This script directly injects the simulated SCC finding notification into the project's
   Continuous Export Pub/Sub topic (`scc-high-alerts-topic`), delivering deterministic,
   instant pipeline execution.

2. Organization Custom Source Mode:
   When an `--org-id` is provided, the script creates or reuses an SCC custom finding source
   under `organizations/{org_id}/sources` and inserts the finding directly into SCC.

Usage:
------
    # 1. Simulate finding with defaults (instant Pub/Sub injection to scc-high-alerts-topic)
    python3 scripts/simulate_scc_finding.py

    # 2. Specify custom finding ID, category, or target resource
    python3 scripts/simulate_scc_finding.py \
        --finding-id demo-finding-01 \
        --category PUBLIC_BUCKET_ACL \
        --resource "//storage.googleapis.com/go-capstone-manus-demo-public-bucket"

    # 3. Simulate with custom topic or severity
    python3 scripts/simulate_scc_finding.py --severity CRITICAL --topic scc-high-alerts-topic

    # 4. Enterprise Org mode (creates finding inside SCC console)
    python3 scripts/simulate_scc_finding.py --org-id 123456789012 --source-name "Demo Source"

    # 5. Mute / resolve the finding when the remediation pipeline completes
    python3 scripts/simulate_scc_finding.py --finding-id demo-finding-01 --mute
"""

import argparse
import base64
from datetime import datetime, timezone
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

# Terminal ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

ADC_PATH = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")


def load_env_defaults():
    """Loads environment variables from .env if present."""
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


load_env_defaults()
DEFAULT_PROJECT_ID = os.getenv("PROJECT_ID") or os.getenv("GCP_PROJECT_ID") or "go-capstone-manus"
DEFAULT_TOPIC = os.getenv("PUB_SUB_TOPIC_NAME") or "scc-high-alerts-topic"
DEFAULT_ORG_ID = os.getenv("ORGANIZATION_ID") or ""


def get_oauth2_token() -> str:
    """Acquires a valid GCP OAuth2 access token via google-auth or local ADC credentials."""
    # Method 1: Try using google-auth if installed
    try:
        import google.auth
        import google.auth.transport.requests

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        request = google.auth.transport.requests.Request()
        credentials.refresh(request)
        if credentials.token:
            return credentials.token
    except Exception:
        pass

    # Method 2: Direct OAuth2 refresh from application_default_credentials.json
    if os.path.exists(ADC_PATH):
        with open(ADC_PATH, "r", encoding="utf-8") as f:
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
            token_data = json.loads(resp.read().decode("utf-8"))
            return token_data["access_token"]

    raise RuntimeError(
        "Could not acquire GCP access token. Please run 'gcloud auth application-default login' "
        "or ensure GOOGLE_APPLICATION_CREDENTIALS is set."
    )


def http_request(url: str, token: str, method: str = "GET", body: Optional[dict] = None) -> Tuple[int, Any]:
    """Issues an authenticated HTTPS request against Google Cloud APIs."""
    ctx = ssl._create_unverified_context()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw_error = e.read().decode("utf-8")
        try:
            error_json = json.loads(raw_error)
        except Exception:
            error_json = {"raw": raw_error}
        return e.code, error_json


def publish_to_pubsub(
    project_id: str,
    topic: str,
    finding_id: str,
    category: str,
    resource_name: str,
    severity: str,
    token: str
) -> str:
    """Publishes a simulated SCC finding notification directly to the Continuous Export Pub/Sub topic."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Payload format matching SCC Continuous Export JSON
    scc_payload = {
        "finding": {
            "name": f"projects/{project_id}/sources/simulation/findings/{finding_id}",
            "parent": f"projects/{project_id}/sources/simulation",
            "resourceName": resource_name,
            "state": "ACTIVE",
            "category": category,
            "severity": severity,
            "findingClass": "MISCONFIGURATION",
            "description": f"Resource {resource_name.split('/')[-1]} has misconfiguration triggering {category}.",
            "eventTime": now_iso,
            "createTime": now_iso,
            "sourceProperties": {
                "Explanation": f"Bucket has public ACL allowing internet-wide unauthenticated access.",
                "Simulation": "Instant demo finding injected directly into Continuous Export Pub/Sub topic."
            }
        },
        "resource": {
            "name": resource_name,
            "projectDisplayName": project_id
        }
    }

    raw_json = json.dumps(scc_payload)
    b64_data = base64.b64encode(raw_json.encode("utf-8")).decode("utf-8")

    publish_url = f"https://pubsub.googleapis.com/v1/projects/{project_id}/topics/{topic}:publish"
    body = {
        "messages": [
            {
                "data": b64_data,
                "attributes": {
                    "finding_id": finding_id,
                    "category": category,
                    "severity": severity,
                    "source": "simulation-tool"
                }
            }
        ]
    }

    print(f"{YELLOW}[*] Injecting finding into Pub/Sub topic 'projects/{project_id}/topics/{topic}'...{RESET}")
    status, res = http_request(publish_url, token, method="POST", body=body)
    if status != 200 or "messageIds" not in res:
        raise RuntimeError(f"Failed to publish to Pub/Sub: HTTP {status} - {json.dumps(res, indent=2)}")

    message_id = res["messageIds"][0]
    print(f"{GREEN}[✓] Successfully published to Pub/Sub topic!{RESET}")
    print(f"    - Message ID:  {message_id}")
    print(f"    - Finding ID:  {finding_id}")
    print(f"    - Category:    {category}")
    print(f"    - Severity:    {severity}")
    print(f"    - Resource:    {resource_name}")
    return message_id


def get_or_create_org_source(org_id: str, token: str, display_name: str = "Demo Source") -> str:
    """Finds existing custom source by display name or creates a new one at organization level."""
    list_url = f"https://securitycenter.googleapis.com/v1/organizations/{org_id}/sources"
    status, res = http_request(list_url, token, method="GET")

    if status == 200 and "sources" in res:
        for s in res["sources"]:
            if s.get("displayName") == display_name:
                print(f"{CYAN}[+] Found existing SCC source:{RESET} {s['name']} ('{display_name}')")
                return s["name"]

    print(f"{YELLOW}[*] Creating new custom SCC source '{display_name}' for organization {org_id}...{RESET}")
    create_url = f"https://securitycenter.googleapis.com/v1/organizations/{org_id}/sources"
    body = {
        "displayName": display_name,
        "description": "Source used for live demonstrations and automated testing"
    }
    status, res = http_request(create_url, token, method="POST", body=body)
    if status not in (200, 201):
        raise RuntimeError(f"Failed to create SCC source: HTTP {status} - {json.dumps(res, indent=2)}")

    source_name = res["name"]
    print(f"{GREEN}[✓] Successfully created SCC source:{RESET} {source_name}")
    return source_name


def create_finding(
    source_name: str,
    finding_id: str,
    category: str,
    resource_name: str,
    severity: str,
    token: str
) -> dict:
    """Directly creates or updates an SCC finding under the specified custom source."""
    url = f"https://securitycenter.googleapis.com/v1/{source_name}/findings?findingId={urllib.parse.quote(finding_id)}"
    event_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    body = {
        "state": "ACTIVE",
        "category": category,
        "resourceName": resource_name,
        "severity": severity,
        "eventTime": event_time,
        "sourceProperties": {
            "Explanation": "Bucket has public ACL allowing internet-wide unauthenticated access.",
            "Simulation": "Instant demo finding created via SecOps test harness."
        }
    }

    print(f"{YELLOW}[*] Injecting instant SCC finding '{finding_id}' into {source_name}...{RESET}")
    status, res = http_request(url, token, method="POST", body=body)
    if status not in (200, 201):
        raise RuntimeError(f"Failed to create SCC finding: HTTP {status} - {json.dumps(res, indent=2)}")

    print(f"{GREEN}[✓] Finding created successfully in SCC!{RESET}")
    print(f"    - Name:     {res.get('name')}")
    print(f"    - Category: {res.get('category')}")
    print(f"    - Severity: {res.get('severity')}")
    print(f"    - State:    {res.get('state')}")
    print(f"    - Resource: {res.get('resourceName')}")
    return res


def mute_finding(source_name: str, finding_id: str, token: str) -> dict:
    """Sets the finding mute state to MUTED via SCC v1 REST API."""
    finding_name = f"{source_name}/findings/{finding_id}"
    url = f"https://securitycenter.googleapis.com/v1/{finding_name}:setMute"
    body = {"mute": "MUTED"}

    print(f"{YELLOW}[*] Setting mute state to MUTED for {finding_name}...{RESET}")
    status, res = http_request(url, token, method="POST", body=body)
    if status != 200:
        raise RuntimeError(f"Failed to mute finding: HTTP {status} - {json.dumps(res, indent=2)}")

    print(f"{GREEN}[✓] Finding successfully muted in SCC!{RESET}")
    return res


def mute_in_firestore(project_id: str, finding_id: str, token: str) -> bool:
    """Sets the remediation status in Firestore 'alerts' collection to DISMISSED_NO_ACTION."""
    try:
        url = (
            f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/"
            f"documents/alerts/{urllib.parse.quote(finding_id)}?updateMask.fieldPaths=remediation_status"
            f"&updateMask.fieldPaths=action_taken&updateMask.fieldPaths=status_reason"
        )
        body = {
            "fields": {
                "remediation_status": {"stringValue": "DISMISSED_NO_ACTION"},
                "action_taken": {"stringValue": "MUTED_VIA_SIMULATOR"},
                "status_reason": {"stringValue": "Alert was muted via simulation CLI."}
            }
        }
        status, res = http_request(url, token, method="PATCH", body=body)
        if status in (200, 201):
            print(f"{GREEN}[✓] Firestore alert record for '{finding_id}' marked as MUTED.{RESET}")
            return True
    except Exception:
        pass
    return False


def set_finding_inactive(source_name: str, finding_id: str, token: str) -> dict:
    """Sets the finding state to INACTIVE."""
    finding_name = f"{source_name}/findings/{finding_id}"
    url = f"https://securitycenter.googleapis.com/v1/{finding_name}?updateMask=state"
    body = {"state": "INACTIVE"}

    print(f"{YELLOW}[*] Setting finding state to INACTIVE for {finding_name}...{RESET}")
    status, res = http_request(url, token, method="PATCH", body=body)
    if status != 200:
        raise RuntimeError(f"Failed to inactivate finding: HTTP {status} - {json.dumps(res, indent=2)}")

    print(f"{GREEN}[✓] Finding state updated to INACTIVE in SCC!{RESET}")
    return res


def main():
    parser = argparse.ArgumentParser(
        description="Simulate an instant SCC Finding for live SecOps pipeline demonstrations."
    )
    parser.add_argument("--project", default=DEFAULT_PROJECT_ID, help="GCP Project ID")
    parser.add_argument("--topic", default=DEFAULT_TOPIC, help="Pub/Sub topic for Continuous Export alerts")
    parser.add_argument("--org-id", default=DEFAULT_ORG_ID, help="GCP Organization ID (if using Org-level SCC custom sources)")
    parser.add_argument("--source-id", default="", help="Numeric Source ID or full source name (optional)")
    parser.add_argument("--source-name", default="Demo Source", help="Display name for custom source")
    parser.add_argument("--finding-id", default=f"demo-finding-{int(datetime.now().timestamp())}", help="Unique Finding ID")
    parser.add_argument("--category", default="PUBLIC_BUCKET_ACL", help="Finding category / detector name")
    parser.add_argument("--resource", default="", help="Resource full URL name (e.g. //storage.googleapis.com/my-bucket)")
    parser.add_argument("--severity", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Finding severity")
    parser.add_argument("--mode", default="auto", choices=["auto", "pubsub", "scc_source"], help="Injection mode")
    parser.add_argument("--mute", action="store_true", help="Mute the specified finding instead of creating it")
    parser.add_argument("--inactive", action="store_true", help="Set the specified finding to INACTIVE")

    args = parser.parse_args()

    resource_name = args.resource
    if not resource_name:
        resource_name = f"//storage.googleapis.com/{args.project}-demo-public-bucket"

    print(f"{BOLD}CloudGuard SecOps - Instant SCC Finding Simulator{RESET}")
    print(f"Project:     {args.project}")
    print(f"Finding ID:  {args.finding_id}")
    print(f"Mode:        {args.mode}")

    try:
        token = get_oauth2_token()
    except Exception as e:
        print(f"{RED}[✗] Authentication error:{RESET} {e}")
        sys.exit(1)

    # Determine whether to use SCC Source API or Direct Pub/Sub Injection
    use_scc_source = False
    if args.mode == "scc_source":
        use_scc_source = True
    elif args.mode == "auto":
        # If organization ID or an explicit source ID is given, attempt SCC source mode;
        # otherwise, standalone GCP projects lack an Org node, so default to Pub/Sub injection.
        if args.org_id or (args.source_id and "organizations/" in args.source_id):
            use_scc_source = True
        else:
            use_scc_source = False

    if args.mute:
        muted_any = False
        if use_scc_source and (args.source_id or args.org_id):
            source_path = args.source_id or f"organizations/{args.org_id}/sources/demo"
            try:
                mute_finding(source_path, args.finding_id, token)
                muted_any = True
            except Exception as e:
                print(f"{YELLOW}[!] SCC mute skipped:{RESET} {e}")

        # Update Firestore alert record
        if mute_in_firestore(args.project, args.finding_id, token):
            muted_any = True

        if not muted_any:
            print(f"{CYAN}[i] Finding {args.finding_id} mute signal acknowledged.{RESET}")
        return

    if args.inactive:
        if use_scc_source and (args.source_id or args.org_id):
            source_path = args.source_id or f"organizations/{args.org_id}/sources/demo"
            set_finding_inactive(source_path, args.finding_id, token)
        else:
            mute_in_firestore(args.project, args.finding_id, token)
        return

    # Create / Trigger Finding
    if use_scc_source:
        try:
            if args.source_id:
                source_path = args.source_id if args.source_id.startswith("organizations/") else f"organizations/{args.org_id}/sources/{args.source_id}"
            else:
                source_path = get_or_create_org_source(args.org_id, token, args.source_name)

            create_finding(
                source_name=source_path,
                finding_id=args.finding_id,
                category=args.category,
                resource_name=resource_name,
                severity=args.severity,
                token=token,
            )
            print(f"\n{BOLD}Pipeline Action Triggered (SCC Source Mode):{RESET}")
            print(f"1. Check the Google Cloud SCC Console (Findings tab) to see the alert.")
            print(f"2. Continuous Export pushes this ACTIVE {args.severity} finding to Pub/Sub topic '{args.topic}'.")
            print(f"3. CloudGuard triage agent will evaluate the finding and dispatch Card V2 to Google Chat.")
            print(f"\nWhen resolved, run:\n  python3 scripts/simulate_scc_finding.py --project {args.project} --finding-id {args.finding_id} --mute")
            return
        except Exception as e:
            if args.mode == "auto":
                print(f"{YELLOW}[!] Organization SCC source creation failed ({e}).{RESET}")
                print(f"{YELLOW}[!] Falling back to Direct Pub/Sub injection mode for standalone project...{RESET}\n")
            else:
                print(f"{RED}[✗] Operation failed:{RESET} {e}")
                sys.exit(1)

    # Standalone Project Mode: Direct Pub/Sub Injection
    print(f"{CYAN}[i] Standalone project environment detected (using direct Pub/Sub injection).{RESET}")
    try:
        publish_to_pubsub(
            project_id=args.project,
            topic=args.topic,
            finding_id=args.finding_id,
            category=args.category,
            resource_name=resource_name,
            severity=args.severity,
            token=token,
        )
        print(f"\n{BOLD}Pipeline Action Triggered (Instant Pub/Sub Mode):{RESET}")
        print(f"1. Pub/Sub notification delivered to 'scc-alert-router' Cloud Function.")
        print(f"2. The Gemini Triage Agent will analyse the misconfiguration and evaluate risk.")
        print(f"3. An interactive Card V2 alert will arrive in Google Chat with progressive disclosure.")
        print(f"4. View telemetry and real-time lifecycle tracking in the SecOps Command Dashboard at /dashboard.")
        print(f"\nWhen resolved, run:\n  python3 scripts/simulate_scc_finding.py --project {args.project} --finding-id {args.finding_id} --mute")
    except Exception as e:
        print(f"{RED}[✗] Pub/Sub injection failed:{RESET} {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
