#!/usr/bin/env python3
"""
Simulate SCC Finding via Custom Source (Instant Demo Tool)
===========================================================
Directly creates a custom Security Command Center (SCC) Finding Source and publishes
an ACTIVE, HIGH-severity security finding (e.g. PUBLIC_BUCKET_ACL) without waiting
for Cloud Asset Inventory (CAI) batch scanning delays.

Why this is needed:
-------------------
SCC runs a mixed-mode scanning model relying on Cloud Asset Inventory (CAI). When creating
real misconfigured cloud resources (like public buckets), there can be a 10-30+ minute lag
before the Security Health Analytics (SHA) scanner sweeps the resource.

By creating a custom finding source and inserting the finding directly:
1. The finding appears immediately in the Google Cloud SCC Console under Findings.
2. SCC Continuous Export evaluates the active finding immediately.
3. Pub/Sub pushes the notification to `scc-high-alerts-topic` instantly, triggering
   the CloudGuard SecOps pipeline (Gemini ADK triage -> Google Chat Card -> GitOps PR).
4. After resolution, the finding can be set to MUTED or INACTIVE.

Usage:
------
    # 1. Create instant demo finding (uses or creates 'Demo Source' automatically)
    python3 scripts/simulate_scc_finding.py

    # 2. Specify custom finding ID, category, or target resource
    python3 scripts/simulate_scc_finding.py \
        --finding-id demo-finding-01 \
        --category PUBLIC_BUCKET_ACL \
        --resource "//storage.googleapis.com/go-capstone-demo-bucket"

    # 3. Mute / resolve the finding when the remediation pipeline completes
    python3 scripts/simulate_scc_finding.py --finding-id demo-finding-01 --mute

    # 4. Set finding to INACTIVE
    python3 scripts/simulate_scc_finding.py --finding-id demo-finding-01 --inactive
"""

import argparse
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
    """Issues an authenticated HTTPS request against the Google Cloud APIs."""
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


def get_or_create_source(project_id: str, token: str, display_name: str = "Demo Source") -> str:
    """Finds existing custom source by display name or creates a new one at project level."""
    list_url = f"https://securitycenter.googleapis.com/v1/projects/{project_id}/sources"
    status, res = http_request(list_url, token, method="GET")

    if status == 200 and "sources" in res:
        for s in res["sources"]:
            if s.get("displayName") == display_name:
                print(f"{CYAN}[+] Found existing SCC source:{RESET} {s['name']} ('{display_name}')")
                return s["name"]

    print(f"{YELLOW}[*] Creating new custom SCC source '{display_name}' for project {project_id}...{RESET}")
    create_url = f"https://securitycenter.googleapis.com/v1/projects/{project_id}/sources"
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
    # SCC Finding create endpoint: POST https://securitycenter.googleapis.com/v1/{source_name}/findings?findingId={finding_id}
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

    print(f"{GREEN}[✓] Finding created successfully!{RESET}")
    print(f"    - Name:     {res.get('name')}")
    print(f"    - Category: {res.get('category')}")
    print(f"    - Severity: {res.get('severity')}")
    print(f"    - State:    {res.get('state')}")
    print(f"    - Resource: {res.get('resourceName')}")
    return res


def mute_finding(source_name: str, finding_id: str, token: str) -> dict:
    """Sets the finding mute state to MUTED."""
    # Endpoint: POST https://securitycenter.googleapis.com/v1/{name=projects/*/sources/*/findings/*}:setMute
    finding_name = f"{source_name}/findings/{finding_id}"
    url = f"https://securitycenter.googleapis.com/v1/{finding_name}:setMute"
    body = {"mute": "MUTED"}

    print(f"{YELLOW}[*] Setting mute state to MUTED for {finding_name}...{RESET}")
    status, res = http_request(url, token, method="POST", body=body)
    if status != 200:
        raise RuntimeError(f"Failed to mute finding: HTTP {status} - {json.dumps(res, indent=2)}")

    print(f"{GREEN}[✓] Finding successfully muted!{RESET}")
    return res


def set_finding_inactive(source_name: str, finding_id: str, token: str) -> dict:
    """Sets the finding state to INACTIVE."""
    finding_name = f"{source_name}/findings/{finding_id}"
    url = f"https://securitycenter.googleapis.com/v1/{finding_name}?updateMask=state"
    body = {"state": "INACTIVE"}

    print(f"{YELLOW}[*] Setting finding state to INACTIVE for {finding_name}...{RESET}")
    status, res = http_request(url, token, method="PATCH", body=body)
    if status != 200:
        raise RuntimeError(f"Failed to inactivate finding: HTTP {status} - {json.dumps(res, indent=2)}")

    print(f"{GREEN}[✓] Finding state updated to INACTIVE!{RESET}")
    return res


def main():
    parser = argparse.ArgumentParser(
        description="Simulate an instant SCC Finding via a custom source for live demonstrations."
    )
    parser.add_argument("--project", default=DEFAULT_PROJECT_ID, help="GCP Project ID")
    parser.add_argument("--source-id", default="", help="Numeric Source ID or full source name (optional)")
    parser.add_argument("--source-name", default="Demo Source", help="Display name for custom source")
    parser.add_argument("--finding-id", default=f"demo-finding-{int(datetime.now().timestamp())}", help="Unique Finding ID")
    parser.add_argument("--category", default="PUBLIC_BUCKET_ACL", help="Finding category / detector name")
    parser.add_argument("--resource", default="", help="Resource full URL name (e.g. //storage.googleapis.com/my-bucket)")
    parser.add_argument("--severity", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Finding severity")
    parser.add_argument("--mute", action="store_true", help="Mute the specified finding instead of creating it")
    parser.add_argument("--inactive", action="store_true", help="Set the specified finding to INACTIVE")

    args = parser.parse_args()

    resource_name = args.resource
    if not resource_name:
        resource_name = f"//storage.googleapis.com/{args.project}-demo-public-bucket"

    print(f"{BOLD}CloudGuard SecOps - Instant SCC Finding Simulator{RESET}")
    print(f"Project:     {args.project}")
    print(f"Finding ID:  {args.finding_id}")

    try:
        token = get_oauth2_token()
    except Exception as e:
        print(f"{RED}[✗] Authentication error:{RESET} {e}")
        sys.exit(1)

    # Determine full source name
    if args.source_id:
        if args.source_id.startswith("projects/"):
            source_path = args.source_id
        elif args.source_id.startswith("sources/"):
            source_path = f"projects/{args.project}/{args.source_id}"
        else:
            source_path = f"projects/{args.project}/sources/{args.source_id}"
    else:
        try:
            source_path = get_or_create_source(args.project, token, args.source_name)
        except Exception as e:
            print(f"{RED}[✗] Source resolution error:{RESET} {e}")
            sys.exit(1)

    try:
        if args.mute:
            mute_finding(source_path, args.finding_id, token)
        elif args.inactive:
            set_finding_inactive(source_path, args.finding_id, token)
        else:
            create_finding(
                source_name=source_path,
                finding_id=args.finding_id,
                category=args.category,
                resource_name=resource_name,
                severity=args.severity,
                token=token,
            )
            print(f"\n{BOLD}Pipeline Action Triggered:{RESET}")
            print(f"1. Check the Google Cloud SCC Console (Findings tab) to see the alert immediately.")
            print(f"2. Continuous Export pushes this ACTIVE {args.severity} finding to Pub/Sub topic 'scc-high-alerts-topic'.")
            print(f"3. CloudGuard triage agent will evaluate the finding and dispatch Card V2 to Google Chat.")
            print(f"\nWhen resolved, run:\n  python3 scripts/simulate_scc_finding.py --project {args.project} --source-id {source_path.split('/')[-1]} --finding-id {args.finding_id} --mute")
    except Exception as e:
        print(f"{RED}[✗] Operation failed:{RESET} {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
