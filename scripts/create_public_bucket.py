#!/usr/bin/env python3
"""
Create Public Bucket ACL Test Script
====================================
Creates a Google Cloud Storage (GCS) bucket configured specifically to trigger
the Security Command Center (SCC) finding: 'Public bucket ACL' (PUBLIC_BUCKET_ACL).

Context:
--------
- Detector: PUBLIC_BUCKET_ACL (Security Health Analytics)
- Vulnerability Description:
  "This bucket is public and can be accessed by anyone on the Internet.
   allUsers represents anyone on the Internet, and allAuthenticatedUsers represents
   anyone who is authenticated with a Google Account; neither is constrained to users
   within your organisation."
- Trigger Conditions:
  1. Uniform Bucket-Level Access (UBLA) is disabled (enabled = false) on the bucket,
     which allows legacy bucket/object Access Control Lists (ACLs).
  2. Public Access Prevention (PAP) is set to 'inherited' (not 'enforced').
  3. An ACL entry grants permissions (e.g., READER) to 'allUsers' or 'allAuthenticatedUsers'.

Usage:
------
    # Create with default settings (allUsers, READER, europe-west2)
    python3 scripts/create_public_bucket.py

    # Specify custom bucket name and project
    python3 scripts/create_public_bucket.py --project go-capstone-manus --bucket my-test-public-bucket

    # Use allAuthenticatedUsers instead of allUsers
    python3 scripts/create_public_bucket.py --entity allAuthenticatedUsers

    # Clean up / delete the bucket
    python3 scripts/create_public_bucket.py --bucket my-test-public-bucket --delete
"""

import argparse
import json
import os
import ssl
import sys
import time
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

DEFAULT_PROJECT_ID = os.getenv("GCP_PROJECT_ID") or os.getenv("PROJECT_ID") or "go-capstone-manus"
DEFAULT_LOCATION = os.getenv("GCP_REGION") or "europe-west2"
ADC_PATH = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")


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


def http_request(
    url: str,
    method: str = "GET",
    token: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    timeout: int = 30
) -> Tuple[int, Dict[str, Any]]:
    """Performs HTTP JSON requests against Google Cloud Storage REST API."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            data = json.loads(raw) if raw else {}
            return resp.status, data
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            data = json.loads(raw)
        except Exception:
            data = {"error": raw}
        return e.code, data


def check_anonymous_access(bucket_name: str) -> Tuple[int, str]:
    """Tests if an unauthenticated requester can view the bucket over the internet."""
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}"
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return resp.status, "Publicly Accessible (HTTP 200 OK)"
    except urllib.error.HTTPError as e:
        if e.code == 401 or e.code == 403:
            return e.code, f"Access Restricted ({e.code} Forbidden/Unauthorized)"
        return e.code, f"HTTP {e.code}"
    except Exception as e:
        return 0, str(e)


def delete_bucket(project_id: str, bucket_name: str, token: str):
    """Deletes the test bucket."""
    print(f"\n{YELLOW}Deleting bucket gs://{bucket_name}...{RESET}")
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}?project={project_id}"
    status, resp = http_request(url, method="DELETE", token=token)
    if status in (200, 204):
        print(f"{GREEN}✔ Successfully deleted gs://{bucket_name}{RESET}")
    else:
        print(f"{RED}✖ Failed to delete bucket (HTTP {status}): {resp}{RESET}")


def create_public_acl_bucket(
    project_id: str,
    bucket_name: str,
    location: str,
    entity: str,
    role: str
):
    """Creates a bucket with UBLA disabled and a public ACL entry to trigger PUBLIC_BUCKET_ACL."""
    print(f"\n{BOLD}═════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}   GCS Bucket Creator: Trigger 'Public bucket ACL' (SCC Finding)  {RESET}")
    print(f"{BOLD}═════════════════════════════════════════════════════════════════{RESET}")
    print(f"Project ID: {CYAN}{project_id}{RESET}")
    print(f"Bucket:     {CYAN}gs://{bucket_name}{RESET}")
    print(f"Location:   {CYAN}{location}{RESET}")
    print(f"ACL Entity: {YELLOW}{entity}{RESET}")
    print(f"ACL Role:   {YELLOW}{role}{RESET}")
    print(f"UBLA:       {RED}Disabled (uniformBucketLevelAccess.enabled = false){RESET}")
    print(f"PAP:        {YELLOW}inherited{RESET}")
    print("─" * 65)

    print(f"\n{CYAN}[Step 1] Acquiring GCP OAuth2 credentials...{RESET}")
    try:
        token = get_oauth2_token()
        print(f"{GREEN}✔ Authentication token acquired.{RESET}")
    except Exception as e:
        print(f"{RED}✖ Authentication failed: {e}{RESET}")
        sys.exit(1)

    # 1. Create the bucket with UBLA disabled
    print(f"\n{CYAN}[Step 2] Creating bucket with Uniform Bucket-Level Access DISABLED...{RESET}")
    create_url = f"https://storage.googleapis.com/storage/v1/b?project={project_id}"
    bucket_payload = {
        "name": bucket_name,
        "location": location,
        "iamConfiguration": {
            "uniformBucketLevelAccess": {
                "enabled": False
            },
            "publicAccessPrevention": "inherited"
        },
        "acl": [
            {
                "entity": entity,
                "role": role
            }
        ]
    }

    status, resp = http_request(create_url, method="POST", token=token, payload=bucket_payload)

    if status == 200:
        print(f"{GREEN}✔ Bucket gs://{bucket_name} created with public ACL!{RESET}")
    elif status == 409:
        print(f"{YELLOW}ℹ Bucket gs://{bucket_name} already exists. Applying public ACL to it...{RESET}")
        # Add public ACL directly
        acl_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/acl"
        acl_payload = {
            "entity": entity,
            "role": role
        }
        acl_status, acl_resp = http_request(acl_url, method="POST", token=token, payload=acl_payload)
        if acl_status == 200:
            print(f"{GREEN}✔ Public ACL grant added to existing bucket!{RESET}")
        else:
            print(f"{RED}✖ Failed to apply ACL (HTTP {acl_status}): {acl_resp}{RESET}")
            sys.exit(1)
    else:
        print(f"{RED}✖ Bucket creation failed (HTTP {status}): {resp}{RESET}")
        if "error" in resp and "message" in resp["error"]:
            print(f"  {RED}Detail: {resp['error']['message']}{RESET}")
            if "publicAccessPrevention" in resp["error"]["message"]:
                print(f"  {YELLOW}Note: An Org Policy may enforce Public Access Prevention on this project.{RESET}")
        sys.exit(1)

    # 2. Verify ACL on the bucket
    print(f"\n{CYAN}[Step 3] Verifying Access Control List (ACL) on bucket...{RESET}")
    get_acl_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/acl/{urllib.parse.quote(entity)}"
    acl_stat, acl_data = http_request(get_acl_url, method="GET", token=token)

    if acl_stat == 200:
        print(f"{GREEN}✔ Confirmed ACL grant:{RESET}")
        print(f"    Entity: {BOLD}{acl_data.get('entity')}{RESET}")
        print(f"    Role:   {BOLD}{acl_data.get('role')}{RESET}")
    else:
        print(f"{YELLOW}⚠ Could not verify specific ACL entry (HTTP {acl_stat}): {acl_data}{RESET}")

    # 3. Test unauthenticated anonymous access
    print(f"\n{CYAN}[Step 4] Testing unauthenticated anonymous Internet access...{RESET}")
    anon_code, anon_msg = check_anonymous_access(bucket_name)
    if anon_code == 200:
        print(f"{GREEN}✔ Anonymous Internet access confirmed: {anon_msg}{RESET}")
    else:
        print(f"{YELLOW}ℹ Anonymous query returned {anon_code}: {anon_msg}{RESET}")

    # 4. Display SCC Finding Trigger Summary
    print(f"\n{BOLD}═════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}               SCC FINDING SIMULATION DETAILS                    {RESET}")
    print(f"{BOLD}═════════════════════════════════════════════════════════════════{RESET}")
    print(f"Finding Type:       {RED}{BOLD}PUBLIC_BUCKET_ACL{RESET}")
    print(f"Finding Class:      MISCONFIGURATION")
    print(f"Resource:           //storage.googleapis.com/projects/_/buckets/{bucket_name}")
    print(f"Public Principal:   {YELLOW}{entity}{RESET}")
    print(f"Access Granted:     {role}")
    print(f"\n{BOLD}SCC Explanation:{RESET}")
    print(f"\"This bucket is public and can be accessed by anyone on the Internet.")
    print(f" allUsers represents anyone on the Internet, and allAuthenticatedUsers represents")
    print(f" anyone who is authenticated with a Google Account; neither is constrained to")
    print(f" users within your organisation.\"")
    print("─" * 65)
    print(f"{CYAN}Security Health Analytics will flag this finding during its next scan.{RESET}")
    print(f"To delete when finished testing:")
    print(f"  python3 scripts/create_public_bucket.py --project {project_id} --bucket {bucket_name} --delete")
    print(f"{BOLD}═════════════════════════════════════════════════════════════════\n{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Creates a GCS bucket triggering the 'Public bucket ACL' (PUBLIC_BUCKET_ACL) SCC finding."
    )
    parser.add_argument(
        "--project",
        default=DEFAULT_PROJECT_ID,
        help=f"GCP Project ID (default: {DEFAULT_PROJECT_ID})"
    )
    parser.add_argument(
        "--bucket",
        default=None,
        help="GCS Bucket name (default: public-acl-test-<timestamp>)"
    )
    parser.add_argument(
        "--location",
        default=DEFAULT_LOCATION,
        help=f"Bucket location (default: {DEFAULT_LOCATION})"
    )
    parser.add_argument(
        "--entity",
        choices=["allUsers", "allAuthenticatedUsers"],
        default="allUsers",
        help="Public entity to grant ACL to (default: allUsers)"
    )
    parser.add_argument(
        "--role",
        choices=["READER", "WRITER", "OWNER"],
        default="READER",
        help="ACL role to grant (default: READER)"
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete the specified bucket instead of creating it"
    )

    args = parser.parse_args()

    bucket_name = args.bucket
    if not bucket_name:
        if args.delete:
            print(f"{RED}Error: --bucket is required when using --delete{RESET}")
            sys.exit(1)
        timestamp = int(time.time())
        # Bucket names must be globally unique
        bucket_name = f"public-acl-{args.project}-{timestamp}"

    if args.delete:
        try:
            token = get_oauth2_token()
            delete_bucket(args.project, bucket_name, token)
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")
            sys.exit(1)
    else:
        create_public_acl_bucket(
            project_id=args.project,
            bucket_name=bucket_name,
            location=args.location,
            entity=args.entity,
            role=args.role
        )


if __name__ == "__main__":
    main()
