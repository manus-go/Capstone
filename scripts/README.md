# CloudGuard Security Finding Simulation Scripts

This directory contains test and simulation scripts for validating the CloudGuard SecOps automated triage, Google Chat notification, and GitOps remediation pipeline.

---

## 1. Public Bucket ACL (`PUBLIC_BUCKET_ACL`)

The scripts create a Google Cloud Storage (GCS) bucket configured specifically to trigger the Security Command Center (SCC) Security Health Analytics detector: **`PUBLIC_BUCKET_ACL`**.

### Finding Context & Explanation
> **"This bucket is public and can be accessed by anyone on the Internet. `allUsers` represents anyone on the Internet, and `allAuthenticatedUsers` represents anyone who is authenticated with a Google Account; neither is constrained to users within your organisation."**

### Detector Trigger Mechanics
SCC's Security Health Analytics raises this finding when:
1. **Uniform Bucket-Level Access (UBLA) is disabled** (`uniform_bucket_level_access = false`), enabling legacy Access Control Lists (ACLs).
2. **Public Access Prevention (PAP)** is set to `inherited` (not `enforced`).
3. An **ACL entry** explicitly grants permissions (`READER`, `WRITER`, or `OWNER`) to:
   - `allUsers`: Anyone on the Internet (unauthenticated).
   - `allAuthenticatedUsers`: Anyone logged into any Google account (personal or corporate, outside your domain).

---

## Available Scripts

### Option A: Python Script (Recommended)
[`create_public_bucket.py`](./create_public_bucket.py) uses the Google Cloud Storage JSON API and Application Default Credentials (ADC) or `google-auth`. It has zero external binary dependencies (`gcloud` CLI is not required in PATH).

#### Usage

```bash
# 1. Create with defaults (unique bucket name, allUsers, READER, europe-west2)
python3 scripts/create_public_bucket.py

# 2. Specify project, custom bucket name, and location
python3 scripts/create_public_bucket.py \
  --project go-capstone-manus \
  --bucket test-public-bucket-$(date +%s) \
  --location europe-west2

# 3. Test with allAuthenticatedUsers instead of allUsers
python3 scripts/create_public_bucket.py \
  --entity allAuthenticatedUsers \
  --role READER

# 4. Clean up / delete the test bucket after verification
python3 scripts/create_public_bucket.py \
  --project go-capstone-manus \
  --bucket <bucket-name> \
  --delete
```

#### CLI Flags
| Flag | Description | Default | Choices |
| :--- | :--- | :--- | :--- |
| `--project` | Target GCP project ID | `go-capstone-manus` (or `$GCP_PROJECT_ID`) | String |
| `--bucket` | Name of the GCS bucket | `public-acl-<project>-<timestamp>` | String |
| `--location` | GCP region for the bucket | `europe-west2` (or `$GCP_REGION`) | String |
| `--entity` | Public principal to grant ACL | `allUsers` | `allUsers`, `allAuthenticatedUsers` |
| `--role` | Access role granted on ACL | `READER` | `READER`, `WRITER`, `OWNER` |
| `--delete` | Deletes the specified `--bucket` | `false` | Flag |

---

### Option B: Bash Script (`gcloud storage` / `gsutil`)
[`create_public_bucket.sh`](./create_public_bucket.sh) is a shell script leveraging `gcloud storage` (with automatic fallback to `gsutil`).

#### Usage

```bash
# 1. Run with default parameters
./scripts/create_public_bucket.sh

# 2. Pass positional arguments: <bucket-name> <entity> <role>
./scripts/create_public_bucket.sh my-test-bucket allUsers READER

# 3. Clean up / delete with gcloud
gcloud storage rm --recursive gs://my-test-bucket
```

---

## Verifying the Finding in Pipeline

Once the bucket is created:
1. **SCC Detection**: Security Health Analytics scans the project and creates the `PUBLIC_BUCKET_ACL` finding.
2. **Pub/Sub Streaming**: Continuous Export pushes the active high/critical finding to `scc-high-alerts-topic`.
3. **Alert Router Cloud Function**: `scc-alert-router` triages the finding with Vertex AI, records it in Cloud Firestore (`alerts/`), and sends a Card V2 alert to the Google Chat space.
4. **Remediation**: Click the interactive **Code Fix** button in Google Chat or run the remediation receiver to generate a dedicated Git branch and GitHub Pull Request with the declarative Terraform fix.

---

## Declarative Terraform Remediation Reference

Per the CloudGuard IaC Policy, remediations are always declarative Terraform (HCL). The automated fix enforces Uniform Bucket-Level Access and enables Public Access Prevention:

```hcl
resource "google_storage_bucket" "remediated_bucket" {
  name     = var.bucket_name
  project  = var.project_id
  location = var.location

  # Enforce Uniform Bucket-Level Access to eliminate legacy object/bucket ACLs
  uniform_bucket_level_access = true

  # Block all public Internet exposure
  public_access_prevention    = "enforced"
}
```
