# CloudGuard Foundation: SCC to Pub/Sub Pipeline

This Terraform module establishes the foundational infrastructure for streaming Google Cloud Security Command Center (SCC) findings into Pub/Sub for automated SecOps triage and GitOps remediation.

## Architecture

```
+------------------------------------+
|  Google Cloud Security Command     |
|  Center (Continuous Export)        |
+-----------------+------------------+
                  |
                  | Filter: ACTIVE & (HIGH | CRITICAL)
                  v
+-----------------+------------------+
|  Pub/Sub Topic                     |
|  (scc-high-alerts-topic)           |
+-----------------+------------------+
                  |
                  v
+-----------------+------------------+
|  Pub/Sub Pull Subscription         |
|  (scc-high-alerts-sub)             |
+------------------------------------+
```

## Resources Provisioned

1. **`google_pubsub_topic.scc_high_alerts_topic`**: Designated topic for active high/critical security findings.
2. **`google_pubsub_subscription.scc_high_alerts_sub`**: Pull subscription for testing, inspecting, and validating SCC JSON payloads.
3. **`google_scc_notification_config.scc_notification_config`**: Organization-level Continuous Export with filter:
   ```hcl
   state = "ACTIVE" AND (severity = "HIGH" OR severity = "CRITICAL")
   ```
4. **`google_pubsub_topic_iam_member.scc_publisher`**: Assigns `roles/pubsub.publisher` on the topic to the native SCC service agent (`google_scc_notification_config.scc_notification_config.service_account`).

## Deployment Instructions

### 1. Configure Variables
Copy `terraform.tfvars.example` to `terraform.tfvars` and specify your GCP Project ID and Organization ID:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:
```hcl
project_id      = "your-gcp-project-id"
organization_id = "your-gcp-org-id"
region          = "europe-west2"
```

### 2. Authenticate with Google Cloud
Ensure your local environment has Application Default Credentials:
```bash
gcloud auth application-default login
```

### 3. Initialize and Apply
```bash
terraform init
terraform plan
terraform apply
```

### 4. Testing the Pull Subscription
To pull messages from the test subscription using `gcloud`:
```bash
gcloud pubsub subscriptions pull scc-high-alerts-sub --auto-ack --limit=1
```
