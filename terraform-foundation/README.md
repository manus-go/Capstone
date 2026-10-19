# CloudGuard Foundation: SCC to Pub/Sub, BigQuery & Firestore Pipeline

This Terraform module establishes the foundational infrastructure for streaming Google Cloud Security Command Center (SCC) findings into Pub/Sub for automated SecOps triage, BigQuery telemetry storage, and intelligent Firestore alert routing with user opt-out preferences.

## Architecture

```
+------------------------------------+
|  Google Cloud Security Command     |
|  Center (Continuous Export)        |
+-----------------+------------------+
                  | Filter: ACTIVE & (HIGH | CRITICAL)
                  v
+-----------------+------------------+
|  Pub/Sub Topic                     |
|  (scc-high-alerts-topic)           |
+--------+-----------------+---------+
         |                 |         |
         v                 v         v
+--------+-------+  +------+------+  +-----------------------------+
| Pull           |  | BigQuery    |  | Cloud Function (Gen 2)      |
| Subscription   |  | Ingestion   |  | (scc-alert-router)          |
| (test payload) |  | Table       |  +--------------+--------------+
+----------------+  +-------------+                 |
                                                    v
                                     +--------------+--------------+
                                     | Cloud Firestore Database    |
                                     | - issue_preferences         |
                                     | - alerts (NOTIFIED/IGNORED) |
                                     +-----------------------------+
```

## Resources Provisioned

1. **`google_pubsub_topic.scc_high_alerts_topic`**: Designated topic for active high/critical security findings.
2. **`google_pubsub_subscription.scc_high_alerts_sub`**: Pull subscription for testing, inspecting, and validating SCC JSON payloads.
3. **`google_scc_project_notification_config.scc_project_notification_config`**: Continuous Export with filter:
   ```hcl
   state = "ACTIVE" AND (severity = "HIGH" OR severity = "CRITICAL")
   ```
4. **`google_bigquery_dataset.secops_lake`** & **`google_bigquery_table.scc_findings_raw`**: Day-partitioned BigQuery data lake storing all raw finding payloads.
5. **`google_pubsub_subscription.scc_high_alerts_bigquery_sub`**: Native BigQuery subscription streaming findings directly into the data lake.
6. **`google_firestore_database.default`**: Firestore Native database storing alert history and issue preferences.
7. **`google_cloudfunctions2_function.scc_alert_router`**: Python Cloud Function triggered by `scc-high-alerts-topic` that evaluates alert categories against user opt-out preferences:
   - **`issue_preferences` Collection**: Catalogs each issue type (e.g. `PUBLIC_BUCKET_ACL`, `OPEN_FIREWALL`) with status `NOTIFIED` or `IGNORED`. New issue types auto-register as `NOTIFIED`.
   - **`alerts` Collection**: Stores every finding tagged with evaluated `status: "NOTIFIED"` or `status: "IGNORED"`. Downstream notifications are suppressed for ignored issue types.

## Deployment Instructions

### 1. Configure Variables
Copy `terraform.tfvars.example` to `terraform.tfvars` and specify your GCP Project ID and Organization ID:

```bash
cp terraform.tfvars.example terraform.tfvars
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

### 4. Opting Out of Issue Types in Firestore
To opt out of receiving notifications for a specific issue type (e.g. `PUBLIC_BUCKET_ACL`):
1. Navigate to Firestore in Google Cloud Console.
2. Open the `issue_preferences` collection.
3. Select the document for the issue type and update the `status` field from `NOTIFIED` to `IGNORED`.
4. Subsequent alerts matching that issue type will be recorded in `alerts` with `status: "IGNORED"` and `notification_sent: false`.
