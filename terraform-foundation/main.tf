terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "google" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

data "google_project" "current" {
  project_id = var.project_id
}

# -----------------------------------------------------------------------------
# 0. Enable Required GCP APIs
# -----------------------------------------------------------------------------
resource "google_project_service" "securitycenter" {
  project                    = var.project_id
  service                    = "securitycenter.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "pubsub" {
  project                    = var.project_id
  service                    = "pubsub.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "bigquery" {
  project                    = var.project_id
  service                    = "bigquery.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "firestore" {
  project                    = var.project_id
  service                    = "firestore.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "cloudfunctions" {
  project                    = var.project_id
  service                    = "cloudfunctions.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "cloudbuild" {
  project                    = var.project_id
  service                    = "cloudbuild.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "run" {
  project                    = var.project_id
  service                    = "run.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "artifactregistry" {
  project                    = var.project_id
  service                    = "artifactregistry.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "eventarc" {
  project                    = var.project_id
  service                    = "eventarc.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

locals {
  is_org_level = var.organization_id != null && var.organization_id != ""
  clean_org_id = replace(var.organization_id, "organizations/", "")

  # Deterministic Google SCC notification service agent address
  scc_service_account = local.is_org_level ? "service-org-${local.clean_org_id}@gcp-sa-scc-notification.iam.gserviceaccount.com" : "service-${data.google_project.current.number}@gcp-sa-scc-notification.iam.gserviceaccount.com"
}

# -----------------------------------------------------------------------------
# 1. Pub/Sub Topic for SCC Findings
# -----------------------------------------------------------------------------
resource "google_pubsub_topic" "scc_high_alerts_topic" {
  name    = var.pubsub_topic_name
  project = var.project_id

  labels = {
    environment = "sandbox"
    managed_by  = "terraform"
    system      = "cloudguard-agent"
  }

  depends_on = [google_project_service.pubsub]
}

# -----------------------------------------------------------------------------
# 2. Pub/Sub Pull Subscription for Testing JSON Payloads
# -----------------------------------------------------------------------------
resource "google_pubsub_subscription" "scc_high_alerts_sub" {
  name    = var.pubsub_subscription_name
  project = var.project_id
  topic   = google_pubsub_topic.scc_high_alerts_topic.name

  # Pull subscription configuration
  ack_deadline_seconds       = 20
  message_retention_duration = "604800s" # 7 days
  retain_acked_messages      = false

  expiration_policy {
    ttl = "2678400s" # 31 days
  }

  labels = {
    environment = "sandbox"
    managed_by  = "terraform"
    system      = "cloudguard-agent"
  }

  depends_on = [google_pubsub_topic.scc_high_alerts_topic]
}

# -----------------------------------------------------------------------------
# 3. IAM Policy Binding: Native SCC Service Account -> Pub/Sub Publisher
# Must be created BEFORE Notification Config so GCP validation passes
# -----------------------------------------------------------------------------
resource "google_pubsub_topic_iam_member" "scc_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.scc_high_alerts_topic.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${local.scc_service_account}"

  depends_on = [google_pubsub_topic.scc_high_alerts_topic]
}

# -----------------------------------------------------------------------------
# 4. Security Command Center (SCC) Continuous Export Notification Config
# -----------------------------------------------------------------------------

# Organization-level continuous export (used when organization_id is provided)
resource "google_scc_notification_config" "scc_org_notification_config" {
  count        = local.is_org_level ? 1 : 0
  config_id    = var.scc_notification_config_id
  organization = can(regex("^organizations/", var.organization_id)) ? var.organization_id : "organizations/${var.organization_id}"
  description  = "CloudGuard Agent - Continuous Export of ACTIVE High and Critical findings (Org-level)"
  pubsub_topic = google_pubsub_topic.scc_high_alerts_topic.id

  streaming_config {
    filter = "state = \"ACTIVE\" AND (severity = \"HIGH\" OR severity = \"CRITICAL\")"
  }

  depends_on = [
    google_project_service.securitycenter,
    google_pubsub_topic.scc_high_alerts_topic,
    google_pubsub_topic_iam_member.scc_publisher
  ]
}

# Project-level continuous export (used for standalone projects without an organization)
resource "google_scc_project_notification_config" "scc_project_notification_config" {
  count        = local.is_org_level ? 0 : 1
  config_id    = var.scc_notification_config_id
  project      = var.project_id
  description  = "CloudGuard Agent - Continuous Export of ACTIVE High and Critical findings (Project-level)"
  pubsub_topic = google_pubsub_topic.scc_high_alerts_topic.id

  streaming_config {
    filter = "state = \"ACTIVE\" AND (severity = \"HIGH\" OR severity = \"CRITICAL\")"
  }

  depends_on = [
    google_project_service.securitycenter,
    google_pubsub_topic.scc_high_alerts_topic,
    google_pubsub_topic_iam_member.scc_publisher
  ]
}

# Ensure the actual service account assigned by GCP to the notification config has publisher permissions
resource "google_pubsub_topic_iam_member" "scc_project_exported_publisher" {
  count   = local.is_org_level ? 0 : 1
  project = var.project_id
  topic   = google_pubsub_topic.scc_high_alerts_topic.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_scc_project_notification_config.scc_project_notification_config[0].service_account}"
}

locals {
  scc_notification_id = local.is_org_level ? try(google_scc_notification_config.scc_org_notification_config[0].id, "") : try(google_scc_project_notification_config.scc_project_notification_config[0].id, "")
}

# -----------------------------------------------------------------------------
# 5. BigQuery Data Lake for SecOps Telemetry & Finding Payloads
# -----------------------------------------------------------------------------
resource "google_bigquery_dataset" "secops_lake" {
  dataset_id                  = var.bigquery_dataset_id
  friendly_name               = "SecOps Security Lake"
  description                 = "Data lake storing raw and processed Security Command Center alerts and GitOps remediation records."
  location                    = var.region
  default_table_expiration_ms = null
  project                     = var.project_id

  labels = {
    environment = "sandbox"
    managed_by  = "terraform"
    system      = "cloudguard-agent"
  }

  depends_on = [google_project_service.bigquery]
}

resource "google_bigquery_table" "scc_findings_raw" {
  dataset_id          = google_bigquery_dataset.secops_lake.dataset_id
  table_id            = var.bigquery_table_id
  project             = var.project_id
  description         = "Raw Security Command Center findings streamed automatically from Pub/Sub."
  deletion_protection = false

  time_partitioning {
    type  = "DAY"
    field = "publish_time"
  }

  labels = {
    environment = "sandbox"
    managed_by  = "terraform"
    system      = "cloudguard-agent"
  }

  schema = jsonencode([
    {
      name        = "subscription_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "The Pub/Sub subscription name that delivered the finding"
    },
    {
      name        = "message_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "The unique Pub/Sub message ID"
    },
    {
      name        = "publish_time"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "The timestamp when the finding was published to Pub/Sub"
    },
    {
      name        = "data"
      type        = "JSON"
      mode        = "NULLABLE"
      description = "Raw JSON Security Command Center finding payload"
    },
    {
      name        = "attributes"
      type        = "JSON"
      mode        = "NULLABLE"
      description = "JSON representation of message attributes"
    }
  ])

  depends_on = [google_bigquery_dataset.secops_lake]
}

# Grant Pub/Sub Service Agent Data Editor on the BigQuery Dataset
resource "google_bigquery_dataset_iam_member" "pubsub_bigquery_data_editor" {
  dataset_id = google_bigquery_dataset.secops_lake.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"

  depends_on = [google_bigquery_dataset.secops_lake]
}

# -----------------------------------------------------------------------------
# 6. Pub/Sub BigQuery Subscription (Automatic Stream Ingestion)
# -----------------------------------------------------------------------------
resource "google_pubsub_subscription" "scc_high_alerts_bigquery_sub" {
  name    = var.bigquery_subscription_name
  project = var.project_id
  topic   = google_pubsub_topic.scc_high_alerts_topic.name

  bigquery_config {
    table            = "${google_bigquery_table.scc_findings_raw.project}.${google_bigquery_table.scc_findings_raw.dataset_id}.${google_bigquery_table.scc_findings_raw.table_id}"
    use_topic_schema = false
    write_metadata   = true
  }

  labels = {
    environment = "sandbox"
    managed_by  = "terraform"
    system      = "cloudguard-agent"
  }

  depends_on = [
    google_pubsub_topic.scc_high_alerts_topic,
    google_bigquery_table.scc_findings_raw,
    google_bigquery_dataset_iam_member.pubsub_bigquery_data_editor
  ]
}

# -----------------------------------------------------------------------------
# 7. Firestore Database for Alert Preferences and Processed Findings
# -----------------------------------------------------------------------------
resource "google_firestore_database" "default" {
  project                 = var.project_id
  name                    = "(default)"
  location_id             = var.region
  type                    = "FIRESTORE_NATIVE"
  delete_protection_state = "DELETE_PROTECTION_DISABLED"
  deletion_policy         = "DELETE"

  depends_on = [google_project_service.firestore]
}

# -----------------------------------------------------------------------------
# 8. Storage Bucket & Code Archive for Cloud Function Source
# -----------------------------------------------------------------------------
resource "google_storage_bucket" "function_source" {
  name                        = "${var.project_id}-gcf-source"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
  force_destroy               = true

  labels = {
    environment = "sandbox"
    managed_by  = "terraform"
    system      = "cloudguard-agent"
  }
}

data "archive_file" "function_source" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/scc-alert-router"
  output_path = "${path.module}/scc-alert-router.zip"
}

resource "google_storage_bucket_object" "function_zip" {
  name   = "scc-alert-router-${data.archive_file.function_source.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.function_source.output_path
}

# -----------------------------------------------------------------------------
# 9. Cloud Function Service Account & IAM Roles
# -----------------------------------------------------------------------------
resource "google_service_account" "alert_router" {
  account_id   = "scc-alert-router-sa"
  display_name = "SCC Alert Router Service Account"
  project      = var.project_id
}

resource "google_project_iam_member" "alert_router_datastore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.alert_router.email}"
}

resource "google_project_iam_member" "alert_router_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.alert_router.email}"
}

resource "google_project_iam_member" "alert_router_event_receiver" {
  project = var.project_id
  role    = "roles/eventarc.eventReceiver"
  member  = "serviceAccount:${google_service_account.alert_router.email}"
}

resource "google_project_iam_member" "alert_router_run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:${google_service_account.alert_router.email}"
}

resource "google_project_iam_member" "pubsub_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

# -----------------------------------------------------------------------------
# 10. Cloud Function (Gen 2) Subscribed to Pub/Sub Topic
# -----------------------------------------------------------------------------
resource "google_cloudfunctions2_function" "scc_alert_router" {
  name        = var.cloud_function_name
  location    = var.region
  project     = var.project_id
  description = "Evaluates SCC alerts from Pub/Sub against user preferences and stores them in Firestore."

  build_config {
    runtime     = "python311"
    entry_point = "process_scc_alert"
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.function_zip.name
      }
    }
  }

  service_config {
    max_instance_count    = 5
    min_instance_count    = 0
    available_memory      = "256M"
    timeout_seconds       = 60
    service_account_email = google_service_account.alert_router.email
    environment_variables = {
      PROJECT_ID = var.project_id
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.scc_high_alerts_topic.id
    retry_policy          = "RETRY_POLICY_DO_NOT_RETRY"
    service_account_email = google_service_account.alert_router.email
  }

  labels = {
    environment = "sandbox"
    managed_by  = "terraform"
    system      = "cloudguard-agent"
  }

  depends_on = [
    google_project_service.cloudfunctions,
    google_project_service.run,
    google_project_service.artifactregistry,
    google_project_service.cloudbuild,
    google_project_service.eventarc,
    google_project_iam_member.pubsub_token_creator,
    google_project_iam_member.alert_router_event_receiver,
    google_firestore_database.default
  ]
}


