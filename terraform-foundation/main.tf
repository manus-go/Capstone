terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
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
}

# -----------------------------------------------------------------------------
# 3. Security Command Center (SCC) Continuous Export Notification Config
# -----------------------------------------------------------------------------
resource "google_scc_notification_config" "scc_notification_config" {
  config_id    = var.scc_notification_config_id
  organization = can(regex("^organizations/", var.organization_id)) ? var.organization_id : "organizations/${var.organization_id}"
  description  = "CloudGuard Agent - Continuous Export of ACTIVE High and Critical findings"
  pubsub_topic = google_pubsub_topic.scc_high_alerts_topic.id

  streaming_config {
    filter = "state = \"ACTIVE\" AND (severity = \"HIGH\" OR severity = \"CRITICAL\")"
  }
}

# -----------------------------------------------------------------------------
# 4. IAM Policy Binding: Native SCC Service Account -> Pub/Sub Publisher
# -----------------------------------------------------------------------------
resource "google_pubsub_topic_iam_member" "scc_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.scc_high_alerts_topic.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_scc_notification_config.scc_notification_config.service_account}"
}
