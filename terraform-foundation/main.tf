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
