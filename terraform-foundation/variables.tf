variable "project_id" {
  description = "The Google Cloud Project ID where Pub/Sub resources will be provisioned."
  type        = string
  default     = "go-capstone-manus"
}

variable "region" {
  description = "The default Google Cloud region for resources."
  type        = string
  default     = "europe-west2"
}

variable "organization_id" {
  description = "The Google Cloud Organization ID hosting Security Command Center (leave empty for standalone project-level SCC)."
  type        = string
  default     = ""
}

variable "pubsub_topic_name" {
  description = "The name of the Pub/Sub topic to receive SCC alert streams."
  type        = string
  default     = "scc-high-alerts-topic"
}

variable "pubsub_subscription_name" {
  description = "The name of the pull subscription used to test and inspect JSON payloads."
  type        = string
  default     = "scc-high-alerts-sub"
}

variable "scc_notification_config_id" {
  description = "Unique identifier for the Security Command Center notification configuration."
  type        = string
  default     = "scc-high-alerts-config"
}

variable "bigquery_dataset_id" {
  description = "The ID of the BigQuery dataset used as the SecOps telemetry data lake."
  type        = string
  default     = "secops_lake"
}

variable "bigquery_table_id" {
  description = "The ID of the BigQuery table storing raw SCC alert payloads."
  type        = string
  default     = "scc_findings_raw"
}

variable "bigquery_subscription_name" {
  description = "The name of the Pub/Sub BigQuery subscription for automatic ingestion."
  type        = string
  default     = "scc-high-alerts-bigquery-sub"
}

variable "cloud_function_name" {
  description = "The name of the Cloud Function processing SCC alerts and storing them in Firestore."
  type        = string
  default     = "scc-alert-router"
}

variable "remediation_receiver_name" {
  description = "The name of the Cloud Run webhook receiver processing user replies from Google Chat."
  type        = string
  default     = "scc-remediation-receiver"
}

variable "google_chat_webhook_url" {
  description = "The Incoming Webhook URL for the Google Chat space to deliver SecOps alerts and remediation plans."
  type        = string
  default     = ""
  sensitive   = true
}

variable "vertex_ai_location" {
  description = "The GCP region for Vertex AI Gemini model calls."
  type        = string
  default     = "europe-west2"
}

variable "vertex_ai_model" {
  description = "The Gemini model name on Vertex AI to generate security summaries and Terraform remediation."
  type        = string
  default     = "gemini-2.5-flash"
}

variable "github_token" {
  description = "Personal Access Token used by the remediation receiver to create branches, commit code, and open Pull Requests."
  type        = string
  default     = ""
  sensitive   = true
}

variable "github_repo" {
  description = "GitHub repository in 'owner/repo' format where remediation PRs should be submitted."
  type        = string
  default     = "manus-go/Capstone"
}

variable "github_base_branch" {
  description = "Target base branch for remediation Pull Requests."
  type        = string
  default     = "main"
}

