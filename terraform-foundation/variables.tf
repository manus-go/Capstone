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
