output "pubsub_topic_id" {
  description = "The fully qualified ID of the Pub/Sub topic."
  value       = google_pubsub_topic.scc_high_alerts_topic.id
}

output "pubsub_topic_name" {
  description = "The name of the Pub/Sub topic."
  value       = google_pubsub_topic.scc_high_alerts_topic.name
}

output "pubsub_subscription_id" {
  description = "The fully qualified ID of the pull subscription."
  value       = google_pubsub_subscription.scc_high_alerts_sub.id
}

output "pubsub_subscription_name" {
  description = "The name of the pull subscription."
  value       = google_pubsub_subscription.scc_high_alerts_sub.name
}

output "scc_notification_config_id" {
  description = "The resource ID of the SCC continuous export notification config."
  value       = local.scc_notification_id
}

output "scc_service_account" {
  description = "The native Security Command Center service account used to publish alerts."
  value       = local.is_org_level ? try(google_scc_notification_config.scc_org_notification_config[0].service_account, local.scc_service_account) : try(google_scc_project_notification_config.scc_project_notification_config[0].service_account, local.scc_service_account)
}

output "bigquery_dataset_id" {
  description = "The ID of the BigQuery SecOps telemetry dataset."
  value       = google_bigquery_dataset.secops_lake.dataset_id
}

output "bigquery_table_id" {
  description = "The ID of the BigQuery table storing raw findings."
  value       = google_bigquery_table.scc_findings_raw.table_id
}

output "bigquery_subscription_name" {
  description = "The name of the Pub/Sub BigQuery subscription."
  value       = google_pubsub_subscription.scc_high_alerts_bigquery_sub.name
}

output "firestore_database_name" {
  description = "The name of the default Firestore database."
  value       = google_firestore_database.default.name
}

output "cloud_function_name" {
  description = "The name of the Cloud Function routing alerts to Firestore."
  value       = google_cloudfunctions2_function.scc_alert_router.name
}

output "cloud_function_uri" {
  description = "The URI of the Cloud Function service."
  value       = google_cloudfunctions2_function.scc_alert_router.service_config[0].uri
}

output "cloud_function_sa" {
  description = "The service account email executing the Cloud Function."
  value       = google_service_account.alert_router.email
}

