variable "project_id" {
  description = "The ID of the GCP project."
  type        = string
  default     = "go-capstone-manus"
}

variable "service_account_email" {
  description = "The email of the service account to remediate."
  type        = string
  default     = "scc-test-owner-sa@go-capstone-manus.iam.gserviceaccount.com"
}

variable "custom_role_id" {
  description = "The ID for the custom role. Must be unique within the project and contain only alphanumeric characters and underscores."
  type        = string
  default     = "sccTestSALeastPrivilege"
}

variable "custom_role_title" {
  description = "The human-readable title for the custom role."
  type        = string
  default     = "SCC Test SA Least Privilege Role"
}

variable "custom_role_permissions" {
  description = "List of permissions for the custom role. CRITICAL: Customize these permissions based on the service account's actual, verified operational needs. The provided defaults are examples and likely insufficient or excessive for your specific use case."
  type        = list(string)
  default = [
    "compute.instances.get",
    "compute.instances.list",
    "storage.buckets.get",
    "storage.buckets.list",
    "logging.logEntries.create",
    "monitoring.metricDescriptors.create",
    "monitoring.metricDescriptors.get",
    "monitoring.metricDescriptors.list",
    "monitoring.timeSeries.create"
  ]
}

# Resource: google_project_iam_custom_role
# This resource defines a new custom IAM role at the project level.
# It includes only the specific permissions required by the service account,
# adhering to the principle of least privilege. The 'permissions' list
# MUST be carefully reviewed and customized by the administrator.
resource "google_project_iam_custom_role" "scc_remediation_custom_role" {
  project     = var.project_id
  role_id     = var.custom_role_id
  title       = var.custom_role_title
  permissions = var.custom_role_permissions
  stage       = "GA" # Set to GA for production-ready roles.
  description = "Least privilege role for service account ${var.service_account_email} to remediate SCC finding. Permissions must be customized."
}

# Resource: google_project_iam_member
# This resource binds the affected service account to the newly created custom role.
# This replaces the excessive 'roles/owner' permission with a granular, least-privilege role.
resource "google_project_iam_member" "add_custom_role_binding" {
  project = var.project_id
  role    = google_project_iam_custom_role.scc_remediation_custom_role.id # References the ID of the custom role.
  member  = "serviceAccount:${var.service_account_email}"
}
