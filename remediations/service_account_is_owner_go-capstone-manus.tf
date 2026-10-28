variable "project_id" {
  description = "The ID of the Google Cloud project."
  type        = string
  default     = "go-capstone-manus"
}

variable "service_account_email" {
  description = "The email of the service account to remediate."
  type        = string
  default     = "scc-test-owner-sa@go-capstone-manus.iam.gserviceaccount.com"
}

variable "least_privilege_roles" {
  description = "A list of least-privilege IAM roles to assign to the service account."
  type        = list(string)
  default     = [
    "roles/viewer",
    "roles/storage.objectViewer"
    # IMPORTANT: Replace these with the actual, specific roles required by the service account.
    # Example: "roles/compute.instanceAdmin.v1", "roles/cloudsql.client", etc.
    # Granular roles should be applied at the most specific resource level possible (e.g., bucket, topic, instance).
    # If resource-level permissions are needed, use google_storage_bucket_iam_member, google_pubsub_topic_iam_member, etc.
  ]
}

# Assign granular least-privilege roles to the service account at the project level.
# This resource ensures that the specified service account is granted only the necessary permissions.
# Each role is managed individually, allowing for fine-grained control and adherence to the principle of least privilege.
resource "google_project_iam_member" "least_privilege_bindings" {
  for_each = toset(var.least_privilege_roles)

  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${var.service_account_email}"

  # Inline comment: This resource adds a specific IAM role binding for the service account.
  # By using 'for_each' over a list of roles, we can assign multiple granular roles declaratively.
  # This replaces the overly broad 'roles/owner' with targeted permissions.
}
