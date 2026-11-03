variable "project_id" {
  description = "The ID of the Google Cloud project where the service account resides."
  type        = string
  default     = "go-capstone-manus"
}

variable "service_account_email" {
  description = "The email of the service account that holds excessive permissions."
  type        = string
  default     = "scc-test-owner-sa@go-capstone-manus.iam.gserviceaccount.com"
}

# Define the member string for the service account, required by IAM resources.
locals {
  service_account_member = "serviceAccount:${var.service_account_email}"
}

# Grant specific, least-privilege roles to the service account.
# IMPORTANT: Replace these example roles with the actual, minimal set of roles
# required by the service account's functional purpose.

resource "google_project_iam_member" "scc_sa_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer" # Example: Allows viewing Compute Engine resources.
  member  = local.service_account_member
  # This resource ensures the service account has 'roles/compute.viewer'.
  # It adheres to the principle of least privilege by granting only necessary view access.
}

resource "google_project_iam_member" "scc_sa_storage_object_viewer" {
  project = var.project_id
  role    = "roles/storage.objectViewer" # Example: Allows viewing objects in Cloud Storage buckets.
  member  = local.service_account_member
  # This resource ensures the service account has 'roles/storage.objectViewer'.
  # It provides granular access to storage without granting broader administrative rights.
}

# Add more `google_project_iam_member` blocks here for any other specific roles
# required by the service account. For instance, if it needs to manage its own keys:
# resource "google_project_iam_member" "scc_sa_service_account_key_admin" {
#   project = var.project_id
#   role    = "roles/iam.serviceAccountKeyAdmin"
#   member  = local.service_account_member
#   # This role allows the service account to manage its own keys, if necessary.
# }
