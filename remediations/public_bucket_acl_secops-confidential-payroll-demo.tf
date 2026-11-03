variable "project_id" {
  description = "The GCP project ID."
  type        = string
  default     = "your-gcp-project-id" # REMINDER: Change this default to your actual project ID
}

variable "bucket_name" {
  description = "The name of the Cloud Storage bucket to remediate."
  type        = string
  default     = "secops-confidential-payroll-demo"
}

resource "google_storage_bucket_iam_binding" "revoke_public_object_viewer" {
  # This resource ensures that the 'roles/storage.objectViewer' role on the bucket
  # has no members, thereby revoking any public read access granted through this role.
  # If 'allUsers' or 'allAuthenticatedUsers' were bound to this role, they will be removed.
  bucket  = var.bucket_name
  role    = "roles/storage.objectViewer"
  members = []
}

resource "google_storage_bucket_iam_binding" "revoke_public_legacy_bucket_reader" {
  # This resource ensures that the 'roles/storage.legacyBucketReader' role on the bucket
  # has no members, thereby revoking any public read access granted through this legacy role.
  # If 'allUsers' or 'allAuthenticatedUsers' were bound to this role, they will be removed.
  bucket  = var.bucket_name
  role    = "roles/storage.legacyBucketReader"
  members = []
}
