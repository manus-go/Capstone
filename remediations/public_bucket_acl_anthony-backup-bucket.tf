resource "google_storage_bucket_iam_policy" "bucket_iam_policy" {
  # The bucket to apply the IAM policy to.
  bucket = var.bucket_name

  # The policy data, constructed to explicitly exclude 'allUsers' and 'allAuthenticatedUsers'.
  # This resource takes full control of the bucket's IAM policy.
  # Any existing bindings not specified in the 'policy_data' will be removed.
  policy_data = data.google_iam_policy.private_bucket_policy.policy_data
}

data "google_iam_policy" "private_bucket_policy" {
  # This data source constructs an IAM policy document.
  # By default, if no 'binding' blocks are specified here, it generates an empty policy.
  # An empty policy, when applied via 'google_storage_bucket_iam_policy', will remove
  # *all* existing IAM bindings from the bucket, including any 'allUsers' or 'allAuthenticatedUsers'
  # bindings, thus making the bucket completely private.

  # IMPORTANT: If there are other legitimate, non-public IAM bindings that should remain
  # for this bucket (e.g., service accounts, specific users/groups), they MUST be explicitly
  # defined within 'binding' blocks here. Otherwise, they will be removed.
  # Ensure that 'allUsers' and 'allAuthenticatedUsers' are NOT included in any 'members' list.

  # Example of how to add legitimate internal bindings (uncomment and modify as needed):
  /*
  binding {
    role    = "roles/storage.objectViewer"
    members = [
      "serviceAccount:my-backup-sa@${var.project_id}.iam.gserviceaccount.com",
      "group:gcp-storage-viewers@example.com",
    ]
  }
  binding {
    role    = "roles/storage.objectAdmin"
    members = [
      "serviceAccount:my-backup-writer-sa@${var.project_id}.iam.gserviceaccount.com",
    ]
  }
  */
}

variable "project_id" {
  description = "The GCP project ID."
  type        = string
  default     = "go-capstone-manus"
}

variable "bucket_name" {
  description = "The name of the GCS bucket to remediate."
  type        = string
  default     = "anthony-backup-bucket"
}
