resource "google_storage_bucket" "remediated_bucket" {
  project                     = var.project_id
  name                        = var.bucket_name
  location                    = var.bucket_location # The bucket's location is required for this resource.
  uniform_bucket_level_access = true                # Remediation: Enforce Uniform Bucket-Level Access to disable object ACLs and centralize permissions via IAM.

  # Optional: Add other bucket configurations as needed, e.g., versioning, lifecycle rules.
  # versioning {
  #   enabled = true
  # }
}

# Remediation: Remove all public IAM bindings by asserting a new, non-public policy.
# This resource will REPLACE the entire IAM policy for the bucket with the one defined below.
# It is CRITICAL to include all legitimate, non-public IAM bindings here to avoid unintended access loss.
resource "google_storage_bucket_iam_policy" "no_public_access_policy" {
  bucket      = google_storage_bucket.remediated_bucket.name
  policy_data = data.google_iam_policy.no_public_access.policy_data
}

data "google_iam_policy" "no_public_access" {
  # Define all legitimate IAM bindings for the bucket here.
  # Ensure 'allUsers' and 'allAuthenticatedUsers' are NOT included in any 'members' list.
  # If no other bindings are needed, you can remove the 'binding' blocks, but be aware
  # that an empty policy_data will remove ALL IAM bindings from the bucket.

  # Example: Grant object viewer role to a specific group
  # binding {
  #   role    = "roles/storage.objectViewer"
  #   members = [
  #     "group:gcp-storage-viewers@example.com"
  #   ]
  # }

  # Example: Grant object admin role to a specific service account
  # binding {
  #   role    = "roles/storage.objectAdmin"
  #   members = [
  #     "serviceAccount:my-service-account@${var.project_id}.iam.gserviceaccount.com"
  #   ]
  # }

  # Example: Grant storage admin role to a specific user
  # binding {
  #   role    = "roles/storage.admin"
  #   members = [
  #     "user:admin-user@example.com"
  #   ]
  # }
}

variable "project_id" {
  description = "The GCP project ID where the bucket resides."
  type        = string
  default     = "go-capstone-manus" # Extracted from finding details
}

variable "bucket_name" {
  description = "The name of the GCS bucket to remediate."
  type        = string
  default     = "bucket-full-of-leeks" # Extracted from finding details
}

variable "bucket_location" {
  description = "The location of the GCS bucket. This is required for the google_storage_bucket resource."
  type        = string
  default     = "US-CENTRAL1" # A common default; please verify and update with your bucket's actual location.
}
