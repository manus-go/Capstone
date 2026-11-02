variable "project_id" {
  description = "The GCP project ID where the bucket resides."
  type        = string
  default     = "go-capstone-manus"
}

variable "bucket_name" {
  description = "The name of the Google Cloud Storage bucket to remediate."
  type        = string
  default     = "leaky-manus-224"
}

resource "google_storage_bucket" "remediated_bucket" {
  project = var.project_id
  name    = var.bucket_name

  # Enable Uniform Bucket-Level Access to disable object ACLs
  # and enforce IAM as the sole access control mechanism. This directly
  # addresses the "PUBLIC_BUCKET_ACL" finding by preventing future public
  # exposure via object ACLs and simplifying access control management.
  uniform_bucket_level_access = true

  # Note: Other existing bucket attributes (like location, storage_class, etc.)
  # will be preserved by Terraform as they are not explicitly managed here.
  # Only the 'uniform_bucket_level_access' attribute is being modified.
}

# Remove 'allUsers' and 'allAuthenticatedUsers' from critical roles.
# By defining these IAM bindings with an empty 'members' list, Terraform
# will ensure that no one, including 'allUsers' and 'allAuthenticatedUsers',
# has these specific roles on the bucket. This is a strong remediation for
# public access, directly addressing the SCC finding's concern about public IAM bindings.
#
# IMPORTANT OPERATIONAL TRADE-OFF: This will remove *all* existing members
# from these specific roles. If there are other legitimate users or service
# accounts currently assigned to these roles, they will also be removed.
# A more granular approach would require pre-identifying and re-adding
# those legitimate members, which is outside the scope of a generic remediation.

resource "google_storage_bucket_iam_binding" "remove_public_admin_binding" {
  bucket  = google_storage_bucket.remediated_bucket.name
  role    = "roles/storage.admin" # Role allowing policy changes and full control
  members = []                    # Ensure no one has this role, including public identities
}

resource "google_storage_bucket_iam_binding" "remove_public_object_admin_binding" {
  bucket  = google_storage_bucket.remediated_bucket.name
  role    = "roles/storage.objectAdmin" # Role allowing full object control (edit/read/delete)
  members = []                          # Ensure no one has this role, including public identities
}

resource "google_storage_bucket_iam_binding" "remove_public_object_viewer_binding" {
  bucket  = google_storage_bucket.remediated_bucket.name
  role    = "roles/storage.objectViewer" # Role allowing read access to objects
  members = []                           # Ensure no one has this role, including public identities
}

resource "google_storage_bucket_iam_binding" "remove_public_object_creator_binding" {
  bucket  = google_storage_bucket.remediated_bucket.name
  role    = "roles/storage.objectCreator" # Role allowing write access to objects
  members = []                            # Ensure no one has this role, including public identities
}
