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

# Define the member string for IAM bindings
locals {
  service_account_member = "serviceAccount:${var.service_account_email}"
}

# This resource is defined to facilitate the removal of the existing 'roles/owner' binding.
# It requires an 'import' step followed by its removal from the HCL configuration.
# This ensures the 'roles/owner' binding is explicitly removed via Terraform.
resource "google_project_iam_member" "owner_to_be_removed" {
  project = var.project_id
  role    = "roles/owner"
  member  = local.service_account_member

  # Lifecycle rule to prevent accidental destruction before import, if desired.
  # Remove or comment out after import and before removing the resource block.
  # lifecycle {
  #   prevent_destroy = true
  # }
}

# Assign specific predefined roles based on the service account's operational requirements.
# IMPORTANT: The example roles below ('roles/compute.instanceAdmin.v1' and 'roles/storage.objectViewer')
# are placeholders. You MUST replace them with the actual least-privilege roles required
# by the service account after a thorough discovery phase of its operational needs.

# Example: Grant Compute Instance Admin role (v1)
resource "google_project_iam_member" "assign_compute_instance_admin" {
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = local.service_account_member

  # This resource grants permissions to manage Compute Engine instances.
  # This is an example of a specific, less-privileged role, replacing 'roles/owner'.
}

# Example: Grant Storage Object Viewer role
resource "google_project_iam_member" "assign_storage_object_viewer" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = local.service_account_member

  # This resource grants permissions to view objects in Cloud Storage buckets.
  # This is another example of a specific, less-privileged role, replacing 'roles/owner'.
}