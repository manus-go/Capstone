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

variable "new_roles" {
  description = "A list of new, least-privilege IAM roles to assign to the service account."
  type        = list(string)
  default     = [
    "roles/viewer",
    "roles/storage.objectViewer"
  ]
}

# This resource block represents the *removal* of the 'roles/owner' binding.
# It must be imported first, and then Terraform will propose to destroy it
# because it's not intended to be part of the long-term desired state.
# The execution instructions will guide you through this process.
resource "google_project_iam_member" "owner_binding_to_be_removed" {
  # The project ID where the service account currently has the owner role.
  project = var.project_id
  # The 'roles/owner' primitive role that needs to be revoked.
  role    = "roles/owner"
  # The service account member string.
  member  = "serviceAccount:${var.service_account_email}"
}

# Assigns each specified least-privilege role to the service account.
# This uses a 'for_each' loop to create a separate IAM member binding for each role.
resource "google_project_iam_member" "new_role_binding" {
  for_each = toset(var.new_roles)

  # The project ID where the new roles will be assigned.
  project = var.project_id
  # The specific least-privilege role from the 'new_roles' variable.
  role    = each.value
  # The service account member string to which the role is assigned.
  member  = "serviceAccount:${var.service_account_email}"
}
