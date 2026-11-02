variable "project_id" {
  description = "The ID of the Google Cloud project where the service account resides."
  type        = string
  default     = "go-capstone-manus"
}

variable "service_account_email" {
  description = "The email of the service account that currently holds the roles/owner permission."
  type        = string
  default     = "scc-test-owner-sa@go-capstone-manus.iam.gserviceaccount.com"
}

variable "specific_roles" {
  description = "A list of specific, least-privilege IAM roles to assign to the service account. These roles should be carefully chosen based on the service account's actual operational requirements."
  type        = list(string)
  default = [
    "roles/storage.objectViewer",
    "roles/logging.logWriter",
    "roles/cloudfunctions.viewer"
  ]
}

# Assign specific, least-privilege IAM roles to the service account.
# Each 'google_project_iam_member' resource ensures that the service account
# receives only the necessary permissions, adhering to the principle of least privilege.
# This replaces the overly broad 'roles/owner' permission.
resource "google_project_iam_member" "service_account_specific_roles" {
  for_each = toset(var.specific_roles)

  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${var.service_account_email}"
}
