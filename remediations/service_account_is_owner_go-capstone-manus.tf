variable "project_id" {
  description = "The ID of the Google Cloud project where the service account is an owner."
  type        = string
  default     = "go-capstone-manus" # From finding details
}

variable "service_account_email" {
  description = "The email of the service account that currently holds the 'roles/owner' permission and needs remediation."
  type        = string
  # IMPORTANT: Replace with the actual service account email from your environment.
  # Example: "my-service-account@go-capstone-manus.iam.gserviceaccount.com"
  default     = "" # User MUST populate this variable with the correct service account email.
}

variable "least_privilege_roles" {
  description = "A list of least-privilege roles to assign to the service account. These roles should be determined based on the service account's actual operational requirements."
  type        = list(string)
  # IMPORTANT: Replace with the actual roles required by the service account.
  # Example: ["roles/storage.objectViewer", "roles/cloudfunctions.viewer"]
  default     = ["roles/viewer"] # Placeholder, user should update based on actual needs.
}

variable "project_owners" {
  description = "A list of ALL principals (users, groups, service accounts) that SHOULD have the 'roles/owner' role on the project. This list MUST NOT include the service_account_email being remediated. If this list is incomplete, other legitimate owners might be removed."
  type        = list(string)
  # IMPORTANT: Populate this with ALL existing and desired owners for the project,
  # EXCLUDING the service account specified in 'service_account_email'.
  # Example: ["user:admin@example.com", "group:gcp-admins@example.com", "serviceAccount:another-sa@project.iam.gserviceaccount.com"]
  default     = [] # User MUST populate this. Leaving empty will remove all owners if not imported correctly.
}

# Resource to manage the 'roles/owner' binding for the project.
# This resource ensures that the 'service_account_email' is NOT an owner.
# It requires a complete list of ALL desired owners for the project.
# Any principal not in 'var.project_owners' will be removed from the 'roles/owner' role.
resource "google_project_iam_binding" "project_owners" {
  project = var.project_id
  role    = "roles/owner"
  members = var.project_owners # This list MUST NOT contain the service_account_email
}

# Resources to assign least-privilege roles to the service account.
# These resources are additive and will grant the specified roles to the service account.
resource "google_project_iam_member" "least_privilege_assignments" {
  for_each = toset(var.least_privilege_roles)

  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${var.service_account_email}" # Assign the new role to the service account
}
