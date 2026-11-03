resource "google_project_iam_custom_role" "least_privilege_sa_role" {
  # Defines a new custom IAM role at the project level.
  # This role will contain only the specific permissions required by the service account,
  # adhering to the principle of least privilege.
  project     = var.project_id
  role_id     = var.custom_role_id
  title       = var.custom_role_title
  description = var.custom_role_description
  permissions = var.custom_role_permissions # Placeholder permissions; adjust as needed for the SA's actual function.

  # Setting `stage` to `GA` indicates the role is stable and ready for production use.
  stage = "GA"
}

resource "google_project_iam_member" "sa_custom_role_binding" {
  # Binds the service account to the newly created custom role.
  # This replaces the excessive 'roles/owner' permission with a granular, least-privilege role.
  project = var.project_id
  role    = google_project_iam_custom_role.least_privilege_sa_role.name # References the custom role's full name.
  member  = "serviceAccount:${var.service_account_email}"
}

# --- Variables --- #
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

variable "custom_role_id" {
  description = "The ID for the new custom IAM role (e.g., 'sa_least_privilege_access')."
  type        = string
  default     = "sccTestOwnerLeastPrivilege"
}

variable "custom_role_title" {
  description = "A human-readable title for the custom role."
  type        = string
  default     = "SCC Test Owner Least Privilege Access"
}

variable "custom_role_description" {
  description = "A description for the custom role, explaining its purpose."
  type        = string
  default     = "Least privilege access for scc-test-owner-sa, replacing roles/owner."
}

variable "custom_role_permissions" {
  description = "List of granular permissions for the custom role. IMPORTANT: Customize this based on the service account's actual functional requirements."
  type        = list(string)
  # Placeholder permissions. In a real scenario, these must be carefully determined.
  # Example: If the SA manages Compute instances and reads Storage buckets.
  default = [
    "compute.instances.list",
    "compute.instances.get",
    "compute.instances.start",
    "compute.instances.stop",
    "storage.buckets.list",
    "storage.objects.list"
  ]
}
