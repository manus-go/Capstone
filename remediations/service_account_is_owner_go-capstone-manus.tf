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

variable "least_privilege_roles" {
  description = "A list of least-privilege IAM roles to assign to the service account."
  type        = list(string)
  default = [
    "roles/storage.objectViewer",    # Example: Allows viewing objects in Cloud Storage buckets
    "roles/logging.logWriter",       # Example: Allows writing logs to Cloud Logging
    "roles/monitoring.metricWriter"  # Example: Allows writing custom metrics to Cloud Monitoring
    # IMPORTANT: Add more specific roles as needed, e.g., roles/compute.viewer, roles/cloudsql.client, etc.
    # These example roles MUST be replaced or augmented based on the service account's actual functional requirements.
  ]
}

# This resource block is TEMPORARY and is used to import the existing 'roles/owner' binding
# so that Terraform can manage and subsequently remove it. After successful 'terraform import'
# and 'terraform apply' (which removes this binding), this entire block MUST be removed
# from your Terraform configuration file.
resource "google_project_iam_member" "scc_test_owner_sa_owner_to_be_removed" {
  project = var.project_id
  role    = "roles/owner"
  member  = "serviceAccount:${var.service_account_email}"

  # Explanation: This temporary resource is declared to allow Terraform to take
  # ownership of the existing 'roles/owner' binding for the service account.
  # Once imported, Terraform can then be instructed to remove this binding
  # by deleting this resource block from the HCL configuration before the final apply.
}

# This resource block assigns specific, least-privilege IAM roles to the service account.
resource "google_project_iam_member" "least_privilege_bindings" {
  for_each = toset(var.least_privilege_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${var.service_account_email}"

  # Explanation: This 'for_each' block iterates through the 'least_privilege_roles'
  # variable, creating a separate 'google_project_iam_member' resource for each
  # specified role. This ensures that the service account is granted only the
  # minimum necessary permissions, adhering to the principle of least privilege.
  # These roles should be carefully selected based on the service account's
  # actual functional requirements to avoid breaking functionality.
}
