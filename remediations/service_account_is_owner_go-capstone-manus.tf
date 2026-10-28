variable "project_id" {
  description = "The ID of the Google Cloud project."
  type        = string
  default     = "go-capstone-manus"
}

variable "service_account_email" {
  description = "The email of the service account to remediate."
  type        = string
  default     = "interactive-test-sa-6968@go-capstone-manus.iam.gserviceaccount.com"
}

# Define a custom IAM role for the service account.
# This role will contain the precise, minimal set of permissions required.
resource "google_project_iam_custom_role" "interactive_test_sa_custom_role" {
  # The project where the custom role will be created.
  project     = var.project_id
  # A unique identifier for the custom role within the project.
  # GCP custom role IDs typically use camelCase or PascalCase.
  role_id     = "interactiveTestSaCustomRole"
  # A human-readable title for the custom role.
  title       = "Interactive Test SA Least Privilege Role"
  # A description explaining the purpose of the role.
  description = "Least privilege role for interactive-test-sa-6968 service account."
  # The stage of the role (e.g., GA, BETA, ALPHA). GA is generally preferred for production.
  stage       = "GA"
  # The list of permissions included in this custom role.
  # IMPORTANT: These are EXAMPLE permissions. You MUST replace them with the actual,
  # minimal set of permissions required for 'interactive-test-sa-6968' to perform
  # its intended functions. Refer to Google Cloud documentation for a comprehensive
  # list of permissions: https://cloud.google.com/iam/docs/understanding-roles#resource-specific_permissions
  permissions = [
    "compute.instances.get",
    "compute.instances.list",
    "storage.buckets.list",
    "logging.logEntries.list",
    "monitoring.timeSeries.list"
  ]
}

# Grant the newly created custom role to the service account on the project.
# This establishes the least-privilege access.
resource "google_project_iam_member" "interactive_test_sa_custom_role_binding" {
  # The project where the binding will be applied.
  project = var.project_id
  # The custom role to grant. The format is 'projects/{project_id}/roles/{role_id}'.
  role    = google_project_iam_custom_role.interactive_test_sa_custom_role.id
  # The member to grant the role to. Format is 'serviceAccount:{email}'.
  member  = "serviceAccount:${var.service_account_email}"
}

# This resource block is included to facilitate the *removal* of the existing
# 'roles/owner' binding for the service account. It is a temporary resource
# that will be removed from the HCL after the initial apply.
#
# IMPORTANT OPERATIONAL STEP:
# 1. After 'terraform init', you MUST import the existing 'roles/owner' binding
#    into Terraform state using the command provided in the execution instructions.
# 2. After successfully importing and applying the custom role (Step 4 in instructions),
#    you will then REMOVE THIS 'google_project_iam_member.interactive_test_sa_owner_binding'
#    resource block from your Terraform configuration file.
# 3. Run 'terraform plan' and 'terraform apply' again. Terraform will then
#    plan to DESTROY this binding, effectively revoking the 'roles/owner'
#    from the service account.
resource "google_project_iam_member" "interactive_test_sa_owner_binding" {
  project = var.project_id
  role    = "roles/owner"
  member  = "serviceAccount:${var.service_account_email}"
  # Prevent accidental destruction of this binding before the custom role is applied
  # and the user is ready to explicitly remove it. This lifecycle block ensures
  # that Terraform will not destroy this resource unless it's explicitly removed
  # from the configuration file.
  lifecycle {
    prevent_destroy = true
  }
}
