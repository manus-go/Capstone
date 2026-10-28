variable "project_id" {
  description = "The ID of the GCP project where the service account resides."
  type        = string
  default     = "go-capstone-manus"
}

variable "service_account_email" {
  description = "The email of the service account to remediate."
  type        = string
  default     = "scc-test-owner-sa@go-capstone-manus.iam.gserviceaccount.com"
}

variable "granular_roles" {
  description = "A list of granular IAM roles to assign to the service account. These should be carefully chosen based on the service account's actual operational needs."
  type        = list(string)
  default     = [
    "roles/compute.viewer",
    "roles/storage.objectAdmin"
    # IMPORTANT: Replace these example roles with the actual least-privilege roles
    # required for 'scc-test-owner-sa' to function correctly.
    # For example, if it only needs to read Compute Engine instances, use 'roles/compute.viewer'.
    # If it needs to manage objects in a specific GCS bucket, consider 'roles/storage.objectAdmin'
    # scoped to that bucket, or a custom role.
  ]
}

# This Terraform configuration explicitly *does not* include a binding for 'roles/owner'
# for the specified service account. If such a binding exists in GCP and is not
# currently managed by Terraform, it must be imported into the Terraform state
# before running 'terraform apply'. Once imported, 'terraform apply' will detect
# that this binding is no longer desired in the configuration and will remove it from GCP.
# The import command for the 'roles/owner' binding would look like this:
# terraform import 'google_project_iam_member.scc_test_owner_sa_owner_binding' 'go-capstone-manus/roles/owner/serviceAccount:scc-test-owner-sa@go-capstone-manus.iam.gserviceaccount.com'

# Assign granular, least-privilege roles to the service account.
# This block iterates through the 'granular_roles' variable and creates a separate
# 'google_project_iam_member' resource for each role.
resource "google_project_iam_member" "scc_test_owner_sa_granular_roles" {
  for_each = toset(var.granular_roles) # Iterate over each role in the list to create individual bindings.

  project = var.project_id # Specifies the project where the IAM binding will be applied.
  role    = each.value     # Assigns one of the granular roles from the 'granular_roles' list.
  member  = "serviceAccount:${var.service_account_email}" # Identifies the service account to which the role is granted.

  # Explanation: By assigning specific, granular IAM roles instead of the broad 'roles/owner',
  # this configuration strictly adheres to the principle of least privilege. This significantly
  # reduces the potential blast radius if the service account were ever compromised, as it would
  # only have access to the explicitly defined permissions, not full control over the project.
  # This also improves auditability by clearly defining the service account's authorized actions.
}
