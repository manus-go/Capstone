variable "project_id" {
  description = "The ID of the GCP project where the service account has owner permissions."
  type        = string
  default     = "go-capstone-manus"
}

variable "service_account_email" {
  description = "The email of the service account that currently holds excessive owner permissions."
  type        = string
  default     = "scc-test-owner-sa@go-capstone-manus.iam.gserviceaccount.com"
}

# This Terraform resource block is a temporary declaration. Its primary purpose
# is to allow Terraform to import the *existing* 'roles/owner' binding for the
# specified service account into its state. Once imported, this entire resource
# block must be REMOVED from the Terraform configuration file.
# The subsequent 'terraform apply' will then detect the absence of this declaration
# and proceed to destroy (revoke) the 'roles/owner' permission from the service account.
# This implements the 'Immediate Revocation' strategy by leveraging Terraform's
# ability to manage and then unmanage (destroy) existing cloud resources.
resource "google_project_iam_member" "scc_owner_to_be_revoked" {
  # Specifies the GCP project where the IAM binding exists. This attribute ensures
  # the remediation targets the correct project as identified by the SCC finding.
  project = var.project_id
  # Defines the role to be revoked. In this case, the highly privileged 'roles/owner'
  # as specified in the SCC finding, which is the target of this remediation.
  role    = "roles/owner"
  # Identifies the service account whose 'roles/owner' permission will be revoked.
  # This directly corresponds to the 'ServiceAccount' attribute in the SCC finding.
  member  = "serviceAccount:${var.service_account_email}"
}
