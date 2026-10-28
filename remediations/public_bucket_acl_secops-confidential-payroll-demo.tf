provider "google" {
  project = var.project_id
}

variable "project_id" {
  description = "The GCP project ID where the bucket resides."
  type        = string
}

variable "bucket_name" {
  description = "The name of the Cloud Storage bucket to remediate."
  type        = string
  default     = "secops-confidential-payroll-demo"
}

resource "google_storage_bucket" "scc_remediated_bucket" {
  project = var.project_id
  name    = var.bucket_name

  // Remediation for PUBLIC_BUCKET_ACL:
  // Enable uniform bucket-level access to disable legacy ACLs and
  // ensure that access is controlled solely by IAM policies.
  // This directly addresses the finding that the bucket allows anonymous
  // public internet read access due to legacy ACLs.
  uniform_bucket_level_access = true

  // IMPORTANT: When importing an existing resource, Terraform will manage
  // only the attributes explicitly defined in this resource block.
  // If the bucket has other configurations (e.g., location, storage_class,
  // versioning, lifecycle_rules, etc.) that are not defined here,
  // Terraform will attempt to reset them to their default values or remove them.
  // To prevent unintended changes, it is highly recommended to first import
  // the bucket and then run `terraform plan` to see what changes Terraform
  // proposes. If there are other attributes you wish to preserve, you must
  // add them to this resource block with their current values.
  // For the purpose of this specific remediation, we are only modifying
  // `uniform_bucket_level_access`.
}
