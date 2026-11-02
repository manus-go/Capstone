resource "google_storage_bucket" "remediated_bucket" {
  # The name of the Google Cloud Storage bucket to remediate.
  name = var.bucket_name

  # The GCP project ID where the bucket resides.
  project = var.project_id

  # The location of the GCS bucket. This must match the existing bucket's location.
  # It's crucial to set this correctly as Terraform will attempt to recreate if it differs.
  location = var.bucket_location

  # Enable uniform bucket-level access to centralize permission management
  # through IAM and disable object ACLs. This directly remediates the PUBLIC_BUCKET_ACL finding.
  uniform_bucket_level_access = true

  # IMPORTANT: If there are other attributes for this bucket (e.g., storage_class, versioning, lifecycle_rules),
  # they should be included here to prevent Terraform from reverting them to default values.
  # For this remediation, we are only focusing on 'uniform_bucket_level_access'.
  # If this bucket is already managed by Terraform, ensure this resource block merges with the existing one.
}

variable "bucket_name" {
  description = "The name of the GCS bucket to remediate."
  type        = string
  default     = "leaky-bucket-demo-1793636857"
}

variable "project_id" {
  description = "The GCP project ID where the bucket resides."
  type        = string
  # IMPORTANT: Replace with your actual GCP project ID or set via environment variables/CLI.
  default     = "your-gcp-project-id"
}

variable "bucket_location" {
  description = "The location of the GCS bucket. This must match the existing bucket's location (e.g., 'US-CENTRAL1', 'EUROPE-WEST1')."
  type        = string
  # IMPORTANT: Replace with the actual location of your bucket. You can find this in the GCP Console.
  default     = "US-CENTRAL1" # Common default, but verify for your bucket
}
