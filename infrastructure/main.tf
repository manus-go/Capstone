terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
  default     = "go-capstone-manus"
}

variable "region" {
  type        = string
  description = "Google Cloud Region"
  default     = "europe-west2"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# =============================================================================
# Baseline Storage Infrastructure
# =============================================================================

# Compliant internal analytics bucket (enforcing UBLA and versioning)
resource "google_storage_bucket" "compliant_analytics_data" {
  name                        = "${var.project_id}-analytics-data-secure"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true

  versioning {
    enabled = true
  }
}

# Remediation for PUBLIC_BUCKET_ACL: Enforcing uniform bucket-level access.
# This disables object ACLs, centralizing access control through IAM policies.
resource "google_storage_bucket" "vulnerable_public_data" {
  name                        = "${var.project_id}-demo-public-bucket"
  location                    = var.region
  # Set uniform_bucket_level_access to true to enforce IAM-only access control.
  uniform_bucket_level_access = true
  force_destroy               = true
}

# The public bucket ACL is removed as uniform_bucket_level_access is now enabled,
# making object ACLs obsolete and preventing public exposure via legacy ACLs.
// resource "google_storage_bucket_access_control" "public_bucket_acl" {
//   bucket = google_storage_bucket.vulnerable_public_data.name
//   role   = "READER"
//   entity = "allUsers"
// }
