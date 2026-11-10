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

# Remediation: Configured to enforce Uniform Bucket-Level Access
# This disables object ACLs, making IAM the exclusive method for granting access.
resource "google_storage_bucket" "vulnerable_public_data" {
  name                        = "${var.project_id}-demo-public-bucket"
  location                    = var.region
  uniform_bucket_level_access = true # Remediation: Enabled Uniform Bucket-Level Access
  force_destroy               = true
}

# Remediation: Removed the public ACL binding as Uniform Bucket-Level Access is now enforced,
# which deprecates object ACLs and centralizes permissions via IAM.
# The previous 'google_storage_bucket_access_control.public_bucket_acl' resource is no longer needed.
