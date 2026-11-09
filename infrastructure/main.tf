
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

# Vulnerable Storage Bucket: Triggering SCC detector PUBLIC_BUCKET_ACL
# Remediation: Enabled Uniform Bucket-Level Access to eliminate public ACLs and enforce IAM-based access control.
resource "google_storage_bucket" "vulnerable_public_data" {
  name                        = "${var.project_id}-demo-public-bucket"
  location                    = var.region
  # Set uniform_bucket_level_access to true to disable object ACLs and centralize permissions with IAM.
  uniform_bucket_level_access = true
  force_destroy               = true
}

# The previous google_storage_bucket_access_control resource for "allUsers" is removed
# because Uniform Bucket-Level Access centralizes access control through IAM policies,
# making object ACLs, including public ones, ineffective and unnecessary.
