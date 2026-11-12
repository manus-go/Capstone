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
# Remediation: uniform_bucket_level_access is now true, disabling legacy ACLs.
resource "google_storage_bucket" "vulnerable_public_data" {
  name                        = "${var.project_id}-demo-public-bucket"
  location                    = var.region
  uniform_bucket_level_access = true # Enforce Uniform Bucket-Level Access
  force_destroy               = true
}

# The public_bucket_acl resource is removed as Uniform Bucket-Level Access centralizes permissions in IAM,
# making object ACLs obsolete and preventing public exposure via legacy ACLs.
