variable "project_id" {
  description = "The GCP project ID."
  type        = string
  default     = "go-capstone-manus"
}

variable "firewall_rule_name" {
  description = "The name of the firewall rule to remediate."
  type        = string
  default     = "fw-loading-test"
}

variable "network_name" {
  description = "The name of the network where the firewall rule exists. This is crucial for importing the rule."
  type        = string
  default     = "default" # Common default, adjust if your network is different
}

variable "iap_ssh_user_member" {
  description = "The IAM member (user or group) to grant IAP-based SSH access. Format: 'user:email@example.com' or 'group:my-group@example.com'"
  type        = string
  # IMPORTANT: Replace with the actual user/group who needs IAP SSH access.
  default     = "user:your-gcp-admin-email@example.com"
}

# Resource to remediate the existing firewall rule
resource "google_compute_firewall" "fw_loading_test_remediated" {
  project = var.project_id
  name    = var.firewall_rule_name
  network = var.network_name

  # This block explicitly denies all traffic for this firewall rule.
  # This effectively disables any previous 'allow' rules, including the problematic
  # unrestricted ingress SSH (TCP:22) from 0.0.0.0/0, thus remediating the SCC finding.
  # This is the "disable" part of the remediation strategy.
  deny {
    protocol = "all"
  }

  # The original rule allowed 0.0.0.0/0. By defining a deny all for this source range,
  # we ensure that if the rule was targeting 0.0.0.0/0, it now denies all traffic from that range.
  # This ensures the problematic ingress is no longer allowed.
  source_ranges = ["0.0.0.0/0"]

  # If the original firewall rule had specific target_tags or target_service_accounts,
  # they should be included here to ensure the modification applies to the correct instances.
  # Example (uncomment and adjust if needed):
  # target_tags = ["your-instance-tag"]
  # target_service_accounts = ["your-service-account@your-project.iam.gserviceaccount.com"]
}

# Resource to grant IAM permission for IAP-based SSH access
resource "google_project_iam_member" "iap_tunnel_accessor" {
  project = var.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  member  = var.iap_ssh_user_member

  # This grants the necessary permission to use IAP for TCP forwarding (including SSH).
  # It allows the specified member to connect to instances via IAP, replacing the need
  # for public SSH firewall rules and significantly reducing the attack surface.
}
