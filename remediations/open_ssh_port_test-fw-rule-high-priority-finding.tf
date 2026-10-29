variable "project_id" {
  description = "The GCP project ID where the firewall rule exists."
  type        = string
  default     = "go-capstone-manus"
}

variable "firewall_rule_name" {
  description = "The name of the firewall rule to modify."
  type        = string
  default     = "test-fw-rule-high-priority-finding"
}

variable "iap_ssh_users" {
  description = "List of members (users/service accounts/groups) to grant IAP Tunnel Resource Accessor role. Format: 'user:email', 'group:email', 'serviceAccount:email'."
  type        = list(string)
  default     = ["user:your-gcp-user@example.com"] # IMPORTANT: Replace with actual user(s) or group(s)
}

locals {
  # Standard IP range used by IAP for TCP forwarding
  iap_source_ranges = ["35.235.240.0/20"]
}

# Data source to read the existing firewall rule's configuration
# This is crucial to preserve other settings like network, direction, priority, and other allowed ports.
data "google_compute_firewall" "existing_firewall_rule" {
  project = var.project_id
  name    = var.firewall_rule_name
}

# Modify the existing firewall rule to restrict SSH access to IAP's IP range.
# This resource will take over management of the existing firewall rule.
resource "google_compute_firewall" "remediated_firewall_rule" {
  project     = var.project_id
  name        = var.firewall_rule_name
  description = "Remediated firewall rule for IAP SSH access. Originally allowed 0.0.0.0/0 for SSH. Now restricted to IAP TCP Forwarding IP ranges."
  network     = data.google_compute_firewall.existing_firewall_rule.network
  direction   = data.google_compute_firewall.existing_firewall_rule.direction
  priority    = data.google_compute_firewall.existing_firewall_rule.priority

  # Update source_ranges to IAP's IP range, effectively removing 0.0.0.0/0 for SSH.
  # This change applies to all 'allow' blocks within this rule.
  source_ranges = local.iap_source_ranges

  # Preserve existing target tags and service accounts
  target_tags             = data.google_compute_firewall.existing_firewall_rule.target_tags
  target_service_accounts = data.google_compute_firewall.existing_firewall_rule.target_service_accounts

  # Reconstruct the 'allow' blocks from the existing rule.
  # This ensures that if the rule allowed other ports (e.g., TCP 80) in addition to TCP 22,
  # those allowances are preserved, but now also restricted to the IAP source_ranges.
  dynamic "allow" {
    for_each = data.google_compute_firewall.existing_firewall_rule.allow
    content {
      protocol = allow.value.protocol
      ports    = allow.value.ports
    }
  }

  # Ensure that TCP 22 is explicitly allowed. If the original rule already had it,
  # the dynamic block above will include it. If not, this would add it.
  # However, the SCC finding implies TCP 22 was already allowed.
  # This block is primarily to ensure the port is present if it was somehow missing
  # or to explicitly state the intent for SSH.
  # If the dynamic block already covers TCP 22, this explicit block might cause a conflict
  # if not handled carefully. For simplicity and assuming the dynamic block covers it,
  # we rely on the dynamic block to recreate the original allow rules, now with restricted source_ranges.
  # If the original rule did NOT have TCP 22, and we want to add it, we'd need more complex logic.
  # Given the finding is OPEN_SSH_PORT, we assume TCP 22 is already in the 'allow' blocks.
}

# Grant the 'IAP-secured Tunnel User' role to specified members.
# This role allows users to connect to instances via IAP TCP forwarding.
resource "google_project_iam_member" "iap_tunnel_accessor" {
  for_each = toset(var.iap_ssh_users)
  project  = var.project_id
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value

  # Comment explaining the purpose of this IAM binding
  # This role is essential for users to leverage IAP for SSH access.
}
