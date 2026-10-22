variable "project_id" {
  description = "The GCP project ID."
  type        = string
  default     = "go-capstone-manus"
}

variable "network_name" {
  description = "The name of the VPC network where the instance resides. Verify this matches your environment."
  type        = string
  default     = "default"
}

variable "trusted_ssh_cidrs" {
  description = "List of trusted IP CIDR ranges allowed to SSH (TCP port 22). YOU MUST UPDATE THIS WITH YOUR ACTUAL CORPORATE/TRUSTED CIDRs."
  type        = list(string)
  default     = ["203.0.113.0/24", "198.51.100.0/24"] # Example CIDRs, REPLACE WITH YOUR OWN
}

variable "instance_target_tags" {
  description = "List of network tags applied to the Compute Engine instances that this firewall rule should apply to. The affected instance(s) must have at least one of these tags."
  type        = list(string)
  default     = ["ssh-restricted"]
}

variable "allow_ssh_firewall_rule_name" {
  description = "Name for the firewall rule allowing trusted SSH access."
  type        = string
  default     = "allow-ssh-from-trusted-cidrs"
}

variable "deny_broad_ssh_firewall_rule_name" {
  description = "Name for the firewall rule denying broad SSH access."
  type        = string
  default     = "deny-broad-ssh-22"
}

resource "google_compute_firewall" "allow_ssh_from_trusted_cidrs" {
  # The project where the firewall rule will be created.
  project = var.project_id
  # The VPC network to which this firewall rule applies.
  network = var.network_name
  # A unique name for the firewall rule.
  name    = var.allow_ssh_firewall_rule_name
  # A descriptive explanation of the rule's purpose, including its remediation context.
  description = "Allows SSH (TCP 22) from trusted CIDR ranges to instances with specific tags. This rule remediates SCC finding OPEN_SSH_PORT by restricting SSH access to authorized sources."

  # Specifies that this rule applies to incoming connections.
  direction = "INGRESS"
  # A lower priority number means higher precedence. This rule has a high priority (100) to ensure trusted access is allowed before any deny rules.
  priority  = 100

  # Defines the source IP ranges from which traffic is allowed. This is restricted to the user-defined trusted CIDRs.
  source_ranges = var.trusted_ssh_cidrs
  # Specifies that this rule only applies to instances that have one of the defined network tags. The affected VM must have one of these tags.
  target_tags   = var.instance_target_tags

  # Defines the allowed protocol and ports.
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # Ensures the firewall rule is active.
  disabled = false
}

resource "google_compute_firewall" "deny_broad_ssh_access" {
  # The project where the firewall rule will be created.
  project = var.project_id
  # The VPC network to which this firewall rule applies.
  network = var.network_name
  # A unique name for the firewall rule.
  name    = var.deny_broad_ssh_firewall_rule_name
  # A descriptive explanation of the rule's purpose, including its remediation context.
  description = "Denies SSH (TCP 22) from 0.0.0.0/0 to instances with specific tags. This rule ensures broad public SSH access is blocked, remediating SCC finding OPEN_SSH_PORT."

  # Specifies that this rule applies to incoming connections.
  direction = "INGRESS"
  # This rule has a slightly lower priority (110) than the allow rule (100). This ensures that trusted SSH connections are allowed first, and then all other broad SSH connections are denied.
  priority  = 110

  # Defines the source IP ranges from which traffic is denied. "0.0.0.0/0" represents all public IP addresses.
  source_ranges = ["0.0.0.0/0"]
  # Specifies that this rule only applies to instances that have one of the defined network tags. This should match the target_tags of the allow rule.
  target_tags   = var.instance_target_tags

  # Defines the denied protocol and ports.
  deny {
    protocol = "tcp"
    ports    = ["22"]
  }

  # Ensures the firewall rule is active.
  disabled = false
}
