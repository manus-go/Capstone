resource "google_compute_firewall" "restrict_ssh_access" {
  project = var.project_id
  name    = var.firewall_rule_name

  # The network to which this rule applies. This must match the existing firewall rule's network.
  network = var.network_name

  # The direction of the traffic to which this rule applies. SSH is an ingress connection.
  direction = "INGRESS"

  # Priority of the firewall rule. Rules with lower priority values have higher precedence.
  # This should match the priority of the existing firewall rule to maintain its order.
  priority = var.firewall_rule_priority

  # This block defines the allowed protocols and ports.
  allow {
    protocol = "tcp"
    ports    = ["22"] # Specifically targeting SSH port 22
  }

  # This is the core remediation: restricting the source IP ranges.
  # Only traffic originating from these CIDR blocks will be allowed.
  source_ranges = var.trusted_ssh_source_ranges

  # IMPORTANT: If the existing firewall rule has target_tags, you MUST include them here
  # with their original values to avoid Terraform attempting to remove them.
  # If the rule applies to all instances in the network and has no target_tags, leave this as an empty list.
  target_tags = var.firewall_target_tags

  # IMPORTANT: If the existing firewall rule has target_service_accounts, you MUST include them here
  # with their original values to avoid Terraform attempting to remove them.
  # If the rule applies to all instances in the network and has no target_service_accounts, leave this as an empty list.
  target_service_accounts = var.firewall_target_service_accounts

  # Optional: Description for the firewall rule, indicating its purpose and remediation status.
  description = "Remediated: Restricts SSH (port 22) access to trusted IP ranges only, as per SCC finding."
}

variable "project_id" {
  description = "The GCP project ID where the firewall rule resides."
  type        = string
  default     = "go-capstone-manus"
}

variable "firewall_rule_name" {
  description = "The name of the firewall rule to modify."
  type        = string
  default     = "test-open-ssh-fw"
}

variable "network_name" {
  description = "The name of the VPC network where the firewall rule exists. This must match the existing rule's network."
  type        = string
  default     = "default" # Common default, but verify from the existing rule
}

variable "firewall_rule_priority" {
  description = "The priority of the firewall rule. This must match the existing rule's priority to avoid unintended changes in rule precedence."
  type        = number
  default     = 1000 # Common default, but verify from the existing rule
}

variable "trusted_ssh_source_ranges" {
  description = "A list of trusted IP CIDR blocks that are allowed to connect via SSH (port 22)."
  type        = list(string)
  # IMPORTANT: Replace with your actual trusted IP ranges. Example: ["203.0.113.0/24", "198.51.100.0/24"]
  default     = ["203.0.113.0/24"] # Placeholder: User MUST change this to their trusted IPs
}

variable "firewall_target_tags" {
  description = "A list of instance tags that this firewall rule applies to. Must match existing rule's target_tags. Leave as empty list if the existing rule has none."
  type        = list(string)
  default     = []
}

variable "firewall_target_service_accounts" {
  description = "A list of service accounts that this firewall rule applies to. Must match existing rule's target_service_accounts. Leave as empty list if the existing rule has none."
  type        = list(string)
  default     = []
}
