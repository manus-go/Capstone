variable "project_id" {
  description = "The GCP project ID."
  type        = string
  default     = "go-capstone-manus"
}

variable "network_name" {
  description = "The name of the VPC network where the VM resides."
  type        = string
  default     = "default" # Common default, verify this matches your environment
}

variable "authorized_ssh_cidrs" {
  description = "A list of IP CIDR ranges (e.g., corporate VPN egress, jump host IPs) authorized to SSH to the VM. YOU MUST REPLACE THIS WITH YOUR ACTUAL AUTHORIZED CIDRs."
  type        = list(string)
  default     = ["203.0.113.0/24"] # EXAMPLE: Replace with your actual authorized IP ranges
}

variable "target_tags" {
  description = "A list of network tags that identify the target VM(s) for this firewall rule. Ensure 'core-payment-gateway-vm' has at least one of these tags."
  type        = list(string)
  default     = ["core-payment-gateway-vm-ssh"] # Ensure this tag is applied to the VM
}

variable "firewall_rule_name" {
  description = "The name for the new, restrictive SSH firewall rule."
  type        = string
  default     = "allow-ssh-restricted-core-payment-gateway"
}

variable "firewall_rule_priority" {
  description = "The priority of the firewall rule. Lower numbers indicate higher priority. Set this lower than any existing permissive SSH rules (e.g., default is 1000) to ensure it takes precedence."
  type        = number
  default     = 500
}

resource "google_compute_firewall" "restrict_ssh_access" {
  # The project where the firewall rule will be created.
  project = var.project_id

  # A unique name for the firewall rule.
  name = var.firewall_rule_name

  # The VPC network to which this firewall rule applies.
  network = var.network_name

  # Specifies that this rule applies to incoming connections.
  direction = "INGRESS"

  # Sets a higher priority for this rule (lower number = higher priority) to ensure it takes
  # precedence over any existing, more permissive SSH rules (e.g., default priority is 1000).
  priority = var.firewall_rule_priority

  # Defines the source IP ranges from which ingress traffic is allowed.
  # This remediates the finding by restricting SSH access from '0.0.0.0/0' to only authorized CIDRs.
  source_ranges = var.authorized_ssh_cidrs

  # Specifies the network tags of the instances to which this rule applies.
  # Ensure the 'core-payment-gateway-vm' has one of these tags for the rule to take effect.
  target_tags = var.target_tags

  # Defines the allowed protocols and ports.
  # This block specifically allows TCP traffic on port 22 (SSH).
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # A descriptive explanation of the firewall rule's purpose.
  description = "Allows SSH (TCP port 22) ingress only from authorized IP ranges to VMs with specific tags, remediating SCC OPEN_SSH_PORT finding."

  # Prevents accidental deletion of this critical security rule.
  lifecycle {
    prevent_destroy = true
  }
}
