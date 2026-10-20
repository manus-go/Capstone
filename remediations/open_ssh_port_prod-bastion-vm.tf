# Terraform Remediation for OPEN_SSH_PORT
# Strategy: Modify the existing firewall rule to narrow the source IP ranges for SSH (port 22) to only explicitly authorized administrative networks or VPN egress points. If the 'prod-bastion-vm' does not require public internet access for any other legitimate services, remove its external IP address entirely.

# Resource remediation snippet
# Please inspect resource '//compute.googleapis.com/projects/437113760931/zones/europe-west2-a/instances/prod-bastion-vm' in project 'go-capstone-manus'.
