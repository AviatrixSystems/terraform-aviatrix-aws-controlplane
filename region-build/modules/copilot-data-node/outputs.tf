output "instance_id" {
  description = "Data Node Instance ID"
  value       = try(aws_instance.aviatrixcopilot.id, "")
}

output "instance_name" {
  description = "Data Node Instance Name"
  value       = try(aws_instance.aviatrixcopilot.tags["Name"], "")
}

output "sg_id" {
  description = "Data Node SG ID"
  value       = try(aws_security_group.AviatrixCopilotSecurityGroup.id, "")
}

output "sg_name" {
  description = "Data Node SG Name"
  value       = try(aws_security_group.AviatrixCopilotSecurityGroup.name, "")
}

output "instance_private_ip" {
  description = "Data Node Instance Private IP"
  value       = try(aws_instance.aviatrixcopilot.private_ip, "")
}

output "instance_details" {
  description = "Data Node Instance Details"
  value       = {
    "instance_id": try(aws_instance.aviatrixcopilot.id, ""),
    "instance_name": try(aws_instance.aviatrixcopilot.tags["Name"], ""),
    "sg_id": try(aws_security_group.AviatrixCopilotSecurityGroup.id, ""),
    "sg_name": try(aws_security_group.AviatrixCopilotSecurityGroup.name, ""),
    "instance_private_ip": try(aws_instance.aviatrixcopilot.private_ip, "")
  }
}