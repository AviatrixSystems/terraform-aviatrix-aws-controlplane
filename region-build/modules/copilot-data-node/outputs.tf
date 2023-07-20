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
