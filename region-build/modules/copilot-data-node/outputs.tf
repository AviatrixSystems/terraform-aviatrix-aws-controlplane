output "instance_ids" {
  description = "Data Node Instance ID"
  value       = try(join(",", aws_instance.aviatrixcopilot.*.id), "")
}

output "instance_names" {
  description = "Data Node Instance ID"
  value       = try(join(",", aws_instance.aviatrixcopilot[*].tags["Name"]), "")
}

output "sg_ids" {
  description = "Data Node SG ID"
  value       = try(join(",", aws_security_group.AviatrixCopilotSecurityGroup[*].tags["Name"]), "")
}