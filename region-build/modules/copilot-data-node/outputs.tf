output "instance_ids" {
  description = "Data Node Instance IDs"
  value       = try(join(",", aws_instance.aviatrixcopilot.*.id), "")
}

output "instance_names" {
  description = "Data Node Instance IDs"
  value       = try(join(",", aws_instance.aviatrixcopilot[*].tags["Name"]), "")
}