locals {
  controller_tags = [for item in aws_launch_template.avtx-controller.tag_specifications : item["resource_type"] == "instance" ? item["tags"]["Name"] : null]
  controller_name = [for item in local.controller_tags : item if item != null]
  copilot_tags    = [for item in aws_launch_template.avtx-copilot.tag_specifications : item["resource_type"] == "instance" ? item["tags"]["Name"] : null]
  copilot_name    = [for item in local.copilot_tags : item if item != null]
  controller_public_ip = var.use_existing_eip ? var.existing_eip : (length(aws_eip.controller_eip) > 0 ? aws_eip.controller_eip[0].public_ip : "")
  copilot_public_ip    = var.use_existing_copilot_eip ? var.existing_copilot_eip : (length(aws_eip.copilot_eip) > 0 ? aws_eip.copilot_eip[0].public_ip : "")
}

output "lb" {
  value = aws_lb.avtx-controller
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.log_group.name
}

output "controller_name" {
  value = local.controller_name[0]
}

output "copilot_name" {
  value = local.copilot_name[0]
}

output "controller_public_ip" {
  value = local.controller_public_ip
}

output "copilot_public_ip" {
  value = local.copilot_public_ip
}

output "lb_dns_name" {
  value = aws_lb.avtx-controller.dns_name
}
