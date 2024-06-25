locals {
  controller_tags      = [for item in aws_launch_template.avtx-controller.tag_specifications : item["resource_type"] == "instance" ? item["tags"]["Name"] : null]
  controller_name      = [for item in local.controller_tags : item if item != null]
  copilot_lt_tags      = var.copilot_deployment == "fault-tolerant" ? aws_launch_template.avtx-copilot-cluster-main[0].tag_specifications : aws_launch_template.avtx-copilot[0].tag_specifications
  copilot_tags         = [for item in local.copilot_lt_tags : item["resource_type"] == "instance" ? item["tags"]["Name"] : null]
  copilot_name         = [for item in local.copilot_tags : item if item != null]
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

output "lb_arn" {
  value = aws_lb.avtx-controller.arn
}

output "waf_arn" {
  value = var.configure_waf == true ? module.controller_alb_waf[0].waf_arn : ""
}

output "vpc_id" {
  value = var.use_existing_vpc ? var.vpc : aws_vpc.vpc[0].id
}

output "subnet_cidrs" {
  value = [data.aws_subnet.subnet1.cidr_block, data.aws_subnet.subnet2.cidr_block]
}

output "controller_sg_id" {
  value = aws_security_group.AviatrixSecurityGroup.id
}

output "rt_id_peering" {
  value = var.use_existing_vpc ? "" : aws_route_table.rtb[0].id
}

output "vpc_cidr_block" {
  value = data.aws_vpc.vpc.cidr_block
}
