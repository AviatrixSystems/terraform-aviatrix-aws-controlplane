locals {
  is_inter_region         = var.ha_distribution == "inter-region" ? true : false
  zone_name               = local.is_inter_region ? var.zone_name : ""
  record_name             = local.is_inter_region ? var.record_name : ""
  dr_region               = local.is_inter_region ? var.dr_region : ""
  dr_controller_public_ip = local.is_inter_region ? module.region2[0].controller_public_ip : ""
  dr_copilot_public_ip    = local.is_inter_region ? module.region2[0].copilot_public_ip : ""
  dr_lb_dns_name          = local.is_inter_region ? module.region2[0].lb_dns_name : ""
  dr_lb_arn               = local.is_inter_region ? module.region2[0].lb_arn : ""
  dr_waf_arn              = local.is_inter_region ? module.region2[0].waf_arn : ""
}

output "ha_distribution" {
  value = var.ha_distribution
}

output "zone_name" {
  value = local.zone_name
}

output "record_name" {
  value = local.record_name
}

output "s3_backup_region" {
  value = var.ha_distribution == "basic" ? "" : var.s3_backup_region
}

output "s3_backup_bucket" {
  value = try(var.ha_distribution == "basic" ? "" : var.use_existing_s3 ? var.s3_backup_bucket : aws_s3_bucket.backup[0].id, "")
}

output "log_group_name" {
  value = var.ha_distribution == "basic" ? "" : module.region1[0].log_group_name
}

output "controller_name" {
  value = var.ha_distribution == "basic" ? "AviatrixController" : module.region1[0].controller_name
}

output "copilot_name" {
  value = var.ha_distribution == "basic" ? "AviatrixCoPilot" : module.region1[0].copilot_name
}

output "region" {
  value = var.region
}

output "dr_region" {
  value = local.dr_region
}

output "controller_public_ip" {
  value = var.ha_distribution == "basic" ? aws_cloudformation_stack.cft[0].outputs["AviatrixControllerEIP"] : module.region1[0].controller_public_ip
}

output "dr_controller_public_ip" {
  value = local.dr_controller_public_ip
}

output "copilot_public_ip" {
  value = var.ha_distribution == "basic" ? aws_cloudformation_stack.cft[0].outputs["AviatrixCoPilotEIP"] : module.region1[0].copilot_public_ip
}

output "dr_copilot_public_ip" {
  value = local.dr_copilot_public_ip
}

output "lb_dns_name" {
  value = var.ha_distribution == "basic" ? "" : module.region1[0].lb_dns_name
}

output "dr_lb_dns_name" {
  value = local.dr_lb_dns_name
}

output "lb_arn" {
  value = var.ha_distribution == "basic" ? "" : module.region1[0].lb_arn
}

output "dr_lb_arn" {
  value = local.dr_lb_arn
}

output "waf_arn" {
  value = var.configure_waf == true ? module.region1.waf_arn : null
}

output "dr_waf_arn" {
  value = var.configure_waf == true ? local.dr_waf_arn : null
}

output "cft_output" {
  value = var.ha_distribution == "basic" ? aws_cloudformation_stack.cft[0].outputs : {}
}
