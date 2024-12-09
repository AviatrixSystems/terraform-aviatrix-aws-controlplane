locals {
  virtual_machine_admin_password = var.virtual_machine_admin_password != "" ? var.virtual_machine_admin_password : var.controller_admin_password

  controller_allowed_cidrs = var.module_config.copilot_deployment ? concat(var.incoming_ssl_cidrs, [format("%s/32", module.copilot_build[0].public_ip)]) : var.incoming_ssl_cidrs
}
