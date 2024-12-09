module "iam" {
  count = var.module_config.controller_iam ? 1 : 0

  source = "./modules/iam_roles"

  name_prefix = "test"
}

module "controller_build" {
  count = var.module_config.controller_deployment ? 1 : 0

  source               = "./modules/controller_build"
  controller_name      = var.controller_name
  use_existing_vpc     = var.use_existing_vpc
  incoming_ssl_cidrs   = local.controller_allowed_cidrs
  ami_id               = var.controller_ami_id
  user_data            = var.controller_user_data
  use_existing_keypair = var.use_existing_keypair
  key_pair_name        = var.key_pair_name

  ec2_role_name = var.module_config.controller_iam ? module.iam[0].ec2_role_name : ""
}

module "controller_init" {
  count = var.module_config.controller_initialization ? 1 : 0

  source  = "terraform-aviatrix-modules/controller-init/aviatrix"
  version = "v1.0.3"

  controller_public_ip      = module.controller_build[0].public_ip
  controller_private_ip     = module.controller_build[0].private_ip
  controller_admin_email    = var.controller_admin_email
  controller_admin_password = var.controller_admin_password
  customer_id               = var.customer_id
  wait_for_setup_duration   = var.controller_wait_for_setup_duration

  depends_on = [module.controller_build]
}

module "copilot_build" {
  count = var.module_config.copilot_deployment ? 1 : 0

  source = "./modules/copilot_build"

  use_existing_vpc = true
  vpc_id           = module.controller_build[0].vpc_id
  subnet_id        = module.controller_build[0].subnet_id

  controller_public_ip  = module.controller_build[0].public_ip
  controller_private_ip = module.controller_build[0].private_ip
  copilot_name          = var.copilot_name
  allowed_cidrs = {
    "https" = {
      protocol = "tcp"
      port     = 443
      cidrs    = var.incoming_ssl_cidrs
    }
    "syslog" = {
      protocol = "udp"
      port     = 5000,
      cidrs    = [format("%s/32", module.controller_build[0].public_ip)]
    }
    "netflow" = {
      protocol = "udp"
      port     = 31283
      cidrs    = [format("%s/32", module.controller_build[0].public_ip)]
    }
  }
}

module "copilot_init" {
  count = var.module_config.copilot_initialization ? 1 : 0

  source  = "terraform-aviatrix-modules/copilot-init/aviatrix"
  version = "v1.0.3"

  controller_public_ip             = module.controller_build[0].public_ip
  controller_admin_password        = var.controller_admin_password
  copilot_public_ip                = module.copilot_build[0].public_ip
  service_account_email            = var.controller_admin_email
  copilot_service_account_password = local.virtual_machine_admin_password

  depends_on = [module.controller_init]
}
