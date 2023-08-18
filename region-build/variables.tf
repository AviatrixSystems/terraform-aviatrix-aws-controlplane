data "aws_region" "current" {}

variable "ha_distribution" {
  type        = string
  description = "Desired Controller high availability distribution"
  default     = "single-az"

  validation {
    condition     = contains(["inter-az", "single-az", "inter-region"], var.ha_distribution)
    error_message = "Valid values for var: ha_distribution are (inter-az, single-az and inter-region)."
  }
}

variable "keypair" {
  type        = string
  description = "Key pair which should be used by Aviatrix controller"
}

variable "region" {
  type        = string
  description = "The region to deploy this module in"
}

variable "create_iam_roles" {
  type    = bool
  default = true
}

variable "ec2_role_name" {
  type    = string
  default = "aviatrix-role-ec2"
}

variable "app_role_name" {
  type    = string
  default = "aviatrix-role-app"
}

variable "vpc_name" {
  type    = string
  default = "Aviatrix-VPC"
}

variable "subnet_name" {
  type    = string
  default = "Aviatrix-Public-Subnet"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/24"
}

variable "instance_type" {
  type        = string
  description = "Controller instance size"
  default     = "t3.large"
}

variable "copilot_deployment" {
  type        = string
  description = "Desired CoPilot deployment type"
  default     = "simple"

  validation {
    condition     = contains(["simple", "fault-tolerant"], var.copilot_deployment)
    error_message = "Valid values for var:copilot_deployment are (simple, fault-tolerant)."
  }
}

variable "copilot_data_node_count" {
  type        = number
  description = "Desired number of CoPilot data nodes in a Fault-Tolerant deployment"
  default     = 3

  validation {
    condition = (
      var.copilot_data_node_count >= 3 && var.copilot_data_node_count <= 9
    )
    error_message = "CoPilot data node count must be between 3 and 9, inclusive."
  }
}

variable "cop_instance_type" {
  type        = string
  description = "CoPilot instance size"
  default     = "t3.2xlarge"
}

variable "root_volume_type" {
  type        = string
  description = "Root volume type for Controller"
  default     = "gp3"
}

# This is the default root volume size as suggested by Aviatrix
variable "root_volume_size" {
  type        = number
  description = "Root volume disk size for controller"
  default     = 64
}

variable "copilot_name" {
  default     = ""
  type        = string
  description = "Name of controller that will be launched"
}

variable "copilot_username" {
  default     = ""
  type        = string
  description = "CoPilot service account username, if desired"
}

variable "copilot_email" {
  default     = ""
  type        = string
  description = "CoPilot user email address, if desired"
}

variable "cop_type" {
  type        = string
  description = "Type of billing, can be 'Copilot' or 'CopilotARM'"
  default     = "Copilot"
}

variable "cop_root_volume_size" {
  type        = number
  description = "Root volume disk size for Copilot"
  default     = 25
}

variable "cop_root_volume_type" {
  type        = string
  description = "Root volume type for Copilot"
  default     = "gp3"
}

variable "cop_default_data_volume_size" {
  type        = number
  description = "Default data disk volume size for Copilot"
  default     = 8
}

variable "cop_default_data_volume_type" {
  type        = string
  description = "Default data disk volume type for Copilot"
  default     = "gp3"
}

variable "cop_controller_auth_ip" {
  type        = string
  description = "Controller IP type to be used by CoPilot for authentication - public, or private"
  default     = "public"
}

variable "incoming_ssl_cidr" {
  type        = list(string)
  description = "Incoming cidr for security group used by controller"
}

variable "cop_incoming_https_cidr" {
  type        = list(string)
  description = "Incoming CIDR for HTTPS access to the CoPilot"
}

variable "cop_incoming_syslog_cidr" {
  type        = list(string)
  description = "Incoming CIDR for Syslog sources to the CoPilot"
  default     = ["0.0.0.0/0"]
}

variable "cop_incoming_netflow_cidr" {
  type        = list(string)
  description = "Incoming CIDR for Netflow sources to the CoPilot"
  default     = ["0.0.0.0/0"]
}

variable "s3_backup_bucket" {
  type        = string
  description = "S3 bucket for Controller DB backup"
}

variable "s3_backup_region" {
  type        = string
  description = "AWS region of S3 backup bucket"
}

variable "termination_protection" {
  type        = bool
  description = "Enable/disable switch for termination protection"
  default     = true
}

variable "admin_email" {
  type        = string
  description = "Controller admin email address"
}

variable "asg_notif_email" {
  type        = string
  description = "Email address for Controller failover notifications"
}

variable "access_account_name" {
  type        = string
  description = "The controller account friendly name (mapping to the AWS account ID)"
}

variable "tags" {
  type        = map(string)
  description = "Map of common tags which should be used for module resources"
  default     = {}
}

variable "controller_version" {
  type        = string
  default     = ""
  description = "The initial version of the Aviatrix Controller at launch"
}

variable "use_existing_vpc" {
  description = "Set to true to use existing VPC."
  type        = bool
  default     = false
}

variable "vpc" {
  type        = string
  description = "VPC in which you want launch Aviatrix controller"
  default     = ""
}

variable "subnet_names" {
  type    = list(string)
  default = []
}

variable "name_prefix" {
  type        = string
  description = "Additional name prefix for your environment resources"
  default     = "avx"
}

variable "license_type" {
  default     = "BYOL"
  type        = string
  description = "Type of billing, can be 'MeteredPlatinum', 'BYOL' or 'Custom'"
}

locals {
  name_prefix       = var.name_prefix != "" ? "${var.name_prefix}-" : ""
  images_byol       = jsondecode(data.http.avx_iam_id.response_body).BYOL
  images_platinum   = jsondecode(data.http.avx_iam_id.response_body).MeteredPlatinum
  images_custom     = jsondecode(data.http.avx_iam_id.response_body).Custom
  images_copilot    = jsondecode(data.http.copilot_iam_id.response_body).Copilot
  images_copilotarm = jsondecode(data.http.copilot_iam_id.response_body).CopilotARM
  cop_ami_id        = var.cop_type == "Copilot" ? local.images_copilot[data.aws_region.current.name] : local.images_copilotarm[data.aws_region.current.name]
  ami_id            = var.license_type == "MeteredPlatinumCopilot" ? local.images_copilot[data.aws_region.current.name] : (var.license_type == "Custom" ? local.images_custom[data.aws_region.current.name] : (var.license_type == "BYOL" || var.license_type == "byol" ? local.images_byol[data.aws_region.current.name] : local.images_platinum[data.aws_region.current.name]))

  cop_tag = var.copilot_name != "" ? var.copilot_name : "${local.name_prefix}AviatrixCopilot"

  common_tags = merge(
    var.tags, {
      module    = "aviatrix-controller-build"
      Createdby = "Terraform+Aviatrix"
  })
}


data "http" "avx_iam_id" {
  url = "https://s3-us-west-2.amazonaws.com/aviatrix-download/AMI_ID/ami_id.json"
  request_headers = {
    "Accept" = "application/json"
  }
}

data "http" "copilot_iam_id" {
  url = "https://aviatrix-download.s3.us-west-2.amazonaws.com/AMI_ID/copilot_ami_id.json"
  request_headers = {
    "Accept" = "application/json"
  }
}

variable "dr_region" {
  type        = string
  description = "DR Region for Aviatrix Controller"
  default     = ""
}

variable "zone_name" {
  type        = string
  description = "The exisitng route 53 zone name"
  default     = true
}

variable "record_name" {
  type        = string
  description = "The record name to be created under exisitng route 53 zone"
  default     = true
}

variable "iam_for_ecs_arn" {
  type        = string
  description = "The ARN of the IAM for ECS"
}

variable "inter_region_primary" {
  type        = string
  description = "For the inter-region scenario, this is the primary region."
  default     = ""
}

variable "inter_region_standby" {
  type        = string
  description = "For the inter-region scenario, this is the standby region."
  default     = ""
}

variable "inter_region_backup_enabled" {
  type        = bool
  description = "Specifies whether backups should be enabled on the primary controller in an inter-region deployment"
  default     = false
}

variable "ecr_image" {
  type        = string
  description = "The AMI ID of the Aviatrix Controller"
  default     = ""
}

variable "avx_customer_id_ssm_path" {
  type        = string
  description = "The path to the Aviatrix customer ID"
  default     = "/aviatrix/controller/customer_id"
}

variable "avx_customer_id_ssm_region" {
  type        = string
  description = "The region the customer ID parameter is in"
  default     = "us-east-1"
}

variable "avx_password_ssm_path" {
  type        = string
  description = "The path to the Aviatrix password"
  default     = "/aviatrix/controller/password"
}

variable "avx_copilot_password_ssm_path" {
  type        = string
  description = "The path to the password for CoPilot"
  default     = "/aviatrix/controller/password"
}

variable "avx_password_ssm_region" {
  type        = string
  description = "The region the password parameter is in"
  default     = "us-east-1"
}

variable "avx_customer_id" {
  type        = string
  description = "The customer ID"
  default     = ""
}

variable "avx_password" {
  type        = string
  description = "The admin password for the Aviatrix Controller"
  default     = ""
}

variable "avx_copilot_password" {
  type        = string
  description = "The service account password for the Aviatrix CoPilot"
  default     = ""
}

variable "attach_eventbridge_role_arn" {
  description = "EventBridge role ARN"
}

variable "use_existing_eip" {
  type        = bool
  description = "Set to true if using an existing EIP"
  default     = false
}

variable "existing_eip" {
  type        = string
  description = "Existing EIP to associate with the Aviatrix Controller"
  default     = ""
}

variable "use_existing_copilot_eip" {
  type        = bool
  description = "Set to true if using an existing EIP for CoPilot"
  default     = false
}

variable "existing_copilot_eip" {
  type        = string
  description = "Existing EIP to associate with the Aviatrix CoPilot"
  default     = ""
}

variable "existing_data_nodes_eips" {
  type        = list(string)
  description = "Existing EIP to associate with the Aviatrix CoPilot (Main Node, in a Fault-Tolerant deployment)"
  default     = [""]
}
