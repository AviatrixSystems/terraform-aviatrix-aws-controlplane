data aws_region current {}

variable ha_distribution {
  type        = string
  description = "Desired Controller high availability distribution"
  default     = "inter-az"

  validation {
    condition     = contains(["inter-az", "inter-region"], var.ha_distribution)
    error_message = "Valid values for var: ha_distribution are (inter-az, inter-region)."
  }
}

variable keypair {
  type        = string
  description = "Key pair which should be used by Aviatrix controller"
}

variable instance_type {
  type        = string
  description = "Controller instance size"
  default     = "t3.large"
}

variable cop_instance_type {
  type        = string
  description = "CoPilot instance size"
  default     = "t3.2xlarge"
}

variable root_volume_type {
  type        = string
  description = "Root volume type for Controller"
  default     = "gp3"
}

# This is the default root volume size as suggested by Aviatrix
variable root_volume_size {
  type        = number
  description = "Root volume disk size for controller"
  default     = 32
}

variable copilot_name {
  default     = ""
  type        = string
  description = "Name of controller that will be launched"
}

variable cop_type {
  type        = string
  description = "Type of billing, can be 'Copilot' or 'CopilotARM'"
  default     = "Copilot"
}

variable cop_root_volume_size {
  type        = number
  description = "Root volume disk size for controller"
  default     = 2000
}

variable cop_root_volume_type {
  type        = string
  description = "Root volume type for controller"
  default     = "gp3"
}

variable incoming_ssl_cidr {
  type        = list(string)
  description = "Incoming cidr for security group used by controller"
}

variable cop_allowed_cidrs {
  type = map(object({
    protocol = string,
    port     = number
    cidrs    = set(string),
  }))
}

variable s3_backup_bucket {
  type        = string
  description = "S3 bucket for Controller DB backup"
}

variable s3_backup_region {
  type        = string
  description = "AWS region of S3 backup bucket"
}

variable termination_protection {
  type        = bool
  description = "Enable/disable switch for termination protection"
  default     = true
}

variable admin_email {
  type        = string
  description = "Controller admin email address"
}

variable asg_notif_email {
  type        = string
  description = "Email address for Controller failover notifications"
}

variable access_account_name {
  type        = string
  description = "The controller account friendly name (mapping to the AWS account ID)"
}

variable aws_account_id {
  type        = string
  description = "AWS account ID"
}

variable tags {
  type        = map(string)
  description = "Map of common tags which should be used for module resources"
  default     = {}
}

variable controller_version {
  type        = string
  default     = "latest"
  description = "The initial version of the Aviatrix Controller at launch"
}

variable vpc {
  type        = string
  description = "VPC in which you want launch Aviatrix controller"
}

variable "subnet_names" {
  type = list(string)
}

/*
variable private_ip {
  type        = string
  description = "Private IP of Aviatrix controller"
}

variable public_ip {
  type        = string
  description = "Public IP of Aviatrix controller"
}

variable ec2_role_name {
  type        = string
  description = "EC2 role name"
  default     = "aviatrix-role-ec2"
}

variable app_role_name {
  type        = string
  description = "APP role name"
  default     = "aviatrix-role-app"
}
*/
variable name_prefix {
  type        = string
  description = "Additional name prefix for your environment resources"
  default     = "avx"
}

variable license_type {
  default     = "BYOL"
  type        = string
  description = "Type of billing, can be 'MeteredPlatinum', 'BYOL' or 'Custom'"
}

locals {
  name_prefix     = var.name_prefix != "" ? "${var.name_prefix}-" : ""
  images_byol     = jsondecode(data.http.avx_iam_id.body).BYOL
  images_platinum = jsondecode(data.http.avx_iam_id.body).MeteredPlatinum
  images_custom   = jsondecode(data.http.avx_iam_id.body).Custom
  #  images_copilot  = jsondecode(data.http.avx_iam_id.body).MeteredPlatinumCopilot
  images_copilot    = jsondecode(data.http.copilot_iam_id.body).Copilot
  images_copilotarm = jsondecode(data.http.copilot_iam_id.body).CopilotARM
  cop_ami_id        = var.cop_type == "Copilot" ? local.images_copilot[data.aws_region.current.name] : local.images_copilotarm[data.aws_region.current.name]
  ami_id            = var.license_type == "MeteredPlatinumCopilot" ? local.images_copilot[data.aws_region.current.name] : (var.license_type == "Custom" ? local.images_custom[data.aws_region.current.name] : (var.license_type == "BYOL" || var.license_type == "byol" ? local.images_byol[data.aws_region.current.name] : local.images_platinum[data.aws_region.current.name]))

  common_tags = merge(
    var.tags, {
      module    = "aviatrix-controller-build"
      Createdby = "Terraform+Aviatrix"
  })
}


data http avx_iam_id {
  url = "https://s3-us-west-2.amazonaws.com/aviatrix-download/AMI_ID/ami_id.json"
  request_headers = {
    "Accept" = "application/json"
  }
}

data http copilot_iam_id {
  url = "https://aviatrix-download.s3.us-west-2.amazonaws.com/AMI_ID/copilot_ami_id.json"
  request_headers = {
    "Accept" = "application/json"
  }
}

