variable "account_email" {
  type        = string
  description = "aviatrix controller access account email"
}

variable "customer_id" {
  type        = string
  description = "aviatrix customer license id"
}

variable "controller_ami_id" {
  type        = string
  description = "AMI ID for controller. If unset, use official image."
  default     = ""
}

variable "controller_user_data" {
  type        = string
  description = "User data for starting the controller"
  default     = ""
}

variable "use_existing_keypair" {
  type        = bool
  default     = false
  description = "Flag to indicate whether to use an existing key pair"
}

variable "key_pair_name" {
  type        = string
  description = "Key pair name"
  default     = ""
}

variable "controller_admin_email" {
  type        = string
  description = "aviatrix controller admin email address"
}

variable "controller_admin_password" {
  type        = string
  description = "aviatrix controller admin password"
}

variable "controller_name" {
  type        = string
  description = "Customized Name for Aviatrix Controller"
  default     = "Aviatrix-Controller"

  validation {
    condition     = can(regex("^[^\\\\/\"\\[\\]:|<>+=;,?*@&~!#$%^()_{}']*$", var.controller_name))
    error_message = "Input string cannot contain the following special characters: `\\` `/` `\"` `[` `]` `:` `|` `<` `>` `+` `=` `;` `,` `?` `*` `@` `&` `~` `!` `#` `$` `%` `^` `(` `)` `_` `{` `}` `'`"
  }
}

variable "controller_wait_for_setup_duration" {
  type        = string
  description = "Duration to wait for controller setup to complete"
  default     = "10m"
}

variable "copilot_name" {
  type        = string
  description = "Customized Name for Aviatrix Copilot"
  default     = "Aviatrix-Copilot"
}

variable "controlplane_subnet_cidr" {
  type        = string
  description = "CIDR for controlplane subnet."
  default     = "10.0.0.0/24"
}

variable "controller_version" {
  type        = string
  description = "Aviatrix Controller version"
  default     = "latest"
}

variable "controller_virtual_machine_admin_username" {
  type        = string
  description = "Admin Username for the controller virtual machine."
  default     = "aviatrix"
}

variable "controller_virtual_machine_admin_password" {
  type        = string
  description = "Admin Password for the controller virtual machine."
  default     = "aviatrix1234!"
}

variable "controller_virtual_machine_size" {
  type        = string
  description = "Virtual Machine size for the controller."
  default     = "t3a.large"
}

variable "incoming_ssl_cidrs" {
  type        = list(string)
  description = "Incoming cidrs for security group used by controller"
}

variable "region" {
  type        = string
  description = "Deployment region for Aviatrix Controller"
  default     = "us-east-1"
}

variable "use_existing_vpc" {
  type        = bool
  description = "Flag to indicate whether to use an existing VPC"
  default     = false
}

variable "vpc_name" {
  type        = string
  description = "VPC name, only required when use_existing_vpc is true"
  default     = ""
}

variable "subnet_name" {
  type        = string
  description = "subnet name, only required when use_existing_vpc is true"
  default     = ""
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID, only required when use_existing_vpc is true"
  default     = ""
}

variable "virtual_machine_admin_username" {
  default = "avx_admin"
}

variable "virtual_machine_admin_password" {
  default = ""
}

variable "module_config" {
  default = {
    controller_iam            = true,
    controller_deployment     = true,
    controller_initialization = true,
    copilot_deployment        = true,
    copilot_initialization    = true,
  }
}
