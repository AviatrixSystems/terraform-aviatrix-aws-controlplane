variable "node_name" {
  description = "Data Node Name Prefix"
  type        = string
}

variable "node_key" {
  type        = number
  description = "Unique CoPilot Data Node Key"
}

variable "ami_id" {
  type        = string
  description = "CoPilot AMI name"
}

variable "instance_type" {
  type        = string
  description = "CoPilot Data Node instance Type"
  default     = "t3.2xlarge"
}

variable "controller_ip" {
  type        = string
  description = "Controller IP address"
}

variable "keypair" {
  type        = string
  description = "Key pair used by the Data Nodes"
}

variable "subnet_id" {
  type        = string
  description = "CoPilot Data Node Subnet"
}

variable "root_volume_size" {
  type        = number
  description = "Root volume disk size for Copilot Data Node"
  default     = 25
}

variable "root_volume_type" {
  type        = string
  description = "Root volume type for Copilot Data Node"
  default     = "gp3"
}

variable "default_data_volume_size" {
  type        = number
  description = "Default data disk volume size for Copilot Data Node"
  default     = 8
}

variable "default_data_volume_type" {
  type        = string
  description = "Default data disk volume type for Copilot Data Node"
  default     = "gp3"
}


variable "tags" {
  type        = map(string)
  description = "Map of common tags which should be used for module resources"
  default     = {}
}