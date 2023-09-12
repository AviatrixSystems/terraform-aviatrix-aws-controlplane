variable "region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "aws_access_key" {
  type        = string
  description = "AWS access key"
}

variable "aws_secret_key" {
  type        = string
  description = "AWS secret access key"
}

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region     = var.region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

module "data_nodes" {
  count = 3
  source = "../copilot-data-node/"

  node_name = "cplt"
  node_key = count.index
  ami_id = "ami-01f93fe138696bc39"
  instance_type = "t3.2xlarge"
  keypair = "shaheer-us-east-1"
  subnet_id = local.data_node_subnets[count.index % length(local.data_node_subnets)]
  root_volume_size = 25
  root_volume_type = "gp3"
  default_data_volume_size = 8
  default_data_volume_type = "gp3"
  tags = {}
}

locals {
  data_node_subnets = ["subnet-0a7d5b2ca4094c76e", "subnet-00e9031dd148308bd"]
}

output "instance_ids" {
  description = "Data Node Instance IDs"
  value       = join(",", module.data_nodes.*.instance_id)
}

output "instance_names" {
  description = "Data Node Instance IDs"
  value       = join(",", module.data_nodes.*.instance_name)
}

output "sg_ids" {
  description = "Data Node SG IDs"
  value       = join(",", module.data_nodes.*.sg_id)
}

output "sg_names" {
  description = "Data Node SG names"
  value       = join(",", module.data_nodes.*.sg_name)
}

output "instance_private_ips" {
  description = "Data Node Instance IDs"
  value       = join(",", module.data_nodes.*.instance_private_ip)
}

output "instance_details" {
  description = "Data Node Instance IDs"
  value       = jsonencode(module.data_nodes.*.instance_details)
}

