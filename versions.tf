terraform {
  required_providers {
    aviatrix = {
      source = "aviatrixsystems/aviatrix"
    }
    aws = {
      source = "hashicorp/aws"
      version = "~>4.20.0"
    }
  }
  required_version = ">= 0.13"
}
