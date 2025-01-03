terraform {
  required_providers {
    aviatrix = {
      source = "aviatrixsystems/aviatrix"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.27"
    }
  }
  required_version = ">= 0.13"
}
