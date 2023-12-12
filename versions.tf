terraform {
  required_providers {
    aviatrix = {
      source = "aviatrixsystems/aviatrix"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~>5.16.1"

    }
    # docker = {
    #   source = "kreuzwerker/docker"
    # }
  }
  required_version = ">= 0.13"
}
