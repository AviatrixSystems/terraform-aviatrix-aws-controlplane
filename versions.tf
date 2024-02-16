terraform {
  required_providers {
    aviatrix = {
      source = "aviatrixsystems/aviatrix"
    }
    aws = {
      source = "hashicorp/aws"
    }
    # docker = {
    #   source = "kreuzwerker/docker"
    # }
  }
  required_version = ">= 0.13"
}
