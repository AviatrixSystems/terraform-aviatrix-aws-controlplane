provider "aws" {
  region = var.region
}

provider "aws" {
  alias  = "region2"
  region = var.dr_region
}
