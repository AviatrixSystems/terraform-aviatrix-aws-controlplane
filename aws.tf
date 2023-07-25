provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Aviatrix-Created-Resource = "Do-Not-Delete-Aviatrix-Created-Resource"
    }
  }
}

provider "aws" {
  alias  = "region2"
  region = var.dr_region
  default_tags {
    tags = {
      Aviatrix-Created-Resource = "Do-Not-Delete-Aviatrix-Created-Resource"
    }
  }
}
