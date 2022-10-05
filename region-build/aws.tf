terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
  required_version = ">= 0.13"
}

# provider "aws" {
#   # alias = "region1"
#   region = var.region
# }

# provider "aws" {
#   alias  = "region2"
#   region = var.dr_region
# }

resource "aws_vpc" "vpc" {
  count      = var.use_existing_vpc ? 0 : 1
  cidr_block = var.vpc_cidr
  tags = {
    Name = var.vpc_name
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "subnet" {
  count                = var.use_existing_vpc ? 0 : 1
  vpc_id               = aws_vpc.vpc[0].id
  cidr_block           = cidrsubnet(var.vpc_cidr, 4, 1)
  availability_zone_id = data.aws_availability_zones.available.zone_ids[0]
  tags = {
    Name = "${var.subnet_name}-1"
  }
}

resource "aws_subnet" "subnet_ha" {
  count                = var.use_existing_vpc ? 0 : 1
  vpc_id               = aws_vpc.vpc[0].id
  cidr_block           = cidrsubnet(var.vpc_cidr, 4, 2)
  availability_zone_id = data.aws_availability_zones.available.zone_ids[1]
  tags = {
    Name = "${var.subnet_name}-2"
  }
}

resource "aws_internet_gateway" "igw" {
  count  = var.use_existing_vpc ? 0 : 1
  vpc_id = aws_vpc.vpc[0].id
  tags = {
    Name = "${var.vpc_name}-igw"
  }
}

resource "aws_route_table" "rtb" {
  count  = var.use_existing_vpc ? 0 : 1
  vpc_id = aws_vpc.vpc[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw[0].id
  }
  tags = {
    Name = "${var.vpc_name}-rtb"
  }
}

resource "aws_route_table_association" "rtb_association" {
  count          = var.use_existing_vpc ? 0 : 1
  subnet_id      = aws_subnet.subnet[0].id
  route_table_id = aws_route_table.rtb[0].id
}

resource "aws_route_table_association" "rtb_association_ha" {
  count          = var.use_existing_vpc ? 0 : 1
  subnet_id      = aws_subnet.subnet_ha[0].id
  route_table_id = aws_route_table.rtb[0].id
}

##############

# resource "aws_vpc" "dr_vpc" {
#   provider   = aws.region2
#   count      = var.ha_distribution == "inter-region" ? (var.use_existing_vpc ? 0 : 1) : 0
#   cidr_block = var.dr_vpc_cidr
#   tags = {
#     Name = var.dr_vpc_name
#   }
# }

# data "aws_availability_zones" "dr_available" {
#   count    = var.ha_distribution == "inter-region" ? 1 : 0
#   provider = aws.region2
#   state    = "available"
# }

# resource "aws_subnet" "dr_subnet" {
#   provider             = aws.region2
#   count                = var.ha_distribution == "inter-region" ? (var.use_existing_vpc ? 0 : 1) : 0
#   vpc_id               = aws_vpc.dr_vpc[0].id
#   cidr_block           = cidrsubnet(var.dr_vpc_cidr, 4, 1)
#   availability_zone_id = data.aws_availability_zones.dr_available[0].zone_ids[0]
#   tags = {
#     Name = "${var.subnet_name}-1"
#   }
# }

# resource "aws_subnet" "dr_subnet_ha" {
#   provider             = aws.region2
#   count                = var.ha_distribution == "inter-region" ? (var.use_existing_vpc ? 0 : 1) : 0
#   vpc_id               = aws_vpc.dr_vpc[0].id
#   cidr_block           = cidrsubnet(var.dr_vpc_cidr, 4, 2)
#   availability_zone_id = data.aws_availability_zones.dr_available[0].zone_ids[1]
#   tags = {
#     Name = "${var.subnet_name}-2"
#   }
# }

# resource "aws_internet_gateway" "dr_igw" {
#   provider = aws.region2
#   count    = var.ha_distribution == "inter-region" ? (var.use_existing_vpc ? 0 : 1) : 0
#   vpc_id   = aws_vpc.dr_vpc[0].id
#   tags = {
#     Name = "${var.dr_vpc_name}-igw"
#   }
# }

# resource "aws_route_table" "dr_rtb" {
#   provider = aws.region2
#   count    = var.ha_distribution == "inter-region" ? (var.use_existing_vpc ? 0 : 1) : 0
#   vpc_id   = aws_vpc.dr_vpc[0].id
#   route {
#     cidr_block = "0.0.0.0/0"
#     gateway_id = aws_internet_gateway.dr_igw[0].id
#   }
#   tags = {
#     Name = "${var.dr_vpc_name}-rtb"
#   }
# }

# resource "aws_route_table_association" "dr_rtb_association" {
#   provider       = aws.region2
#   count          = var.ha_distribution == "inter-region" ? (var.use_existing_vpc ? 0 : 1) : 0
#   subnet_id      = aws_subnet.dr_subnet[0].id
#   route_table_id = aws_route_table.dr_rtb[0].id
# }

# resource "aws_route_table_association" "dr_rtb_association_ha" {
#   provider       = aws.region2
#   count          = var.ha_distribution == "inter-region" ? (var.use_existing_vpc ? 0 : 1) : 0
#   subnet_id      = aws_subnet.dr_subnet_ha[0].id
#   route_table_id = aws_route_table.dr_rtb[0].id
# }




