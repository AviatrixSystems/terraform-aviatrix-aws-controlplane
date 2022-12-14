terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
  required_version = ">= 0.13"
}

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
