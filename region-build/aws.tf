terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
  required_version = ">= 0.13"
}

resource "aws_vpc" "vpc" {
  #checkov:skip=CKV2_AWS_11: Ensure VPC flow logging is enabled in all VPCs - AVXIT-7603
  #checkov:skip=CKV2_AWS_12: Ensure the default security group of every VPC restricts all traffic - AVXIT-7604
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

  # Force delete SG script to run at the end when only the VPC is left
  depends_on = [
    null_resource.delete_sg_script
  ]
}

resource "aws_subnet" "subnet_ha" {
  count                = var.use_existing_vpc ? 0 : 1
  vpc_id               = aws_vpc.vpc[0].id
  cidr_block           = cidrsubnet(var.vpc_cidr, 4, 2)
  availability_zone_id = data.aws_availability_zones.available.zone_ids[1]
  tags = {
    Name = "${var.subnet_name}-2"
  }

  # Force delete SG script to run at the end when only the VPC is left
  depends_on = [
    null_resource.delete_sg_script
  ]
}

resource "aws_internet_gateway" "igw" {
  count  = var.use_existing_vpc ? 0 : 1
  vpc_id = aws_vpc.vpc[0].id
  tags = {
    Name = "${var.vpc_name}-igw"
  }

  # Force delete SG script to run at the end when only the VPC is left
  depends_on = [
    null_resource.delete_sg_script
  ]
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

  lifecycle {
    ignore_changes = [route]
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

resource "tls_private_key" "key_pair_material" {
  count     = var.use_existing_keypair ? 0 : 1
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "key_pair" {
  count      = var.use_existing_keypair ? 0 : 1
  key_name   = var.keypair
  public_key = tls_private_key.key_pair_material[0].public_key_openssh
}

# Inter-region-v2

resource "aws_subnet" "subnet_private_1" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  vpc_id               = aws_vpc.vpc[0].id
  cidr_block           = cidrsubnet(var.vpc_cidr, 4, 3)
  availability_zone_id = data.aws_availability_zones.available.zone_ids[0]
  tags = {
    Name = "${var.subnet_name}-private-1"
  }
}

resource "aws_subnet" "subnet_private_2" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  vpc_id               = aws_vpc.vpc[0].id
  cidr_block           = cidrsubnet(var.vpc_cidr, 4, 4)
  availability_zone_id = data.aws_availability_zones.available.zone_ids[1]
  tags = {
    Name = "${var.subnet_name}-private-2"
  }
}

resource "aws_eip" "natgw_1" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  domain = "vpc"
  tags   = merge(local.common_tags, tomap({ "Name" = "Aviatrix-HA-NAT-GW-1" }))
}

resource "aws_eip" "natgw_2" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  domain = "vpc"
  tags   = merge(local.common_tags, tomap({ "Name" = "Aviatrix-HA-NAT-GW-2" }))
}

resource "aws_nat_gateway" "natgw_1" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  allocation_id = aws_eip.natgw_1[0].id
  subnet_id     = aws_subnet.subnet[0].id
  tags = {
    Name = "${var.vpc_name}-natgw-1"
  }
}

resource "aws_nat_gateway" "natgw_2" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  allocation_id = aws_eip.natgw_2[0].id
  subnet_id     = aws_subnet.subnet_ha[0].id
  tags = {
    Name = "${var.vpc_name}-natgw-2"
  }
}

resource "aws_route_table" "rtb_private_1" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  vpc_id = aws_vpc.vpc[0].id
  tags = {
    Name = "${var.vpc_name}-private-rtb-1"
  }
}

resource "aws_route" "r1" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  route_table_id         = aws_route_table.rtb_private_1[0].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.natgw_1[0].id
}

resource "aws_route_table" "rtb_private_2" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  vpc_id = aws_vpc.vpc[0].id
  tags = {
    Name = "${var.vpc_name}-private-rtb-2"
  }
}

resource "aws_route" "r2" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  route_table_id         = aws_route_table.rtb_private_2[0].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.natgw_2[0].id
}

resource "aws_route_table_association" "private_1" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  subnet_id      = aws_subnet.subnet_private_1[0].id
  route_table_id = aws_route_table.rtb_private_1[0].id
}

resource "aws_route_table_association" "private_2" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  subnet_id      = aws_subnet.subnet_private_2[0].id
  route_table_id = aws_route_table.rtb_private_2[0].id
}
