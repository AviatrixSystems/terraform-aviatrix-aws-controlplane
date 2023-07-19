resource "aws_network_interface" "eni-copilot" {
  subnet_id       = var.subnet_ids[count.index % length(var.subnet_ids)]
  count           = var.node_count
  security_groups = [aws_security_group.AviatrixCopilotSecurityGroup[count.index].id]
  tags = merge(var.tags, {
    Name = "${var.node_name}-data-${count.index}-eni"
  })

  lifecycle {
    ignore_changes = [
      security_groups,
    ]
  }
}

data "aws_subnet" "subnet" {
  count = var.node_count
  id    = var.subnet_ids[count.index % length(var.subnet_ids)]
}

resource "aws_instance" "aviatrixcopilot" {
  count                  = var.node_count
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.keypair
  availability_zone      = data.aws_subnet.subnet[count.index].availability_zone

  network_interface {
    network_interface_id = aws_network_interface.eni-copilot[count.index].id
    device_index         = 0
  }

  root_block_device {
    volume_size = var.root_volume_size
    volume_type = var.root_volume_type
  }

  tags = merge(var.tags, {
    Name = "${var.node_name}-data-${count.index}"
  })
}

resource "aws_ebs_volume" "data" {
  count             = var.node_count
  availability_zone = data.aws_subnet.subnet[count.index].availability_zone
  size              = var.default_data_volume_size
  type              = var.default_data_volume_type
  tags = {
    Name = "${var.node_name}-data-${count.index}-ebs"
  }
}

resource "aws_volume_attachment" "data" {
  count       = var.node_count
  device_name = "/dev/sda2"
  volume_id   = aws_ebs_volume.data[count.index].id
  instance_id = aws_instance.aviatrixcopilot[count.index].id
}

resource "aws_security_group" "AviatrixCopilotSecurityGroup" {
  count       = var.node_count
  name        = "${var.node_name}CopilotDataNodeSG-${count.index}"
  description = "Aviatrix - Copilot Data Node ${count.index} Security Group"
  vpc_id      = data.aws_subnet.subnet[count.index].vpc_id

  tags = merge(var.tags, {
    Name = "${var.node_name}CopilotDataNodeSG-${count.index}"
  })
}

resource "aws_security_group_rule" "copilot_https_ingress_rule" {
  count             = var.node_count
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup[count.index].id
  description       = "CoPilot Data Node ${count.index} HTTPS Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_syslog_ingress_rule" {
  count             = var.node_count
  type              = "ingress"
  from_port         = 5000
  to_port           = 5000
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup[count.index].id
  description       = "CoPilot Data Node ${count.index} Syslog Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_netflow_ingress_rule" {
  count             = var.node_count
  type              = "ingress"
  from_port         = 31283
  to_port           = 31283
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup[count.index].id
  description       = "CoPilot Data Node ${count.index} Netflow Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_egress_rule" {
  count             = var.node_count
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup[count.index].id
}
