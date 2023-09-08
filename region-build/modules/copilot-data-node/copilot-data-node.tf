resource "aws_network_interface" "eni-copilot" {
  subnet_id       = var.subnet_id
  security_groups = [aws_security_group.AviatrixCopilotSecurityGroup.id]
  tags = merge(var.tags, {
    Name = "${var.node_name}-data-${var.node_key}-eni"
  })

  lifecycle {
    ignore_changes = [
      security_groups,
    ]
  }
}

data "aws_subnet" "subnet" {
  id    = var.subnet_id
}

resource "aws_instance" "aviatrixcopilot" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.keypair
  availability_zone      = data.aws_subnet.subnet.availability_zone
  user_data = <<EOF
#!/bin/bash
jq '.config.controllerIp="${var.controller_ip}" | .config.controllerPublicIp="${var.controller_ip}" | .config.isCluster=true' /etc/copilot/db.json > /etc/copilot/db.json.tmp
mv /etc/copilot/db.json.tmp /etc/copilot/db.json
EOF
  network_interface {
    network_interface_id = aws_network_interface.eni-copilot.id
    device_index         = 0
  }

  root_block_device {
    volume_size = var.root_volume_size
    volume_type = var.root_volume_type
  }

  tags = merge(var.tags, {
    Name = "${var.node_name}-data-${var.node_key}"
  })
}

resource "aws_ebs_volume" "data" {
  availability_zone = data.aws_subnet.subnet.availability_zone
  size              = var.default_data_volume_size
  type              = var.default_data_volume_type
  tags = {
    Name = "${var.node_name}-data-${var.node_key}-ebs"
  }
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sda2"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.aviatrixcopilot.id
}

resource "aws_security_group" "AviatrixCopilotSecurityGroup" {
  name        = "${var.node_name}CopilotDataNodeSG-${var.node_key}"
  description = "Aviatrix - Copilot Data Node ${var.node_key} Security Group"
  vpc_id      = data.aws_subnet.subnet.vpc_id

  tags = merge(var.tags, {
    Name = "${var.node_name}CopilotDataNodeSG-${var.node_key}"
  })
}

resource "aws_security_group_rule" "copilot_https_ingress_rule" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup.id
  description       = "CoPilot Data Node ${var.node_key} HTTPS Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_syslog_ingress_rule" {
  type              = "ingress"
  from_port         = 5000
  to_port           = 5000
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup.id
  description       = "CoPilot Data Node ${var.node_key} Syslog Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_netflow_ingress_rule" {
  type              = "ingress"
  from_port         = 31283
  to_port           = 31283
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup.id
  description       = "CoPilot Data Node ${var.node_key} Netflow Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_egress_rule" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup.id
}