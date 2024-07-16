resource "aws_launch_template" "avtx-copilot-cluster-main" {
  # checkov:skip=CKV_AWS_79: Ensure Instance Metadata Service Version 1 is not enabled - AVXIT-7528
  # checkov:skip=CKV_AWS_88: EC2 instance should not have public IP. - AVXIT-7529
  count       = var.copilot_deployment == "fault-tolerant" ? 1 : 0
  name        = "avtx-copilot-cluster-main"
  description = "Launch template for Aviatrix Copilot Cluster Main Node"

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.copilot_root_volume_size
      volume_type           = var.copilot_root_volume_type
      delete_on_termination = false
    }
  }

  monitoring {
    enabled = var.monitoring
  }

  disable_api_termination              = var.termination_protection
  image_id                             = var.copilot_ami_id != "" ? var.copilot_ami_id : local.cop_ami_id
  ebs_optimized                        = var.ebs_optimized
  instance_initiated_shutdown_behavior = "terminate"
  instance_type                        = var.copilot_instance_type
  key_name                             = var.keypair

  network_interfaces {
    device_index                = 0
    associate_public_ip_address = true
    security_groups             = [aws_security_group.AviatrixCopilotSecurityGroup.id]
  }

  tag_specifications {
    resource_type = "volume"

    tags = { Name = "AvxCopilot-Main" }
  }

  tag_specifications {
    resource_type = "instance"

    tags = merge(local.common_tags, {
      Name = "${local.cop_tag}-Main"
    })
  }

  depends_on = [module.data_nodes]
}


resource "aws_launch_template" "avtx-copilot" {
  count       = var.copilot_deployment == "fault-tolerant" ? 0 : 1
  name        = "avtx-copilot"
  description = "Launch template for Aviatrix Copilot"

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.copilot_root_volume_size
      volume_type           = var.copilot_root_volume_type
      delete_on_termination = true
    }
  }

  block_device_mappings {
    device_name = "/dev/sda2"

    ebs {
      volume_size           = var.copilot_default_data_volume_size
      volume_type           = var.copilot_default_data_volume_type
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = var.monitoring
  }

  disable_api_termination              = var.termination_protection
  image_id                             = var.copilot_ami_id != "" ? var.copilot_ami_id : local.cop_ami_id
  ebs_optimized                        = var.ebs_optimized
  instance_initiated_shutdown_behavior = "terminate"
  instance_type                        = var.copilot_instance_type
  key_name                             = var.keypair

  network_interfaces {
    device_index                = 0
    associate_public_ip_address = true
    security_groups             = [aws_security_group.AviatrixCopilotSecurityGroup.id]
  }

  tag_specifications {
    resource_type = "volume"

    tags = { Name = "AvxCopilot" }
  }

  tag_specifications {
    resource_type = "instance"

    tags = merge(local.common_tags, {
      Name = local.cop_tag
    })
  }
}

resource "aws_autoscaling_group" "avtx_copilot" {
  name                      = "avtx_copilot"
  max_size                  = 1
  min_size                  = 0
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1
  force_delete              = true
  suspended_processes       = var.copilot_ha_enabled ? null : ["Launch", "Terminate", "HealthCheck", "ReplaceUnhealthy"]

  launch_template {
    id      = var.copilot_deployment == "fault-tolerant" ? aws_launch_template.avtx-copilot-cluster-main[0].id : aws_launch_template.avtx-copilot[0].id
    version = "$Latest"
  }

  vpc_zone_identifier = var.use_existing_vpc ? var.subnet_ids : tolist([aws_subnet.subnet[0].id, aws_subnet.subnet_ha[0].id])
  target_group_arns   = [aws_lb_target_group.avtx-copilot.arn]

  initial_lifecycle_hook {
    name                 = "init"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 1200
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"

    notification_target_arn = aws_sns_topic.controller_updates.arn
    role_arn                = "arn:${local.iam_type}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
  }

  tag {
    key                 = "app"
    value               = "copilot"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = data.aws_default_tags.current.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  wait_for_capacity_timeout = "30m"
  timeouts {
    delete = "15m"
  }

  depends_on = [
    null_resource.delete_sg_script
  ]
}

# Define a listener
resource "aws_lb_listener" "avtx-copilot" {
  load_balancer_arn = aws_lb.avtx-controller.arn
  port              = "8443"
  protocol          = var.load_balancer_type == "application" ? "HTTPS" : "TCP"
  certificate_arn   = var.load_balancer_type == "application" ? var.alb_cert_arn : null

  default_action {
    target_group_arn = aws_lb_target_group.avtx-copilot.arn
    type             = "forward"
  }
}

resource "aws_lb_target_group" "avtx-copilot" {
  name     = "${local.name_prefix}copilot"
  port     = 443
  protocol = var.load_balancer_type == "application" ? "HTTPS" : "TCP"
  vpc_id   = var.use_existing_vpc ? var.vpc : aws_vpc.vpc[0].id

  depends_on = [aws_lb.avtx-controller]

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "AviatrixCopilotSecurityGroup" {
  name        = "${local.name_prefix}AviatrixCopilotSecurityGroup"
  description = "Aviatrix - Copilot Security Group"
  vpc_id      = var.use_existing_vpc ? var.vpc : aws_vpc.vpc[0].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}AviatrixCopilotSecurityGroup"
  })
}

resource "aws_security_group_rule" "copilot_https_ingress_rule" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = concat(var.copilot_incoming_https_cidr, tolist([var.vpc_cidr]))
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup.id
  description       = "CoPilot HTTPS Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_syslog_ingress_rule" {
  type              = "ingress"
  from_port         = 5000
  to_port           = 5000
  protocol          = "udp"
  cidr_blocks       = var.copilot_incoming_syslog_cidr
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup.id
  description       = "CoPilot Syslog Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_netflow_ingress_rule" {
  type              = "ingress"
  from_port         = 31283
  to_port           = 31283
  protocol          = "udp"
  cidr_blocks       = var.copilot_incoming_netflow_cidr
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup.id
  description       = "CoPilot Netflow Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_alb_ingress_rule" {
  type              = "ingress"
  from_port         = 8443
  to_port           = 8443
  protocol          = "tcp"
  cidr_blocks       = concat(var.copilot_incoming_https_cidr, tolist([var.vpc_cidr]))
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup.id
  description       = "CoPilot ALB Ingress - DO NOT DELETE"
}

resource "aws_security_group_rule" "copilot_egress_rule" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixCopilotSecurityGroup.id
}

resource "aws_eip" "copilot_eip" {
  count  = var.use_existing_copilot_eip ? 0 : 1
  domain = "vpc"
  tags   = local.common_tags
}

resource "aws_eip" "copilot_data_nodes_eips" {
  count  = var.copilot_deployment == "fault-tolerant" ? var.use_existing_copilot_eip ? 0 : var.copilot_data_node_count : 0
  domain = "vpc"
  tags = merge(local.common_tags, {
    Name          = "CopilotDataNodeEIP-${count.index}",
    DataNodeIndex = count.index
  })
}


module "data_nodes" {
  count  = var.copilot_deployment == "fault-tolerant" ? var.copilot_data_node_count : 0
  source = "./modules/copilot-data-node"

  node_name                = local.cop_tag
  node_key                 = count.index
  ami_id                   = var.copilot_ami_id != "" ? var.copilot_ami_id : local.cop_ami_id
  instance_type            = var.copilot_instance_type
  controller_ip            = var.use_existing_eip ? var.existing_eip : aws_eip.controller_eip[0].public_ip
  keypair                  = var.keypair
  subnet_id                = local.data_node_subnets[count.index % length(local.data_node_subnets)]
  root_volume_size         = var.copilot_root_volume_size
  root_volume_type         = var.copilot_root_volume_type
  default_data_volume_size = var.copilot_default_data_volume_size
  default_data_volume_type = var.copilot_default_data_volume_type
  ebs_optimized            = var.ebs_optimized
  monitoring               = var.monitoring
  tags                     = local.common_tags
}

locals {
  data_node_subnets = var.use_existing_vpc ? var.subnet_ids : tolist([aws_subnet.subnet[0].id, aws_subnet.subnet_ha[0].id])
}
