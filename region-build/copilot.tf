resource "aws_launch_template" "avtx-copilot" {
  name        = "avtx-copilot"
  description = "Launch template for Aviatrix Copilot"

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.cop_root_volume_size
      volume_type           = var.cop_root_volume_type
      delete_on_termination = false
    }
  }

  disable_api_termination = var.termination_protection

  ebs_optimized = true

  image_id                             = local.cop_ami_id
  instance_initiated_shutdown_behavior = "terminate"
  instance_type                        = var.cop_instance_type
  key_name                             = var.keypair

  network_interfaces {
    device_index                = 0
    associate_public_ip_address = false
    security_groups             = [aws_security_group.AviatrixCopilotSecurityGroup.id]
  }

  tag_specifications {
    resource_type = "volume"

    tags = { Name = "AvxCopilot" }
  }

  tag_specifications {
    resource_type = "instance"

    tags = merge(local.common_tags, {
      Name = var.copilot_name != "" ? var.copilot_name : "${local.name_prefix}AviatrixCopilot"
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

  launch_template {
    id      = aws_launch_template.avtx-copilot.id
    version = "$Latest"
  }

  vpc_zone_identifier = var.use_existing_vpc ? var.subnet_names : tolist([aws_subnet.subnet[0].id, aws_subnet.subnet_ha[0].id])
  target_group_arns   = [aws_lb_target_group.avtx-copilot.arn]

  initial_lifecycle_hook {
    name                 = "init"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 1200
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"

    notification_target_arn = aws_sns_topic.controller_updates.arn
    role_arn                = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
  }

  tag {
    key                 = "app"
    value               = "copilot"
    propagate_at_launch = true
  }
  wait_for_capacity_timeout = "30m"
  timeouts {
    delete = "15m"
  }
}

# Define a listener
resource "aws_lb_listener" "avtx-copilot" {
  load_balancer_arn = aws_lb.avtx-controller.arn
  port              = "8443"
  protocol          = "TCP"

  default_action {
    target_group_arn = aws_lb_target_group.avtx-copilot.arn
    type             = "forward"
  }
}

resource "aws_lb_target_group" "avtx-copilot" {
  name     = "${local.name_prefix}copilot"
  port     = 443
  protocol = "TCP"
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

  dynamic "ingress" {
    for_each = var.cop_allowed_cidrs
    content {
      description      = ingress.key
      from_port        = ingress.value["port"]
      to_port          = ingress.value["port"]
      protocol         = ingress.value["protocol"]
      cidr_blocks      = ingress.value["cidrs"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = null
      security_groups  = null
      self             = null
    }
  }
  egress = [
    {
      description      = "All out traffic allowed"
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = null
      security_groups  = null
      self             = null
    }
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}AviatrixCopilotSecurityGroup"
  })
}

resource "aws_eip" "copilot_eip" {
  vpc  = true
  tags = local.common_tags
}
