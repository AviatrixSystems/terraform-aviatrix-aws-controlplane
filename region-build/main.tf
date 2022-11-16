data "aws_caller_identity" "current" {}

resource "time_sleep" "wait_for_zip" {
  create_duration = "60s"
}

resource "aws_lambda_function" "lambda" {
  filename      = "${path.cwd}/aws_controller.zip"
  function_name = "AVX_Platform_HA"
  # role          = aws_iam_role.iam_for_lambda.arn
  role        = var.iam_for_lambda_arn
  handler     = "aws_controller.lambda_handler"
  runtime     = "python3.9"
  description = "AVIATRIX PLATFORM HIGH AVAILABILITY"
  timeout     = 900

  # Can't use depends_on and configure providers at the same time:
  #
  # Error: Module module.controller_ha.module.region2 contains provider configuration
  # Providers cannot be configured within modules using count, for_each or depends_on.
  #
  # Using a time_sleep that's longer than the time needed to generate the zip file for now
  # This can be removed when we reference the zip file on S3.
  depends_on = [
    time_sleep.wait_for_zip
  ]
  # depends_on moved to calling the module
  # depends_on    = [null_resource.lambda]

  environment {
    variables = var.ha_distribution == "inter-region" ? ({
      AVIATRIX_TAG     = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name,
      AVIATRIX_COP_TAG = aws_launch_template.avtx-copilot.tag_specifications[1].tags.Name,
      # Logic moved to calling the module
      # AWS_ROLE_APP_NAME = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name,
      # AWS_ROLE_EC2_NAME = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name,
      AWS_ROLE_APP_NAME = var.app_role_name,
      AWS_ROLE_EC2_NAME = var.ec2_role_name,
      CTRL_INIT_VER     = var.controller_version,
      VPC_ID            = var.vpc,
      EIP               = aws_eip.controller_eip.public_ip,
      COP_EIP           = aws_eip.copilot_eip.public_ip,
      # Can not use aws_autoscaling_group.avtx_ctrl.name as that creates a circular dependency
      CTRL_ASG           = "avtx_controller",
      COP_ASG            = "avtx_copilot",
      TMP_SG_GRP         = "",
      S3_BUCKET_BACK     = var.s3_backup_bucket,
      S3_BUCKET_REGION   = var.s3_backup_region,
      API_PRIVATE_ACCESS = "False",
      ADMIN_EMAIL        = var.admin_email,
      PRIMARY_ACC_NAME   = var.access_account_name
      INTER_REGION       = "True"
      DR_REGION          = var.dr_region
      PREEMPTIVE         = var.preemptive ? "True" : "False"
      ACTIVE_REGION      = var.inter_region_primary
      STANDBY_REGION     = var.inter_region_standby
      ZONE_NAME          = var.zone_name
      RECORD_NAME        = var.record_name
      }) : ({
      AVIATRIX_TAG     = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name,
      AVIATRIX_COP_TAG = aws_launch_template.avtx-copilot.tag_specifications[1].tags.Name,
      # Logic moved to calling the module
      # AWS_ROLE_APP_NAME = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name,
      # AWS_ROLE_EC2_NAME = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name,
      AWS_ROLE_APP_NAME = var.app_role_name,
      AWS_ROLE_EC2_NAME = var.ec2_role_name,
      CTRL_INIT_VER     = var.controller_version,
      VPC_ID            = var.vpc,
      EIP               = aws_eip.controller_eip.public_ip,
      COP_EIP           = aws_eip.copilot_eip.public_ip,
      # Can not use aws_autoscaling_group.avtx_ctrl.name as that creates a circular dependency
      CTRL_ASG           = "avtx_controller",
      COP_ASG            = "avtx_copilot",
      TMP_SG_GRP         = "",
      S3_BUCKET_BACK     = var.s3_backup_bucket,
      S3_BUCKET_REGION   = var.s3_backup_region,
      API_PRIVATE_ACCESS = "False",
      ADMIN_EMAIL        = var.admin_email,
      PRIMARY_ACC_NAME   = var.access_account_name
      INTER_REGION       = "False"
    })
  }

  lifecycle {
    ignore_changes = [
      environment,
    ]
  }
}

resource "aws_eip" "controller_eip" {
  vpc  = true
  tags = merge(local.common_tags, tomap({ "Name" = "Avx-Controller" }))
}

resource "aws_security_group" "AviatrixSecurityGroup" {
  name        = "${local.name_prefix}AviatrixSecurityGroup"
  description = "Aviatrix - Controller Security Group"
  vpc_id      = var.use_existing_vpc ? var.vpc : aws_vpc.vpc[0].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}AviatrixSecurityGroup"
  })
}

resource "aws_security_group_rule" "ingress_rule" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = concat(var.incoming_ssl_cidr, tolist([var.vpc_cidr]))
  security_group_id = aws_security_group.AviatrixSecurityGroup.id
  description       = "DO NOT DELETE"
}

resource "aws_security_group_rule" "egress_rule" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixSecurityGroup.id
}

resource "aws_launch_template" "avtx-controller" {
  name        = "avtx-controller"
  description = "Launch template for Aviatrix Controller"

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size = var.root_volume_size
      volume_type = var.root_volume_type
    }
  }

  disable_api_termination = var.termination_protection

  ebs_optimized = true

  iam_instance_profile {
    # Logic moved to calling the module
    # name = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name
    name = var.ec2_role_name
  }

  image_id                             = local.ami_id
  instance_initiated_shutdown_behavior = "terminate"
  instance_type                        = var.instance_type
  key_name                             = var.keypair

  network_interfaces {
    device_index                = 0
    associate_public_ip_address = true
    security_groups             = [aws_security_group.AviatrixSecurityGroup.id]
  }

  tag_specifications {
    resource_type = "instance"

    tags = { Name = "AviatrixController" }
  }

  tag_specifications {
    resource_type = "volume"

    tags = { Name = "AvxController" }
  }
}

resource "aws_autoscaling_group" "avtx_ctrl" {
  name                      = "avtx_controller"
  max_size                  = 1
  min_size                  = 0
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1
  force_delete              = true

  launch_template {
    id      = aws_launch_template.avtx-controller.id
    version = "$Latest"
  }

  vpc_zone_identifier = var.use_existing_vpc ? var.subnet_names : tolist([aws_subnet.subnet[0].id, aws_subnet.subnet_ha[0].id])
  target_group_arns   = [aws_lb_target_group.avtx-controller.arn]

  warm_pool {
    pool_state                  = var.ha_distribution == "inter-az" ? "Running" : null
    min_size                    = var.ha_distribution == "inter-az" ? 1 : null
    max_group_prepared_capacity = var.ha_distribution == "inter-az" ? 1 : null
  }

  initial_lifecycle_hook {
    name                 = "init"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 900
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"

    notification_target_arn = aws_sns_topic.controller_updates.arn
    role_arn                = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
  }

  tag {
    key                 = "Aviatrix"
    value               = "Controller"
    propagate_at_launch = true
  }
  wait_for_capacity_timeout = "20m"
  timeouts {
    delete = "15m"
  }
}

resource "aws_sns_topic" "controller_updates" {
  name = "controller-ha-updates"
}

resource "aws_sns_topic_subscription" "asg_updates_for_lambda" {
  topic_arn = aws_sns_topic.controller_updates.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.lambda.arn
}

resource "aws_sns_topic_subscription" "asg_updates_for_notif_email" {
  topic_arn = aws_sns_topic.controller_updates.arn
  protocol  = "email"
  endpoint  = var.asg_notif_email
}

resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.controller_updates.arn
}
