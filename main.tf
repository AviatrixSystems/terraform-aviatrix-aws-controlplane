data "aws_caller_identity" "current" {}

module "aviatrix-iam-roles" {
  count         = var.create_iam_roles ? 1 : 0
  source        = "github.com/AviatrixSystems/terraform-modules.git//aviatrix-controller-iam-roles"
  ec2_role_name = var.ec2_role_name
  app_role_name = var.app_role_name
}

resource aws_iam_role iam_for_lambda {
  name = "iam_for_avtx_ctrl_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource aws_iam_policy lambda-policy {
  name        = "aviatrix-ctrl-lambda-policy"
  path        = "/"
  description = "Policy for creating aviatrix-controller"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeAddresses",
        "ec2:DescribeVolumes",
        "ec2:StopInstances",
        "ec2:AssociateAddress",
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:DescribeSecurityGroups",
        "lambda:UpdateFunctionConfiguration",
        "autoscaling:CompleteLifecycleAction",
        "ssm:SendCommand",
        "ssm:ListCommandInvocations",
        "iam:PassRole",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": "*"
    },
    {
      "Effect":"Allow",
      "Action":[
        "ssm:GetParametersByPath",
        "ssm:GetParameters",
        "ssm:GetParameter"
      ],
      "Resource":"arn:aws:ssm:*:*:parameter/aviatrix/*"
    },
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
EOF
}

resource aws_iam_role_policy_attachment attach-policy {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda-policy.arn
}

resource "null_resource" "lambda" {
  provisioner "local-exec" {
    command = <<EOT
    rm aws_controller.zip
    mkdir lambda
    pip3 install --target ./lambda requests boto3
    cd lambda
    zip -r ../aws_controller.zip .
    cd ..
    zip -g aws_controller.zip aws_controller.py
    rm -rf lambda
    EOT
  }

  triggers = {
    source_file = filebase64sha256("${path.module}/aws_controller.py")
  }
}

resource aws_lambda_function lambda {
  # s3_bucket     = "aviatrix-lambda-${data.aws_region.current.name}"
  # s3_key        = "aws_controller.zip"
  filename = "${path.module}/aws_controller.zip" 
  function_name = "AVX_Platform_HA"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "aws_controller.lambda_handler"
  runtime       = "python3.9"
  description   = "AVIATRIX PLATFORM HIGH AVAILABILITY"
  timeout       = 900
  # source_code_hash = filebase64sha256("aws_controller.zip")

  depends_on = [null_resource.lambda]

  environment {
    variables = var.enable_inter_region ? ({
      AVIATRIX_TAG       = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name,
      AVIATRIX_COP_TAG   = aws_launch_template.avtx-copilot.tag_specifications[1].tags.Name,
      AWS_ROLE_APP_NAME  = var.create_iam_roles ? module.aviatrix-iam-roles.aviatrix-role-app-name : var.app_role_name,
      AWS_ROLE_EC2_NAME  = var.create_iam_roles ? module.aviatrix-iam-roles.aviatrix-role-ec2-name : var.ec2_role_name,
      CTRL_INIT_VER      = var.controller_version,
      VPC_ID             = var.use_existing_vpc ? var.vpc : aws_vpc.vpc[0].id,
      EIP                = aws_eip.controller_eip.public_ip,
      DR_EIP             = aws_eip.dr_controller_eip[0].public_ip,
      COP_EIP            = aws_eip.copilot_eip.public_ip,
      # Can not use aws_autoscaling_group.avtx_ctrl.name as that creates a circular dependency
      CTRL_ASG           = "avtx_controller",
      COP_ASG            = "avtx_copilot",
      TMP_SG_GRP         = "",
      S3_BUCKET_BACK     = var.s3_backup_bucket,
      S3_BUCKET_REGION   = var.s3_backup_region,
      API_PRIVATE_ACCESS = "False",
      ADMIN_EMAIL        = var.admin_email,
      PRIMARY_ACC_NAME   = var.access_account_name
      INTER_REGION = var.enable_inter_region ? "True" : "False"
      PRI_REGION = var.region
      SEC_REGION = var.dr_region
    }) : ({
      AVIATRIX_TAG       = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name,
      AVIATRIX_COP_TAG   = aws_launch_template.avtx-copilot.tag_specifications[1].tags.Name,
      AWS_ROLE_APP_NAME  = var.create_iam_roles ? module.aviatrix-iam-roles.aviatrix-role-app-name : var.app_role_name,
      AWS_ROLE_EC2_NAME  = var.create_iam_roles ? module.aviatrix-iam-roles.aviatrix-role-ec2-name : var.ec2_role_name,
      CTRL_INIT_VER      = var.controller_version,
      VPC_ID             = var.use_existing_vpc ? var.vpc : aws_vpc.vpc[0].id,
      EIP                = aws_eip.controller_eip.public_ip,
      COP_EIP            = aws_eip.copilot_eip.public_ip,
      # Can not use aws_autoscaling_group.avtx_ctrl.name as that creates a circular dependency
      CTRL_ASG           = "avtx_controller",
      COP_ASG            = "avtx_copilot",
      TMP_SG_GRP         = "",
      S3_BUCKET_BACK     = var.s3_backup_bucket,
      S3_BUCKET_REGION   = var.s3_backup_region,
      API_PRIVATE_ACCESS = "False",
      ADMIN_EMAIL        = var.admin_email,
      PRIMARY_ACC_NAME   = var.access_account_name
      INTER_REGION = var.enable_inter_region ? "True" : "False"
    })
  }

  lifecycle {
    ignore_changes = [
      environment,
    ]
  }
}

resource aws_eip controller_eip {
  vpc  = true
  tags = merge(local.common_tags,tomap({"Name" = "Avx-Controller"}))
}

resource aws_security_group AviatrixSecurityGroup {
  name        = "${local.name_prefix}AviatrixSecurityGroup"
  description = "Aviatrix - Controller Security Group"
  vpc_id      = var.use_existing_vpc ? var.vpc : aws_vpc.vpc[0].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}AviatrixSecurityGroup"
  })
}

resource aws_security_group_rule ingress_rule {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = var.incoming_ssl_cidr
  security_group_id = aws_security_group.AviatrixSecurityGroup.id
}

resource aws_security_group_rule egress_rule {
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
      # encrypted   = true
    }
  }

  disable_api_termination = var.termination_protection

  ebs_optimized = true

  iam_instance_profile {
    name = var.create_iam_roles ? module.aviatrix-iam-roles.aviatrix-role-ec2-name : var.ec2_role_name
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

    tags = {Name = "AviatrixController"}
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

  vpc_zone_identifier = var.use_existing_vpc ? var.subnet_names : tolist([aws_subnet.subnet[0].id,aws_subnet.subnet_ha[0].id])
  target_group_arns   = [aws_lb_target_group.avtx-controller.arn]

  warm_pool {
    pool_state                  = var.ha_distribution == "inter-az" ? "Running" : null
    min_size                    = var.ha_distribution == "inter-az" ? 1 : null
    max_group_prepared_capacity = var.ha_distribution == "inter-az" ? 1 : null
  }

  initial_lifecycle_hook {
    name                 = "init"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 600
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


#####################################################

resource aws_eip dr_controller_eip {
  count                = var.enable_inter_region ? 1 : 0
  provider = aws.region2
  vpc  = true
  tags = merge(local.common_tags,tomap({"Name" = "Avx-Controller"}))
}

resource aws_security_group dr_AviatrixSecurityGroup {
  count                = var.enable_inter_region ? 1 : 0
  provider = aws.region2
  name        = "${local.name_prefix}AviatrixSecurityGroup"
  description = "Aviatrix - Controller Security Group"
  vpc_id      = var.use_existing_vpc ? var.dr_vpc : aws_vpc.dr_vpc[0].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}AviatrixSecurityGroup"
  })
}

resource aws_security_group_rule dr_ingress_rule {
  count                = var.enable_inter_region ? 1 : 0
  provider = aws.region2
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = var.incoming_ssl_cidr
  security_group_id = aws_security_group.dr_AviatrixSecurityGroup[0].id
}

resource aws_security_group_rule dr_egress_rule {
  count                = var.enable_inter_region ? 1 : 0
  provider = aws.region2
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.dr_AviatrixSecurityGroup[0].id
}

resource "aws_launch_template" "dr_avtx-controller" {
  count                = var.enable_inter_region ? 1 : 0
  provider = aws.region2
  name        = "avtx-controller"
  description = "Launch template for DR Aviatrix Controller"

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size = var.root_volume_size
      volume_type = var.root_volume_type
      # encrypted   = true
    }
  }

  disable_api_termination = var.termination_protection

  ebs_optimized = true

  iam_instance_profile {
    name = var.create_iam_roles ? module.aviatrix-iam-roles.aviatrix-role-ec2-name : var.ec2_role_name
  }

  image_id                             = local.dr_ami_id
  instance_initiated_shutdown_behavior = "terminate"
  instance_type                        = var.instance_type
  key_name                             = var.dr_keypair

  network_interfaces {
    device_index                = 0
    associate_public_ip_address = true
    security_groups             = [aws_security_group.dr_AviatrixSecurityGroup[0].id]
  }

  tag_specifications {
    resource_type = "instance"

    tags = {Name = "AviatrixController"}
  }

  tag_specifications {
    resource_type = "volume"

    tags = { Name = "AvxController" }
  }
}

resource "aws_autoscaling_group" "dr_avtx_ctrl" {
  count                = var.enable_inter_region ? 1 : 0
  provider = aws.region2
  name                      = "avtx_controller"
  max_size                  = 1
  min_size                  = 0
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1
  force_delete              = true

  launch_template {
    id      = aws_launch_template.dr_avtx-controller[0].id
    version = "$Latest"
  }

  vpc_zone_identifier = var.use_existing_vpc ? var.dr_subnet_names : tolist([aws_subnet.dr_subnet[0].id,aws_subnet.dr_subnet_ha[0].id])
  target_group_arns   = [aws_lb_target_group.dr_avtx-controller[0].arn]

  warm_pool {
    pool_state                  = var.ha_distribution == "inter-az" ? "Running" : null
    min_size                    = var.ha_distribution == "inter-az" ? 1 : null
    max_group_prepared_capacity = var.ha_distribution == "inter-az" ? 1 : null
  }

  initial_lifecycle_hook {
    name                 = "init"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 600
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"

    notification_target_arn = aws_sns_topic.dr_controller_updates[0].arn
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

resource "aws_sns_topic" "dr_controller_updates" {
  count                = var.enable_inter_region ? 1 : 0
  provider = aws.region2
  name = "dr-controller-ha-updates"
}

resource "aws_sns_topic_subscription" "dr_asg_updates_for_lambda" {
  count                = var.enable_inter_region ? 1 : 0
  provider = aws.region2
  topic_arn = aws_sns_topic.dr_controller_updates[0].arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.lambda.arn
}

resource "aws_sns_topic_subscription" "dr_asg_updates_for_notif_email" {
  count                = var.enable_inter_region ? 1 : 0
  provider = aws.region2
  topic_arn = aws_sns_topic.dr_controller_updates[0].arn
  protocol  = "email"
  endpoint  = var.asg_notif_email
}

resource "aws_lambda_permission" "dr_with_sns" {
  count                = var.enable_inter_region ? 1 : 0
  statement_id  = "AllowExecutionFromSNS-2"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda.arn
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.dr_controller_updates[0].arn
}


# data "aws_route53_zone" "zone" {
#   name         = "aviatrix.link"
#   # private_zone = true
# }

# resource "aws_route53_record" "primary" {
#   zone_id = data.aws_route53_zone.zone.zone_id
#   name    = "controller.aviatrix.link"
#   type    = "A"
#   ttl     = "60"

#   weighted_routing_policy {
#     weight = 200
#   }

#   set_identifier = "primary"
#   records        = ["54.167.136.95"]
# }

# resource "aws_cloudwatch_metric_alarm" "primary" {
#     count                = var.enable_inter_region ? 1 : 0
#     actions_enabled           = true
#     alarm_actions             = [
#         aws_sns_topic.controller_updates.arn,
#     ]
#     alarm_name                = "primary"
#     comparison_operator       = "LessThanOrEqualToThreshold"
#     datapoints_to_alarm       = 1
#     dimensions                = {
#         "HealthCheckId" = aws_route53_health_check.primary[0].id
#     }
#     evaluation_periods        = 1
#     insufficient_data_actions = []
#     metric_name               = "HealthCheckStatus"
#     namespace                 = "AWS/Route53"
#     ok_actions                = [
#         aws_sns_topic.controller_updates.arn,
#     ]
#     period                    = 60
#     statistic                 = "Maximum"
#     tags                      = {}
#     tags_all                  = {}
#     threshold                 = 0
# }

# resource "aws_route53_health_check" "primary" {
#     count                = var.enable_inter_region ? 1 : 0
#     child_health_threshold = 0
#     child_healthchecks     = []
#     disabled               = false
#     enable_sni             = false
#     failure_threshold      = 2
#     invert_healthcheck     = false
#     ip_address             = aws_eip.controller_eip.public_ip
#     measure_latency        = false
#     port                   = 443
#     regions                = ["us-west-1","us-east-1","eu-west-1"]
#     request_interval       = 30
#     tags                   = {
#         "Name" = "primary"
#     }
#     type                   = "TCP"
# }