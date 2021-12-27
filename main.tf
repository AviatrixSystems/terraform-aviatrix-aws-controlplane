provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

module "aviatrix-iam-roles" {
  source = "github.com/AviatrixSystems/terraform-modules.git//aviatrix-controller-iam-roles?ref=terraform_0.13"
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
        "ec2:StopInstances",
        "ec2:AssociateAddress",
        "ec2:DescribeImages",
        "ec2:DeregisterImage",
        "ec2:DescribeSnapshots",
        "ec2:DeleteSnapshot",
        "ec2:CreateImage",
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeKeyPairs",
        "ec2:CreateKeyPair",
        "ec2:DescribeVolumes",
        "ec2:ModifyInstanceCreditSpecification",
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface",
        "lambda:UpdateFunctionConfiguration",
        "lambda:GetFunction",
        "lambda:AddPermission",
        "autoscaling:AttachInstances",
        "autoscaling:DetachInstances",
        "autoscaling:PutNotificationConfiguration",
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:UpdateAutoScalingGroup",
        "autoscaling:CompleteLifecycleAction",
        "ssm:SendCommand",
        "ssm:ListCommandInvocations",
        "iam:PassRole",
        "iam:CreateServiceLinkedRole",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": "*"
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

resource aws_lambda_function lambda {
  s3_bucket     = "aviatrix-lambda-${data.aws_region.current.name}"
  s3_key        = "aws_controller.zip"
  function_name = "AVX_Controller"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "aws_controller.lambda_handler"
  runtime       = "python3.9"
  description   = "AVIATRIX CONTROLLER HIGH AVAILABILITY"
  timeout       = 900

  environment {
    variables = {
      AWS_PRIM_ACC_ID    = var.aws_account_id
      AVIATRIX_TAG       = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name,
      AWS_ROLE_APP_NAME  = module.aviatrix-iam-roles.aviatrix-role-app-name,
      AWS_ROLE_EC2_NAME  = module.aviatrix-iam-roles.aviatrix-role-ec2-name,
      CTRL_INIT_VER      = var.controller_version
      EIP                = aws_eip.controller_eip.public_ip,
      S3_BUCKET_BACK     = var.s3_backup_bucket,
      S3_BUCKET_REGION   = var.s3_backup_region,
      API_PRIVATE_ACCESS = "False",
      ADMIN_PWD          = var.admin_password,
      ADMIN_EMAIL        = var.admin_email,
      NOTIF_EMAIL        = var.admin_email,
      PRIMARY_ACC_NAME   = var.access_account_name
    }
  }
}

resource aws_eip controller_eip {
  vpc  = true
  tags = local.common_tags
}

resource aws_security_group AviatrixSecurityGroup {
  name        = "${local.name_prefix}AviatrixSecurityGroup"
  description = "Aviatrix - Controller Security Group"
  vpc_id      = var.vpc

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
      #      encrypted   = true
    }
  }

  disable_api_termination = var.termination_protection

  ebs_optimized = true

  iam_instance_profile {
    name = module.aviatrix-iam-roles.aviatrix-role-ec2-name
  }

  image_id                             = local.ami_id
  instance_initiated_shutdown_behavior = "terminate"
  instance_type                        = var.instance_type
  key_name                             = var.keypair

  #  monitoring {
  #    enabled = true
  #  }

  network_interfaces {
    device_index                = 0
    associate_public_ip_address = true
    security_groups             = [aws_security_group.AviatrixSecurityGroup.id]
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "AviatrixController"
    }
  }
}

resource "aws_autoscaling_group" "avtx_ctrl" {
  name     = "avtx_controller"
  max_size = 1
  min_size = 0
  #If you add a lifecycle hook, the grace period does not start until the lifecycle
  #hook actions are completed and the instance enters the InService state.
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1
  force_delete              = true

  launch_template {
    id      = aws_launch_template.avtx-controller.id
    version = "$Latest"
  }

  vpc_zone_identifier = var.subnet_names
  target_group_arns   = [aws_lb_target_group.avtx-controller.arn]

  #  warm_pool {
  #    pool_state                  = "Running"
  #    min_size                    = 1
  #    max_group_prepared_capacity = 1
  #  }

  initial_lifecycle_hook {
    name                 = "init"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 1200
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"

    notification_target_arn = aws_sns_topic.controller_updates.arn
    role_arn                = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
  }

  #  tag {
  #    key                 = "foo"
  #    value               = "bar"
  #    propagate_at_launch = true
  #  }
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

output "controller_private_ip" {
  value = aws_eip.controller_eip.private_ip
}

output "controller_public_ip" {
  value = aws_eip.controller_eip.public_ip
}
