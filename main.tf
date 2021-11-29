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
  #s3_bucket     = "aviatrix-lambda-${data.aws_region.current.name}"
  #s3_key        = "aviatrix_ha.zip"
  filename      = "aviatrix_ha.zip"
  layers        = ["arn:aws:lambda:us-east-1:493018848597:layer:requests:1","arn:aws:lambda:us-east-1:493018848597:layer:lambda_layer:2"]
  function_name = "AVX_Controller"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "aviatrix_ha.lambda_handler"
  runtime       = "python3.9"
  description   = "MANAGED BY TERRAFORM"
  timeout       = 900

  environment {
    variables = {
      AWS_PRIM_ACC_ID   = var.aws_account_id
      AVIATRIX_TAG      = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name,
      AWS_ROLE_APP_NAME = module.aviatrix-iam-roles.aviatrix-role-app-name,
      AWS_ROLE_EC2_NAME = module.aviatrix-iam-roles.aviatrix-role-ec2-name,
      CTRL_INIT_VER     = var.controller_version
      EIP               = aws_eip.controller_eip.public_ip,
      S3_BUCKET_BACK    = var.s3_backup_bucket,
      S3_BUCKET_REGION  = var.s3_backup_region,
      API_PRIVATE_ACCESS= "False",
      ADMIN_PWD         = var.admin_password,
      ADMIN_EMAIL       = var.admin_email,
      NOTIF_EMAIL       = var.admin_email,
      PRIMARY_ACC_NAME  = var.access_account_name
    }
  }
}

resource aws_eip controller_eip {
  vpc   = true
  tags  = local.common_tags
}

resource "aws_launch_template" "avtx-controller" {
  name = "avtx-controller"
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

  image_id = local.ami_id
  instance_initiated_shutdown_behavior = "terminate"
  instance_type = var.instance_type
  key_name = var.keypair

  #  monitoring {
  #    enabled = true
  #  }

  network_interfaces {
    device_index = 0
    associate_public_ip_address = true
  }

  #  vpc_security_group_ids = ["sg-12345678"]

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "AviatrixController"
    }
  }

#  user_data = base64encode(data.template_file.user_data_hw.rendered)
}

/*
data "template_file" "user_data_hw" {
  template = <<EOF
#!/bin/bash -xe
apt install -y jq
output="/tmp/assume-role-output.json"
aws sts assume-role --role-arn ${module.aviatrix-iam-roles.aviatrix-role-app-arn} --role-session-name AWSCLI-Session > $output
AccessKeyId=$(cat $output | jq -r '.Credentials''.AccessKeyId')
SecretAccessKey=$(cat $output | jq -r '.Credentials''.SecretAccessKey')
SessionToken=$(cat $output | jq -r '.Credentials''.SessionToken')
export AWS_ACCESS_KEY_ID=$AccessKeyId
export AWS_SECRET_ACCESS_KEY=$SecretAccessKey
export AWS_SESSION_TOKEN=$SessionToken
export AWS_DEFAULT_REGION=us-east-1
aws ec2 associate-address --instance-id "$(wget -q -O - http://169.254.169.254/latest/meta-data/instance-id)" --allocation-id ${aws_eip.controller_eip.allocation_id}
EOF
}
*/

resource "aws_autoscaling_group" "avtx_ctrl" {
  name                      = "avtx_controller"
  max_size                  = 1
  min_size                  = 0
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
  vpc_zone_identifier = ["subnet-0616d68b7e6b0309e","subnet-0948c4e0fef5ddfb8"]

  warm_pool {
    pool_state                  = "Running"
    min_size                    = 1
    max_group_prepared_capacity = 1
  }

  initial_lifecycle_hook {
    name                 = "init"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 2000
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"

    notification_target_arn = aws_sns_topic.controller_updates.arn
    role_arn                = "arn:aws:iam::493018848597:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
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

/*
resource "aws_sns_topic_subscription" "asg_updates_for_notif_email" {
  topic_arn = aws_sns_topic.controller_updates.arn
  protocol  = "email"
  endpoint  = var.asg_notif_email ? var.asg_notif_email : var.admin_email
}
*/

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
