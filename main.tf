module "region1" {
  source                 = "./region-build"
  region                 = var.region
  dr_region              = var.dr_region
  vpc_cidr               = var.vpc_cidr
  admin_email            = var.admin_email
  asg_notif_email        = var.asg_notif_email
  incoming_ssl_cidr      = var.incoming_ssl_cidr
  keypair                = var.keypair
  access_account_name    = var.access_account_name
  s3_backup_bucket       = var.s3_backup_bucket
  s3_backup_region       = var.s3_backup_region
  termination_protection = var.termination_protection
  create_iam_roles       = var.create_iam_roles
  ec2_role_name          = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name
  app_role_name          = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name
  ha_distribution        = var.ha_distribution
  vpc_name               = var.vpc_name
  subnet_name            = var.subnet_name
  instance_type          = var.instance_type
  cop_instance_type      = var.cop_instance_type
  root_volume_type       = var.root_volume_type
  root_volume_size       = var.root_volume_size
  copilot_name           = var.copilot_name
  cop_type               = var.cop_type
  cop_root_volume_size   = var.cop_root_volume_size
  cop_root_volume_type   = var.cop_root_volume_type
  cop_allowed_cidrs      = var.cop_allowed_cidrs
  tags                   = var.tags
  controller_version     = var.controller_version
  use_existing_vpc       = var.use_existing_vpc
  vpc                    = var.vpc
  subnet_names           = var.subnet_names
  name_prefix            = var.name_prefix
  license_type           = var.license_type
  preemptive             = var.preemptive
  iam_for_lambda_arn     = aws_iam_role.iam_for_lambda.arn
  inter_region_primary   = var.region
  inter_region_standby   = var.dr_region
  zone_name              = var.zone_name
  record_name            = var.record_name
}

module "region2" {
  providers = {
    aws = aws.region2
  }
  count                  = var.ha_distribution == "inter-region" ? 1 : 0
  source                 = "./region-build"
  region                 = var.dr_region
  vpc_cidr               = var.dr_vpc_cidr
  dr_region              = var.region
  admin_email            = var.admin_email
  asg_notif_email        = var.asg_notif_email
  incoming_ssl_cidr      = var.incoming_ssl_cidr
  keypair                = var.dr_keypair
  access_account_name    = var.access_account_name
  s3_backup_bucket       = var.s3_backup_bucket
  s3_backup_region       = var.s3_backup_region
  termination_protection = var.termination_protection
  create_iam_roles       = var.create_iam_roles
  ec2_role_name          = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name
  app_role_name          = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name
  ha_distribution        = var.ha_distribution
  vpc_name               = var.dr_vpc_name
  subnet_name            = var.subnet_name
  instance_type          = var.instance_type
  cop_instance_type      = var.cop_instance_type
  root_volume_type       = var.root_volume_type
  root_volume_size       = var.root_volume_size
  copilot_name           = var.copilot_name
  cop_type               = var.cop_type
  cop_root_volume_size   = var.cop_root_volume_size
  cop_root_volume_type   = var.cop_root_volume_type
  cop_allowed_cidrs      = var.cop_allowed_cidrs
  tags                   = var.tags
  controller_version     = var.controller_version
  use_existing_vpc       = var.use_existing_vpc
  vpc                    = var.dr_vpc
  subnet_names           = var.dr_subnet_names
  name_prefix            = var.name_prefix
  license_type           = var.license_type
  preemptive             = var.preemptive
  iam_for_lambda_arn     = aws_iam_role.iam_for_lambda.arn
  inter_region_primary   = var.region
  inter_region_standby   = var.dr_region
  zone_name              = var.zone_name
  record_name            = var.record_name
}

# data "aws_caller_identity" "current" {}

module "aviatrix-iam-roles" {
  count = var.create_iam_roles ? 1 : 0
  source        = "./aviatrix-controller-iam-roles"
  ec2_role_name = var.ec2_role_name
  app_role_name = var.app_role_name
}

resource "aws_iam_role" "iam_for_lambda" {
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

resource "aws_iam_policy" "lambda-policy" {
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
        "ec2:StopInstances",
        "lambda:UpdateFunctionConfiguration",
        "lambda:GetFunctionConfiguration",
        "autoscaling:DescribeLoadBalancerTargetGroups",
        "autoscaling:DetachLoadBalancerTargetGroups",
        "autoscaling:CompleteLifecycleAction",
        "autoscaling:DescribeAutoScalingGroups",
        "cloudwatch:DescribeAlarmHistory",
        "ssm:SendCommand",
        "ssm:ListCommandInvocations",
        "iam:PassRole",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject",
        "route53:ChangeResourceRecordSets",
        "route53:ListHostedZonesByName",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups"
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

resource "aws_iam_role_policy_attachment" "attach-policy" {
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
    zip -gj aws_controller.zip ${path.module}/aws_controller.py
    rm -rf lambda
    EOT
  }

  triggers = {
    source_file = filebase64sha256("${path.module}/aws_controller.py")
  }
}

data "aws_route53_zone" "avx_zone" {
  count = var.ha_distribution == "inter-region" ? 1 : 0
  name  = var.zone_name
}

resource "aws_route53_record" "avx_primary" {
  count   = var.ha_distribution == "inter-region" ? 1 : 0
  zone_id = data.aws_route53_zone.avx_zone[0].zone_id
  name    = var.record_name
  type    = "A"
  # set_identifier = "${var.region}-avx-controller"

  alias {
    # zone_id                = aws_lb.avtx-controller.zone_id
    # name                   = aws_lb.avtx-controller.dns_name
    # evaluate_target_health = true
    zone_id                = module.region1.lb.zone_id
    name                   = module.region1.lb.dns_name
    evaluate_target_health = false
  }

  # failover_routing_policy {
  #   type = "PRIMARY"
  # }
  # health_check_id = aws_route53_health_check.aviatrix_controller_health_check[0].id
}
