resource "null_resource" "region_conflict" {
  count = var.ha_distribution == "inter-region" ? 1 : 0
  lifecycle {
    precondition {
      condition     = var.region != var.dr_region ? true : false
      error_message = "region and dr_region should be different regions"
    }
  }
}

resource "null_resource" "validate_waf_alb_arn" {
  lifecycle {
    precondition {
      condition     = var.configure_waf ? var.load_balancer_type == "application" : true
      error_message = "var.load_balancer_type must be application if var.configure_waf is true"
    }
  }
}

resource "null_resource" "validate_alb_cert_arn" {
  lifecycle {
    precondition {
      condition     = var.load_balancer_type == "application" ? var.alb_cert_arn != "" : true
      error_message = "var.alb_cert_arn must be specified if var.load_balancer_type is application"
    }
  }
}

resource "null_resource" "validate_dr_alb_cert_arn" {
  lifecycle {
    precondition {
      condition     = var.ha_distribution == "inter-region" && var.load_balancer_type == "application" ? var.dr_alb_cert_arn != "" : true
      error_message = "var.dr_alb_cert_arn must be specified if var.ha_distribution is inter-region and var.load_balancer_type is application"
    }
  }
}

module "region1" {
  source                        = "./region-build"
  region                        = var.region
  dr_region                     = var.dr_region
  vpc_cidr                      = var.vpc_cidr
  admin_email                   = var.admin_email
  asg_notif_email               = var.asg_notif_email
  incoming_ssl_cidr             = var.incoming_ssl_cidr
  keypair                       = var.keypair
  access_account_name           = var.access_account_name
  s3_backup_bucket              = var.s3_backup_bucket
  s3_backup_region              = var.s3_backup_region
  termination_protection        = var.termination_protection
  create_iam_roles              = var.create_iam_roles
  ec2_role_name                 = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name
  app_role_name                 = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name
  ha_distribution               = var.ha_distribution
  vpc_name                      = var.vpc_name
  subnet_name                   = var.subnet_name
  controller_name               = var.controller_name
  instance_type                 = var.instance_type
  copilot_deployment            = var.copilot_deployment
  copilot_data_node_count       = var.copilot_data_node_count
  cop_instance_type             = var.cop_instance_type
  root_volume_type              = var.root_volume_type
  root_volume_size              = var.root_volume_size
  ebs_optimized                 = var.ebs_optimized
  monitoring                    = var.monitoring
  copilot_name                  = var.copilot_name
  copilot_username              = var.copilot_username
  copilot_email                 = var.copilot_email
  cop_controller_auth_ip        = var.cop_controller_auth_ip
  cop_type                      = var.cop_type
  cop_root_volume_size          = var.cop_root_volume_size
  cop_root_volume_type          = var.cop_root_volume_type
  cop_default_data_volume_size  = var.cop_default_data_volume_size
  cop_default_data_volume_type  = var.cop_default_data_volume_type
  cop_incoming_https_cidr       = var.cop_incoming_https_cidr
  cop_incoming_netflow_cidr     = var.cop_incoming_netflow_cidr
  cop_incoming_syslog_cidr      = var.cop_incoming_syslog_cidr
  tags                          = var.tags
  controller_version            = var.controller_version
  use_existing_vpc              = var.use_existing_vpc
  vpc                           = var.vpc
  subnet_ids                    = var.subnet_ids
  name_prefix                   = var.name_prefix
  license_type                  = var.license_type
  iam_for_ecs_arn               = aws_iam_role.iam_for_ecs.arn
  inter_region_primary          = var.region
  inter_region_standby          = var.dr_region
  zone_name                     = var.zone_name
  record_name                   = var.record_name
  inter_region_backup_enabled   = var.inter_region_backup_enabled
  avx_customer_id_ssm_path      = var.avx_customer_id_ssm_path
  avx_customer_id_ssm_region    = var.avx_customer_id_ssm_region
  avx_password_ssm_path         = var.avx_password_ssm_path
  avx_copilot_password_ssm_path = var.avx_copilot_password_ssm_path
  avx_password_ssm_region       = var.avx_password_ssm_region
  avx_customer_id               = var.avx_customer_id
  avx_password                  = var.avx_password
  avx_copilot_password          = var.avx_copilot_password
  attach_eventbridge_role_arn   = aws_iam_role.iam_for_eventbridge.arn
  use_existing_eip              = var.use_existing_eip
  existing_eip                  = var.existing_eip
  use_existing_copilot_eip      = var.use_existing_copilot_eip
  existing_copilot_eip          = var.existing_copilot_eip
  controller_ha_enabled         = var.controller_ha_enabled
  copilot_ha_enabled            = var.copilot_ha_enabled
  standby_instance_state        = var.standby_instance_state
  controller_ami_id             = var.controller_ami_id
  copilot_ami_id                = var.copilot_ami_id
  template_user_data            = var.template_user_data
  load_balancer_type            = var.load_balancer_type
  configure_waf                 = var.load_balancer_type == "application" && var.configure_waf == true ? true : false
  alb_cert_arn                  = var.alb_cert_arn
  ecr_image                     = "public.ecr.aws/n9d6j0n9/aviatrix_aws_ha:latest"
  # ecr_image                     = "${aws_ecr_repository.repo.repository_url}:latest"
}

module "region2" {
  providers = {
    aws = aws.region2
  }
  count                         = var.ha_distribution == "inter-region" ? 1 : 0
  source                        = "./region-build"
  region                        = var.dr_region
  vpc_cidr                      = var.dr_vpc_cidr
  dr_region                     = var.region
  admin_email                   = var.admin_email
  asg_notif_email               = var.asg_notif_email
  incoming_ssl_cidr             = var.incoming_ssl_cidr
  keypair                       = var.dr_keypair
  access_account_name           = var.access_account_name
  s3_backup_bucket              = var.s3_backup_bucket
  s3_backup_region              = var.s3_backup_region
  termination_protection        = var.termination_protection
  create_iam_roles              = var.create_iam_roles
  ec2_role_name                 = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name
  app_role_name                 = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name
  ha_distribution               = var.ha_distribution
  vpc_name                      = var.dr_vpc_name
  subnet_name                   = var.subnet_name
  controller_name               = var.controller_name
  instance_type                 = var.instance_type
  copilot_deployment            = var.copilot_deployment
  copilot_data_node_count       = var.copilot_data_node_count
  cop_instance_type             = var.cop_instance_type
  root_volume_type              = var.root_volume_type
  root_volume_size              = var.root_volume_size
  ebs_optimized                 = var.ebs_optimized
  monitoring                    = var.monitoring
  copilot_name                  = var.copilot_name
  copilot_username              = var.copilot_username
  copilot_email                 = var.copilot_email
  cop_controller_auth_ip        = var.cop_controller_auth_ip
  cop_type                      = var.cop_type
  cop_root_volume_size          = var.cop_root_volume_size
  cop_root_volume_type          = var.cop_root_volume_type
  cop_default_data_volume_size  = var.cop_default_data_volume_size
  cop_default_data_volume_type  = var.cop_default_data_volume_type
  cop_incoming_https_cidr       = var.cop_incoming_https_cidr
  cop_incoming_netflow_cidr     = var.cop_incoming_netflow_cidr
  cop_incoming_syslog_cidr      = var.cop_incoming_syslog_cidr
  tags                          = var.tags
  controller_version            = var.controller_version
  use_existing_vpc              = var.use_existing_vpc
  vpc                           = var.dr_vpc
  subnet_ids                    = var.dr_subnet_ids
  name_prefix                   = var.name_prefix
  license_type                  = var.license_type
  iam_for_ecs_arn               = aws_iam_role.iam_for_ecs.arn
  inter_region_primary          = var.region
  inter_region_standby          = var.dr_region
  zone_name                     = var.zone_name
  record_name                   = var.record_name
  inter_region_backup_enabled   = var.inter_region_backup_enabled
  avx_customer_id_ssm_path      = var.avx_customer_id_ssm_path
  avx_customer_id_ssm_region    = var.avx_customer_id_ssm_region
  avx_password_ssm_path         = var.avx_password_ssm_path
  avx_copilot_password_ssm_path = var.avx_copilot_password_ssm_path
  avx_password_ssm_region       = var.avx_password_ssm_region
  avx_customer_id               = var.avx_customer_id
  avx_password                  = var.avx_password
  avx_copilot_password          = var.avx_copilot_password
  attach_eventbridge_role_arn   = aws_iam_role.iam_for_eventbridge.arn
  use_existing_eip              = var.use_existing_eip
  existing_eip                  = var.existing_dr_eip
  use_existing_copilot_eip      = var.use_existing_copilot_eip
  existing_copilot_eip          = var.existing_copilot_dr_eip
  controller_ha_enabled         = var.controller_ha_enabled
  copilot_ha_enabled            = var.copilot_ha_enabled
  controller_ami_id             = var.dr_controller_ami_id
  copilot_ami_id                = var.dr_copilot_ami_id
  standby_instance_state        = var.standby_instance_state
  template_user_data            = var.template_user_data
  load_balancer_type            = var.load_balancer_type
  configure_waf                 = var.load_balancer_type == "application" && var.configure_waf == true ? true : false
  alb_cert_arn                  = var.dr_alb_cert_arn
  ecr_image                     = "public.ecr.aws/n9d6j0n9/aviatrix_aws_ha:latest"
  # ecr_image                     = "${aws_ecr_repository.repo.repository_url}:latest"
  depends_on = [null_resource.region_conflict]
}

module "aviatrix-iam-roles" {
  count                         = var.create_iam_roles ? 1 : 0
  source                        = "./aviatrix-controller-iam-roles"
  ec2_role_name                 = var.ec2_role_name
  app_role_name                 = var.app_role_name
  app_role_max_session_duration = var.app_role_max_session_duration
}

resource "aws_iam_role" "iam_for_ecs" {
  name = "aviatrix-controller-ecs"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "ecs-policy" {
  name        = "aviatrix-ctrl-ecs-policy"
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
        "ec2:DescribeRegions",
        "ec2:StopInstances",
        "ec2:AssociateAddress",
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:DescribeSecurityGroups",
        "ec2:StopInstances",
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
        "ssm:GetParameter"
      ],
      "Resource":[
        "arn:${local.iam_type}:ssm:${var.avx_password_ssm_region}:${data.aws_caller_identity.current.account_id}:parameter${var.avx_password_ssm_path}",
        "arn:${local.iam_type}:ssm:${var.avx_password_ssm_region}:${data.aws_caller_identity.current.account_id}:parameter${var.avx_copilot_password_ssm_path}",
        "arn:${local.iam_type}:ssm:${var.avx_customer_id_ssm_region}:${data.aws_caller_identity.current.account_id}:parameter${var.avx_customer_id_ssm_path}"
        ]
    },
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "arn:${local.iam_type}:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeTaskDefinition",
        "ecs:RegisterTaskDefinition",
        "ecs:TagResource",
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:PutImage",
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:ChangeMessageVisibility",
        "sqs:GetQueueUrl",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach-policy" {
  role       = aws_iam_role.iam_for_ecs.name
  policy_arn = aws_iam_policy.ecs-policy.arn
}

resource "aws_iam_role" "iam_for_eventbridge" {
  name = "aviatrix-eventbridge-role"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "events.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

resource "aws_iam_policy" "eventbridge-policy" {
  name        = "aviatrix-eventbridge-policy"
  path        = "/"
  description = "Policy for EventBridge to run ECS tasks"
  policy      = <<EOF
{
    "Statement": [
        {
            "Action": "ecs:RunTask",
            "Effect": "Allow",
            "Resource": "arn:${local.iam_type}:ecs:*:${data.aws_caller_identity.current.account_id}:task-definition/*",
            "Sid": "ECSAccess1"
        },
        {
            "Action": "iam:PassRole",
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "PassRole"
        }
    ],
    "Version": "2012-10-17"
}
EOF
}

resource "aws_iam_role_policy_attachment" "eventbridge-attach-policy" {
  role       = aws_iam_role.iam_for_eventbridge.name
  policy_arn = aws_iam_policy.eventbridge-policy.arn
}

##################################
# Create ECS Resources
##################################

locals {
  image_name = "avx_platform_ha"
  image_path = "${path.module}/docker"
  image_tag  = "latest"
}

# resource "aws_ecr_repository" "repo" {
#   name         = "avx_platform_ha"
#   force_delete = true
#   tags         = local.common_tags
# }

# resource "docker_image" "ecr_image" {
#   name = local.image_name

#   build {
#     context    = local.image_path
#     dockerfile = "Dockerfile.aws"
#     no_cache   = true
#     tag        = ["${aws_ecr_repository.repo.repository_url}:${local.image_tag}"]
#   }
#   triggers = {
#     source_file = filebase64sha256("${local.image_path}/app/aws_controller.py")
#   }
#   depends_on = [
#     aws_ecr_repository.repo
#   ]
# }

# resource "null_resource" "push_ecr_image" {
#   triggers = {
#     source_file = filebase64sha256("${local.image_path}/app/aws_controller.py")
#   }

#   provisioner "local-exec" {
#     command = <<-EOF
#     aws ecr get-login-password \
#       --region ${var.region} \
#       | docker login \
#       --username AWS \
#       --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.region}.${local.ecr_url}
#     docker push ${aws_ecr_repository.repo.repository_url}:${local.image_tag}
#     EOF
#   }
#   depends_on = [
#     docker_image.ecr_image
#   ]
# }

data "aws_caller_identity" "current" {}

data "aws_route53_zone" "avx_zone" {
  count        = var.ha_distribution == "inter-region" ? 1 : 0
  name         = var.zone_name
  private_zone = var.private_zone
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
  lifecycle {
    ignore_changes = [
      alias
    ]
  }
}
