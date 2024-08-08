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
  count                            = var.ha_distribution == "basic" ? 0 : 1
  source                           = "./region-build"
  region                           = var.region
  dr_region                        = var.dr_region
  vpc_cidr                         = var.vpc_cidr
  admin_email                      = var.admin_email
  asg_notif_email                  = var.asg_notif_email == "" ? var.admin_email : var.asg_notif_email
  incoming_ssl_cidr                = var.incoming_ssl_cidr
  keypair                          = var.keypair
  access_account_name              = var.access_account_name
  s3_backup_bucket                 = var.use_existing_s3 ? var.s3_backup_bucket : aws_s3_bucket.backup[0].id
  s3_backup_region                 = var.s3_backup_region
  termination_protection           = var.termination_protection
  create_iam_roles                 = var.create_iam_roles
  ec2_role_name                    = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name
  app_role_name                    = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name
  ha_distribution                  = var.ha_distribution
  vpc_name                         = var.vpc_name
  subnet_name                      = var.subnet_name
  controller_name                  = var.controller_name
  instance_type                    = var.instance_type
  copilot_deployment               = var.copilot_deployment
  copilot_data_node_count          = var.copilot_data_node_count
  copilot_instance_type            = var.copilot_instance_type
  root_volume_type                 = var.root_volume_type
  root_volume_size                 = var.root_volume_size
  ebs_optimized                    = var.ebs_optimized
  monitoring                       = var.monitoring
  copilot_name                     = var.copilot_name
  copilot_username                 = var.copilot_username
  copilot_email                    = var.copilot_email
  cop_controller_auth_ip           = var.cop_controller_auth_ip
  copilot_type                     = var.copilot_type
  copilot_root_volume_size         = var.copilot_root_volume_size
  copilot_root_volume_type         = var.copilot_root_volume_type
  copilot_default_data_volume_size = var.copilot_default_data_volume_size
  copilot_default_data_volume_type = var.copilot_default_data_volume_type
  copilot_incoming_https_cidr      = var.copilot_incoming_https_cidr == null ? var.incoming_ssl_cidr : var.copilot_incoming_https_cidr
  copilot_incoming_netflow_cidr    = var.copilot_incoming_netflow_cidr
  copilot_incoming_syslog_cidr     = var.copilot_incoming_syslog_cidr
  tags                             = var.tags
  controller_version               = var.controller_version
  use_existing_keypair             = var.use_existing_keypair
  use_existing_vpc                 = var.use_existing_vpc
  vpc                              = var.vpc
  subnet_ids                       = var.subnet_ids
  name_prefix                      = var.name_prefix
  license_type                     = var.license_type
  iam_for_ecs_arn                  = aws_iam_role.iam_for_ecs[0].arn
  ecs_task_execution_arn           = aws_iam_role.iam_for_ecs_task_execution[0].arn
  inter_region_primary             = var.region
  inter_region_standby             = var.dr_region
  zone_name                        = var.zone_name
  record_name                      = var.record_name
  inter_region_backup_enabled      = var.inter_region_backup_enabled
  avx_customer_id_ssm_path         = var.avx_customer_id_ssm_path
  avx_customer_id_ssm_region       = var.avx_customer_id_ssm_region
  avx_password_ssm_path            = var.avx_password_ssm_path
  avx_copilot_password_ssm_path    = var.avx_copilot_password_ssm_path
  avx_password_ssm_region          = var.avx_password_ssm_region
  avx_customer_id                  = var.avx_customer_id
  avx_password                     = var.avx_password
  avx_copilot_password             = var.avx_copilot_password
  attach_eventbridge_role_arn      = aws_iam_role.iam_for_eventbridge[0].arn
  use_existing_eip                 = var.use_existing_eip
  existing_eip                     = var.existing_eip
  use_existing_copilot_eip         = var.use_existing_copilot_eip
  existing_copilot_eip             = var.existing_copilot_eip
  controller_ha_enabled            = var.controller_ha_enabled
  copilot_ha_enabled               = var.copilot_ha_enabled
  standby_instance_state           = var.standby_instance_state
  controller_ami_id                = var.controller_ami_id
  copilot_ami_id                   = var.copilot_ami_id
  user_data                        = var.user_data
  load_balancer_type               = var.load_balancer_type
  configure_waf                    = var.load_balancer_type == "application" && var.configure_waf == true ? true : false
  alb_cert_arn                     = var.alb_cert_arn
  controller_json_url              = var.controller_json_url
  copilot_json_url                 = var.copilot_json_url
  cdn_server                       = var.cdn_server
  healthcheck_lambda_arn           = var.ha_distribution == "inter-region-v2" ? aws_iam_role.iam_for_healthcheck[0].arn : null
  healthcheck_interval             = var.healthcheck_interval
  healthcheck_state                = "DISABLED"
  healthcheck_subnet_ids           = var.healthcheck_subnet_ids
  # ecr_image                        = "public.ecr.aws/n9d6j0n9/aviatrix_aws_ha:latest"
  ecr_image = "${aws_ecr_repository.repo.repository_url}:latest"
}

module "region2" {
  providers = {
    aws = aws.region2
  }
  count                            = var.ha_distribution == "inter-region" || var.ha_distribution == "inter-region-v2" ? 1 : 0
  source                           = "./region-build"
  region                           = var.dr_region
  vpc_cidr                         = var.dr_vpc_cidr
  dr_region                        = var.region
  admin_email                      = var.admin_email
  asg_notif_email                  = var.asg_notif_email == "" ? var.admin_email : var.asg_notif_email
  incoming_ssl_cidr                = var.incoming_ssl_cidr
  keypair                          = var.dr_keypair
  access_account_name              = var.access_account_name
  s3_backup_bucket                 = var.use_existing_s3 ? var.s3_backup_bucket : aws_s3_bucket.backup[0].id
  s3_backup_region                 = var.s3_backup_region
  termination_protection           = var.termination_protection
  create_iam_roles                 = var.create_iam_roles
  ec2_role_name                    = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name
  app_role_name                    = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name
  ha_distribution                  = var.ha_distribution
  vpc_name                         = var.dr_vpc_name
  subnet_name                      = var.subnet_name
  controller_name                  = var.controller_name
  instance_type                    = var.instance_type
  copilot_deployment               = var.copilot_deployment
  copilot_data_node_count          = var.copilot_data_node_count
  copilot_instance_type            = var.copilot_instance_type
  root_volume_type                 = var.root_volume_type
  root_volume_size                 = var.root_volume_size
  ebs_optimized                    = var.ebs_optimized
  monitoring                       = var.monitoring
  copilot_name                     = var.copilot_name
  copilot_username                 = var.copilot_username
  copilot_email                    = var.copilot_email
  cop_controller_auth_ip           = var.cop_controller_auth_ip
  copilot_type                     = var.copilot_type
  copilot_root_volume_size         = var.copilot_root_volume_size
  copilot_root_volume_type         = var.copilot_root_volume_type
  copilot_default_data_volume_size = var.copilot_default_data_volume_size
  copilot_default_data_volume_type = var.copilot_default_data_volume_type
  copilot_incoming_https_cidr      = var.copilot_incoming_https_cidr == null ? var.incoming_ssl_cidr : var.copilot_incoming_https_cidr
  copilot_incoming_netflow_cidr    = var.copilot_incoming_netflow_cidr
  copilot_incoming_syslog_cidr     = var.copilot_incoming_syslog_cidr
  tags                             = var.tags
  controller_version               = var.controller_version
  use_existing_keypair             = var.use_existing_keypair
  use_existing_vpc                 = var.use_existing_vpc
  vpc                              = var.dr_vpc
  subnet_ids                       = var.dr_subnet_ids
  name_prefix                      = var.name_prefix
  license_type                     = var.license_type
  iam_for_ecs_arn                  = aws_iam_role.iam_for_ecs[0].arn
  ecs_task_execution_arn           = aws_iam_role.iam_for_ecs_task_execution[0].arn
  inter_region_primary             = var.region
  inter_region_standby             = var.dr_region
  zone_name                        = var.zone_name
  record_name                      = var.record_name
  inter_region_backup_enabled      = var.inter_region_backup_enabled
  avx_customer_id_ssm_path         = var.avx_customer_id_ssm_path
  avx_customer_id_ssm_region       = var.avx_customer_id_ssm_region
  avx_password_ssm_path            = var.avx_password_ssm_path
  avx_copilot_password_ssm_path    = var.avx_copilot_password_ssm_path
  avx_password_ssm_region          = var.avx_password_ssm_region
  avx_customer_id                  = var.avx_customer_id
  avx_password                     = var.avx_password
  avx_copilot_password             = var.avx_copilot_password
  attach_eventbridge_role_arn      = aws_iam_role.iam_for_eventbridge[0].arn
  use_existing_eip                 = var.use_existing_eip
  existing_eip                     = var.existing_dr_eip
  use_existing_copilot_eip         = var.use_existing_copilot_eip
  existing_copilot_eip             = var.existing_copilot_dr_eip
  controller_ha_enabled            = var.controller_ha_enabled
  copilot_ha_enabled               = var.copilot_ha_enabled
  controller_ami_id                = var.dr_controller_ami_id
  copilot_ami_id                   = var.dr_copilot_ami_id
  standby_instance_state           = var.standby_instance_state
  user_data                        = var.user_data
  load_balancer_type               = var.load_balancer_type
  configure_waf                    = var.load_balancer_type == "application" && var.configure_waf == true ? true : false
  alb_cert_arn                     = var.dr_alb_cert_arn
  controller_json_url              = var.controller_json_url
  copilot_json_url                 = var.copilot_json_url
  cdn_server                       = var.cdn_server
  healthcheck_lambda_arn           = var.ha_distribution == "inter-region-v2" ? aws_iam_role.iam_for_healthcheck[0].arn : null
  healthcheck_interval             = var.healthcheck_interval
  healthcheck_state                = var.ha_distribution == "inter-region-v2" ? "ENABLED" : ""
  healthcheck_subnet_ids           = var.healthcheck_dr_subnet_ids
  # ecr_image                        = "public.ecr.aws/n9d6j0n9/aviatrix_aws_ha:latest"
  ecr_image  = "${aws_ecr_repository.repo.repository_url}:latest"
  depends_on = [null_resource.region_conflict]
}

resource "random_id" "aviatrix" {
  byte_length = 4
}

module "aviatrix-iam-roles" {
  count                         = var.ha_distribution == "basic" ? 0 : var.create_iam_roles ? 1 : 0
  source                        = "./aviatrix-controller-iam-roles"
  ec2_role_name                 = var.ec2_role_name
  app_role_name                 = var.app_role_name
  app_role_max_session_duration = var.app_role_max_session_duration
}

resource "aws_iam_role" "iam_for_ecs" {
  count = var.ha_distribution == "basic" ? 0 : 1
  name  = "${var.ecs_role_name}-${random_id.aviatrix.hex}"

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
  count       = var.ha_distribution == "basic" ? 0 : 1
  name        = "${var.ecs_policy_name}-${random_id.aviatrix.hex}"
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
  count      = var.ha_distribution == "basic" ? 0 : 1
  role       = aws_iam_role.iam_for_ecs[0].name
  policy_arn = aws_iam_policy.ecs-policy[0].arn
}

resource "aws_iam_role" "iam_for_eventbridge" {
  count = var.ha_distribution == "basic" ? 0 : 1
  name  = "${var.eventbridge_role_name}-${random_id.aviatrix.hex}"

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
  count       = var.ha_distribution == "basic" ? 0 : 1
  name        = "${var.eventbridge_policy_name}-${random_id.aviatrix.hex}"
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
  count      = var.ha_distribution == "basic" ? 0 : 1
  role       = aws_iam_role.iam_for_eventbridge[0].name
  policy_arn = aws_iam_policy.eventbridge-policy[0].arn
}

resource "aws_iam_role" "iam_for_ecs_task_execution" {
  count              = var.ha_distribution == "basic" ? 0 : 1
  name               = "${var.ecs_task_execution_role_name}-${random_id.aviatrix.hex}"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role.json
}

data "aws_iam_policy_document" "ecs_task_execution_assume_role" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "ecs-task-execution-attach-policy" {
  count      = var.ha_distribution == "basic" ? 0 : 1
  role       = aws_iam_role.iam_for_ecs_task_execution[0].name
  policy_arn = "arn:${local.iam_type}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_s3_bucket" "backup" {
  #checkov:skip=CKV_AWS_18: Ensure the S3 bucket has access logging enabled - AVXIT-7605
  #checkov:skip=CKV_AWS_144: Ensure that S3 bucket has cross-region replication enabled - AVXIT-7607
  #checkov:skip=CKV_AWS_21: Ensure all data stored in the S3 bucket have versioning enabled - AVXIT-7609
  #checkov:skip=CKV_AWS_145: Ensure that S3 buckets are encrypted with KMS by default - AVXIT-7610
  #checkov:skip=CKV2_AWS_6: Ensure that S3 bucket has a Public Access block - AVXIT-7611
  provider      = aws.s3_region
  count         = var.ha_distribution == "basic" ? 0 : var.use_existing_s3 ? 0 : 1
  bucket_prefix = var.s3_backup_bucket
  force_destroy = true
}

##################################
# Create ECS Resources
##################################

locals {
  image_name = "avx_platform_ha"
  image_path = "${path.module}/docker"
  image_tag  = "latest"
}

resource "aws_ecr_repository" "repo" {
  name         = "avx_platform_ha"
  force_delete = true
  tags         = local.common_tags
}

resource "docker_image" "ecr_image" {
  name = local.image_name

  build {
    context    = local.image_path
    dockerfile = "Dockerfile.aws"
    no_cache   = true
    tag        = ["${aws_ecr_repository.repo.repository_url}:${local.image_tag}"]
  }
  triggers = {
    source_file = filebase64sha256("${local.image_path}/app/aws_controller.py")
  }
  depends_on = [
    aws_ecr_repository.repo
  ]
}

resource "null_resource" "push_ecr_image" {
  triggers = {
    source_file = filebase64sha256("${local.image_path}/app/aws_controller.py")
  }

  provisioner "local-exec" {
    command = <<-EOF
    aws ecr get-login-password \
      --region ${var.region} \
      | docker login \
      --username AWS \
      --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.region}.${local.ecr_url}
    docker push ${aws_ecr_repository.repo.repository_url}:${local.image_tag}
    EOF
  }
  depends_on = [
    docker_image.ecr_image
  ]
}

data "aws_caller_identity" "current" {}

data "aws_route53_zone" "avx_zone" {
  count        = var.ha_distribution == "inter-region" || var.ha_distribution == "inter-region-v2" ? 1 : 0
  name         = var.zone_name
  private_zone = var.private_zone
}

resource "aws_route53_record" "avx_primary" {
  count   = var.ha_distribution == "inter-region" || var.ha_distribution == "inter-region-v2" ? 1 : 0
  zone_id = data.aws_route53_zone.avx_zone[0].zone_id
  name    = var.record_name
  type    = "A"
  # set_identifier = "${var.region}-avx-controller"

  alias {
    # zone_id                = aws_lb.avtx-controller.zone_id
    # name                   = aws_lb.avtx-controller.dns_name
    # evaluate_target_health = true
    zone_id                = module.region1[0].lb.zone_id
    name                   = module.region1[0].lb.dns_name
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

# Basic deployment

resource "aws_cloudformation_stack" "cft" {
  # checkov:skip=CKV_AWS_124: Ensure that CloudFormation stacks are sending event notifications to an SNS topic - AVXIT-7528
  count = var.ha_distribution == "basic" ? 1 : 0

  name         = var.cft_stack_name
  template_url = var.use_existing_vpc ? "https://s3.us-east-1.amazonaws.com/avx-cloudformation-templates/avx_controlplane_existing_vpc_prod.template" : "https://s3.us-east-1.amazonaws.com/avx-cloudformation-templates/avx_controlplane_prod.template"

  parameters = {
    AdminEmail                  = var.admin_email
    AllowedHttpsIngressIpParam  = var.incoming_ssl_cidr[0]
    CustomerId                  = var.avx_customer_id
    VpcCidr                     = var.use_existing_vpc ? null : var.vpc_cidr
    SubnetCidr                  = var.use_existing_vpc ? null : cidrsubnet(var.vpc_cidr, 24 - tonumber(split("/", var.vpc_cidr)[1]), 0)
    SubnetAZ                    = var.use_existing_vpc ? null : "${var.region}a"
    AdminPassword               = var.avx_password
    AdminPasswordConfirm        = var.avx_password
    HTTPProxy                   = ""
    HTTPSProxy                  = ""
    TargetVersion               = var.controller_version
    DataVolSize                 = var.copilot_default_data_volume_size < 100 ? 100 : var.copilot_default_data_volume_size
    ControllerInstanceTypeParam = var.instance_type
    CoPilotInstanceTypeParam    = var.copilot_instance_type
    VpcParam                    = var.use_existing_vpc ? var.vpc : null
    SubnetParam                 = var.use_existing_vpc ? var.subnet_ids[0] : null
  }

  capabilities = ["CAPABILITY_IAM"]
}

resource "time_sleep" "waiting_for_initialization" {
  for_each        = { for i in aws_cloudformation_stack.cft : i.name => i }
  create_duration = "20m"
}

locals {
  argument_vpc_id   = var.ha_distribution == "basic" ? aws_cloudformation_stack.cft[0].outputs["AviatrixVpcID"] : ""
  argument_cft_name = var.ha_distribution == "basic" ? aws_cloudformation_stack.cft[0].name : ""
  # Add a delay so that the CFT deletes most of the resources before attempting to delete the security groups.
  argument_delete_sg_basic = format("--region %s --vpc %s --delete_cft %s --delay 600", var.region, local.argument_vpc_id, local.argument_cft_name)
}

resource "null_resource" "delete_sg_script_basic" {
  count = var.ha_distribution == "basic" && !var.use_existing_vpc ? 1 : 0

  triggers = {
    argument_delete_sg_basic = local.argument_delete_sg_basic
  }

  provisioner "local-exec" {
    when       = destroy
    command    = "python3 -W ignore ${path.module}/region-build/delete_sg.py ${self.triggers.argument_delete_sg_basic}"
    on_failure = continue
  }
}

# Inter-region V2

resource "aws_iam_role" "iam_for_healthcheck" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  name               = "${var.healthcheck_role_name}-${random_id.aviatrix.hex}"
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

resource "aws_iam_policy" "healthcheck-policy" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  name        = "${var.healthcheck_policy_name}-${random_id.aviatrix.hex}"
  path        = "/"
  description = "Aviatrix Healthcheck Policy"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:CreateNetworkInterface",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeNetworkInterfaces"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
		{
			"Action": [
				"ecs:DescribeTaskDefinition"
			],
			"Effect": "Allow",
			"Resource": "*"
		},    
		{
			"Action": [
				"ecs:RunTask"
			],
			"Effect": "Allow",
			"Resource": "arn:aws:ecs:*:*:task-definition/*"
		},
    {
      "Action": "iam:PassRole",
      "Effect": "Allow",
      "Resource": "arn:aws:iam::*:role/*"
    },
    {
      "Action": [
        "logs:CreateLogStream",
        "logs:CreateLogGroup",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Action": "sns:Publish",
      "Effect": "Allow",
      "Resource": "arn:aws:sns:*:*:*"
    },
    {
      "Effect":"Allow",
      "Action":[
        "ssm:GetParameter"
      ],
      "Resource": "arn:${local.iam_type}:ssm:${var.avx_password_ssm_region}:${data.aws_caller_identity.current.account_id}:parameter${var.avx_password_ssm_path}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda-attach-policy" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  role       = aws_iam_role.iam_for_healthcheck[0].name
  policy_arn = aws_iam_policy.healthcheck-policy[0].arn
}

resource "aws_vpc_peering_connection" "region1_to_region2" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  vpc_id      = module.region1[0].vpc_id
  peer_vpc_id = module.region2[0].vpc_id
  peer_region = var.dr_region

  depends_on = [module.region1, module.region2]
}

resource "aws_vpc_peering_connection_accepter" "peer" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  provider = aws.region2

  vpc_peering_connection_id = aws_vpc_peering_connection.region1_to_region2[0].id
  auto_accept               = true
}

resource "aws_security_group_rule" "healthcheck_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [module.region2[0].vpc_cidr_block]
  security_group_id = module.region1[0].controller_sg_id
  description       = "Aviatrix health check from ${module.region2[0].vpc_id} in ${var.dr_region}"
}

resource "aws_security_group_rule" "healthcheck_region2" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  provider = aws.region2

  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [module.region1[0].vpc_cidr_block]
  security_group_id = module.region2[0].controller_sg_id
  description       = "Aviatrix health check from ${module.region1[0].vpc_id} in ${var.region}"
}

resource "aws_route" "public_r1_to_r2_new_vpc" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  route_table_id            = module.region1[0].public_rt_id
  destination_cidr_block    = module.region2[0].vpc_cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.region1_to_region2[0].id

}

resource "aws_route" "public_r2_to_r1_new_vpc" {
  count = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0

  provider = aws.region2

  route_table_id            = module.region2[0].public_rt_id
  destination_cidr_block    = module.region1[0].vpc_cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.region1_to_region2[0].id
}

resource "aws_route" "public_r1_to_r2_existing_vpc" {
  for_each = toset(var.healthcheck_public_rt_ids)

  route_table_id            = each.key
  destination_cidr_block    = module.region2[0].vpc_cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.region1_to_region2[0].id
}

resource "aws_route" "public_r2_to_r1_existing_vpc" {
  for_each = toset(var.healthcheck_dr_public_rt_ids)

  provider = aws.region2

  route_table_id            = each.key
  destination_cidr_block    = module.region1[0].vpc_cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.region1_to_region2[0].id
}

resource "aws_route" "private_r1_to_r2_existing_vpc" {
  for_each = toset(var.healthcheck_private_rt_ids)

  route_table_id            = each.key
  destination_cidr_block    = module.region2[0].vpc_cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.region1_to_region2[0].id
}

resource "aws_route" "private_r2_to_r1_existing_vpc" {
  for_each = toset(var.healthcheck_dr_private_rt_ids)

  provider = aws.region2

  route_table_id            = each.key
  destination_cidr_block    = module.region1[0].vpc_cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.region1_to_region2[0].id
}
