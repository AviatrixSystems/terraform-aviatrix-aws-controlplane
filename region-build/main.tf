data "aws_caller_identity" "current" {}

resource "time_sleep" "wait_for_zip" {
  create_duration = "60s"
}

resource "aws_ecr_repository" "repo" {
  name = "avx_platform_ha"

  tags = local.common_tags
}

module "ecs_cluster" {
  source  = "terraform-aws-modules/ecs/aws"
  version = "4.1.2"

  cluster_name = "avx_platform_ha"

  cluster_configuration = {
    execute_command_configuration = {
      logging = "OVERRIDE"
      log_configuration = {
        # You can set a simple string and ECS will create the CloudWatch log group for you
        # or you can create the resource yourself as shown here to better manage retetion, tagging, etc.
        # Embedding it into the module is not trivial and therefore it is externalized
        cloud_watch_log_group_name = aws_cloudwatch_log_group.log_group.name
      }
    }
  }

  # Capacity provider
  fargate_capacity_providers = {
    FARGATE = {
      default_capacity_provider_strategy = {
        weight = 50
        base   = 20
      }
    }
    FARGATE_SPOT = {
      default_capacity_provider_strategy = {
        weight = 50
      }
    }
  }

  tags = local.common_tags
}

#module "ecs_disabled" {
#  source  = "terraform-aws-modules/ecs/aws"
#  version = "4.1.2"
#
#  create = false
#}

resource "aws_cloudwatch_log_group" "log_group" {
  name              = "/aws/ecs/avx_platform_ha"
  retention_in_days = 7

  tags = local.common_tags
}

resource "aws_ecs_task_definition" "task_def" {
  family                   = "AVX_PLATFORM_HA"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  task_role_arn            = var.iam_for_lambda_arn
  container_definitions = jsonencode([
    {
      name   = var.ecs_service_name
      image  = "${aws_ecr_repository.repo.repository_url}:latest"
      cpu    = 256
      memory = 512
      environment = var.ha_distribution == "inter-region" ? [
        {
          name  = "AVIATRIX_TAG",
          value = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name
        },
        {
          name  = "AVIATRIX_COP_TAG",
          value = aws_launch_template.avtx-copilot.tag_specifications[1].tags.Name
        },
        # Logic moved to calling the module
        # AWS_ROLE_APP_NAME = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name,
        # AWS_ROLE_EC2_NAME = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name,
        {
          name  = "AWS_ROLE_APP_NAME",
          value = var.app_role_name
        },
        {
          name  = "AWS_ROLE_EC2_NAME",
          value = var.ec2_role_name
        },
        {
          name  = "CTRL_INIT_VER",
          value = var.controller_version
        },
        {
          name  = "VPC_ID",
          value = var.vpc
        },
        {
          name  = "EIP",
          value = aws_eip.controller_eip.public_ip
        },
        {
          name  = "COP_EIP",
          value = aws_eip.copilot_eip.public_ip
        },
        {
          name  = "CTRL_ASG",
          # Can not use aws_autoscaling_group.avtx_ctrl.name as that creates a circular dependency
          value = "avtx_controller"
        },
        {
          name  = "COP_ASG",
          value = "avtx_copilot"
        },
        {
          name  = "TMP_SG_GRP",
          value = ""
        },
        {
          name  = "S3_BUCKET_BACK",
          value = var.s3_backup_bucket
        },
        {
          name  = "S3_BUCKET_REGION",
          value = var.s3_backup_region
        },
        {
          name  = "API_PRIVATE_ACCESS",
          value = "False"
        },
        {
          name  = "ADMIN_EMAIL",
          value = var.admin_email
        },
        {
          name  = "PRIMARY_ACC_NAME",
          value = var.access_account_name
        },
        {
          name  = "INTER_REGION",
          value = var.ha_distribution == "inter-region" ? "True" : "False"
        },
        {
          name  = "DR_REGION",
          value = var.dr_region
        },
        {
          name  = "PREEMPTIVE",
          value = var.preemptive ? "True" : "False"
        },
        {
          name  = "ACTIVE_REGION",
          value = var.inter_region_primary
        },
        {
          name  = "STANDBY_REGION",
          value = var.inter_region_standby
        },
        {
          name  = "ZONE_NAME",
          value = var.zone_name
        },
        {
          name  = "RECORD_NAME",
          value = var.record
        },
        {
          name  = "INTER_REGION_BACKUP_ENABLED",
          value = var.inter_region_backup_enabled ? "True" : "False"
        }
      ] : [
        {
          name = "AVIATRIX_TAG",
          value = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name
        },
        {
          name = "AVIATRIX_COP_TAG",
          value = aws_launch_template.avtx-copilot.tag_specifications[1].tags.Name
        },
        # Logic moved to calling the module
        # AWS_ROLE_APP_NAME = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-app-name : var.app_role_name,
        # AWS_ROLE_EC2_NAME = var.create_iam_roles ? module.aviatrix-iam-roles[0].aviatrix-role-ec2-name : var.ec2_role_name,
        {
          name = "AWS_ROLE_APP_NAME",
          value = var.app_role_name
        },
        {
          name = "AWS_ROLE_EC2_NAME",
          value = var.ec2_role_name
        },
        {
          name = "CTRL_INIT_VER",
          value = var.controller_version
        },
        {
          name = "VPC_ID",
          value = var.vpc
        },
        {
          name = "EIP",
          value = aws_eip.controller_eip.public_ip
        },
        {
          name = "COP_EIP",
          value = aws_eip.copilot_eip.public_ip
        },
        {
          name = "CTRL_ASG",
          # Can not use aws_autoscaling_group.avtx_ctrl.name as that creates a circular dependency
          value = "avtx_controller"
        },
        {
          name = "COP_ASG",
          value = "avtx_copilot"
        },
        {
          name = "TMP_SG_GRP",
          value = ""
        },
        {
          name = "S3_BUCKET_BACK",
          value = var.s3_backup_bucket
        },
        {
          name = "S3_BUCKET_REGION",
          value = var.s3_backup_region
        },
        {
          name = "API_PRIVATE_ACCESS",
          value = "False"
        },
        {
          name = "ADMIN_EMAIL",
          value = var.admin_email
        },
        {
          name = "PRIMARY_ACC_NAME",
          value = var.access_account_name
        },
        {
          name = "INTER_REGION",
          value = var.ha_distribution == "inter-region" ? "True" : "False"
        }
      ]
    }
  ])

  tags = local.common_tags

  # Can't use depends_on and configure providers at the same time:
  #
  # Error: Module module.controller_ha.module.region2 contains provider configuration
  # Providers cannot be configured within modules using count, for_each or depends_on.
  #
  # Using a time_sleep that's longer than the time needed to generate the zip file for now
  # This can be removed when we reference the zip file on S3.
  # depends_on = [
  #   time_sleep.wait_for_zip
  # ]
  # depends_on moved to calling the module
  # depends_on    = [null_resource.lambda]

  lifecycle {
    ignore_changes = [
      container_definitions
    ]
  }
}

resource "aws_ecs_service" "service" {
  name = "avx-platform-ha"
  cluster = module.ecs_cluster.cluster_id
  task_definition = aws_ecs_task_definition.task_def.arn
  launch_type = "FARGATE"

  tags = local.common_tags
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

resource "aws_sqs_queue" "controller_updates_queue" {
  name = "controller-ha-updates-queue"
}

resource "aws_sns_topic" "controller_updates" {
  name = "controller-ha-updates"
}

resource "aws_sns_topic_subscription" "asg_updates_for_sqs" {
  topic_arn = aws_sns_topic.controller_updates.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.controller_updates-queue.arn
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

module "compute_queue_backlog_lambda" {
  source  = "dailymuse/ecs-queue-backlog-autoscaling/aws//modules/lambda-function"
  version = "2.4.0"
}

module "ecs-queue-backlog-autoscaling" {
  source  = "dailymuse/ecs-queue-backlog-autoscaling/aws"
  version = "2.4.0"

  cluster_name = module.ecs_cluster.cluster_name

  service_name             = aws_ecs_service.service.name
  service_est_msgs_per_sec = 1
  # service_max_capacity     = 1
  # service_min_capacity     = 0

  queue_name                 = aws_sqs_queue.controller_updates-queue.name

  lambda_name = module.compute_queue_backlog_lambda.name

  depends_on_service = aws_ecs_service.service
}

resource "aws_sqs_queue_policy" "main" {
  queue_url = var.create_queue ? aws_sqs_queue.main[0].id : data.aws_sqs_queue.main[0].url
  policy    = data.aws_iam_policy_document.sqs.json
}

data "aws_iam_policy_document" "sqs" {
  statement {
    effect    = "Allow"
    actions   = ["sqs:GetQueueUrl", "sqs:GetQueueAttributes"]
    resources = [var.create_queue ? aws_sqs_queue.main[0].arn : data.aws_sqs_queue.main[0].arn]

    principals {
      identifiers = [module.compute_queue_backlog_lambda.execution_role_arn]

      type = "AWS"
    }
  }
}
