data "aws_caller_identity" "current" {}

resource "time_sleep" "wait_for_zip" {
  create_duration = "60s"
}

resource "aws_ecs_task_definition" "task_def" {
  family                   = "AVX_PLATFORM_HA"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = var.ecs_task_execution_arn
  task_role_arn            = var.iam_for_ecs_arn
  container_definitions = jsonencode([
    {
      name   = module.ecs_cluster.cluster_name
      image  = var.ecr_image
      cpu    = 256
      memory = 512
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/aws/ecs/avx_platform_ha"
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "fargate"
        }
      }
      environment = var.ha_distribution == "inter-region" ? [
        {
          name  = "AVIATRIX_TAG",
          value = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name
        },
        {
          name  = "AVIATRIX_COP_TAG",
          value = local.cop_tag
        },
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
          value = var.use_existing_eip ? var.existing_eip : aws_eip.controller_eip[0].public_ip
        },
        {
          name  = "COP_EIP",
          value = var.use_existing_copilot_eip ? var.existing_copilot_eip : aws_eip.copilot_eip[0].public_ip
        },
        {
          name  = "COP_DATA_NODES_DETAILS",
          value = var.copilot_deployment == "fault-tolerant" ? jsonencode(module.data_nodes.*.instance_details) : ""
        },
        {
          name  = "COP_DEPLOYMENT",
          value = var.copilot_deployment
        },
        {
          name  = "COP_USERNAME",
          value = var.copilot_username
        },
        {
          name  = "COP_EMAIL",
          value = var.copilot_email
        },
        {
          name  = "COP_AUTH_IP",
          value = var.cop_controller_auth_ip
        },
        {
          name = "CTRL_ASG",
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
          name  = "CONTROLLER_TMP_SG_GRP",
          value = ""
        },
        {
          name  = "COPILOT_TMP_SG_GRP",
          value = ""
        },
        {
          name  = "CONTROLLER_RUNNING",
          value = ""
        },
        {
          name  = "COPILOT_RUNNING",
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
          value = var.record_name
        },
        {
          name  = "INTER_REGION_BACKUP_ENABLED",
          value = var.inter_region_backup_enabled ? "True" : "False"
        },
        {
          name  = "SQS_QUEUE_NAME",
          value = aws_sqs_queue.controller_updates_queue.name
        },
        {
          name  = "SQS_QUEUE_REGION",
          value = var.region
        },
        {
          name  = "AVX_CUSTOMER_ID_SSM_PATH",
          value = var.avx_customer_id_ssm_path
        },
        {
          name  = "AVX_CUSTOMER_ID_SSM_REGION",
          value = var.avx_customer_id_ssm_region
        },
        {
          name  = "AVX_PASSWORD_SSM_PATH",
          value = var.avx_password_ssm_path
        },
        {
          name  = "AVX_COPILOT_PASSWORD_SSM_PATH",
          value = var.avx_copilot_password_ssm_path
        },
        {
          name  = "AVX_PASSWORD_SSM_REGION",
          value = var.avx_password_ssm_region
        },
        {
          name  = "AVX_CUSTOMER_ID",
          value = var.avx_customer_id
        },
        {
          name  = "AVX_PASSWORD",
          value = var.avx_password
        },
        {
          name  = "AVX_COP_PASSWORD",
          value = var.avx_copilot_password
        }
        ] : [
        {
          name  = "AVIATRIX_TAG",
          value = aws_launch_template.avtx-controller.tag_specifications[0].tags.Name
        },
        {
          name  = "AVIATRIX_COP_TAG",
          value = local.cop_tag
        },
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
          value = var.use_existing_eip ? var.existing_eip : aws_eip.controller_eip[0].public_ip
        },
        {
          name  = "COP_EIP",
          value = var.use_existing_copilot_eip ? var.existing_copilot_eip : aws_eip.copilot_eip[0].public_ip
        },
        {
          name  = "COP_DATA_NODES_DETAILS",
          value = var.copilot_deployment == "fault-tolerant" ? jsonencode(module.data_nodes.*.instance_details) : ""
        },
        {
          name  = "COP_DEPLOYMENT",
          value = var.copilot_deployment
        },
        {
          name  = "COP_USERNAME",
          value = var.copilot_username
        },
        {
          name  = "COP_EMAIL",
          value = var.copilot_email
        },
        {
          name  = "COP_AUTH_IP",
          value = var.cop_controller_auth_ip
        },
        {
          name = "CTRL_ASG",
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
          name  = "SQS_QUEUE_NAME",
          value = aws_sqs_queue.controller_updates_queue.name
        },
        {
          name  = "SQS_QUEUE_REGION",
          value = var.region
        },
        {
          name  = "AVX_CUSTOMER_ID_SSM_PATH",
          value = var.avx_customer_id_ssm_path
        },
        {
          name  = "AVX_CUSTOMER_ID_SSM_REGION",
          value = var.avx_customer_id_ssm_region
        },
        {
          name  = "AVX_PASSWORD_SSM_PATH",
          value = var.avx_password_ssm_path
        },
        {
          name  = "AVX_COPILOT_PASSWORD_SSM_PATH",
          value = var.avx_copilot_password_ssm_path
        },
        {
          name  = "AVX_PASSWORD_SSM_REGION",
          value = var.avx_password_ssm_region
        },
        {
          name  = "AVX_CUSTOMER_ID",
          value = var.avx_customer_id
        },
        {
          name  = "AVX_PASSWORD",
          value = var.avx_password
        },
        {
          name  = "AVX_COP_PASSWORD",
          value = var.avx_copilot_password
        }
      ]
    }
  ])

  tags = local.common_tags

  lifecycle {
    ignore_changes = [
      container_definitions
    ]
    precondition {
      condition     = (var.copilot_email == "" && var.copilot_username == "") || (var.copilot_email != "" && var.copilot_username != "")
      error_message = "To add a user for copilot, please provide both the username and the email. Otherwise, they both should be empty."
    }
    precondition {
      condition     = (contains(["inter-az", "single-az", "inter-region"], var.ha_distribution) && var.copilot_deployment == "simple") || (contains(["inter-az", "single-az"], var.ha_distribution) && var.copilot_deployment == "fault-tolerant")
      error_message = "Fault-Tolerant CoPilot cannot be deployed in an inter-region HA distribution. Please either change the CoPilot deployment, or the HA distribution."
    }
  }
}

resource "aws_eip" "controller_eip" {
  #checkov:skip=CKV2_AWS_19: Ensure that all EIP addresses allocated to a VPC are attached to EC2 instances - AVXIT-7595
  count  = var.use_existing_eip ? 0 : 1
  domain = "vpc"
  tags   = merge(local.common_tags, tomap({ "Name" = "Avx-Controller" }))
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
  description       = "Generated by Aviatrix deployment module - DO NOT DELETE"
}

resource "aws_launch_template" "avtx-controller" {
  #checkov:skip=CKV_AWS_79: Ensure Instance Metadata Service Version 1 is not enabled - AVXIT-7573
  #checkov:skip=CKV_AWS_88: EC2 instance should not have public IP. - AVXIT-7574
  name        = "avtx-controller"
  description = "Launch template for Aviatrix Controller"

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.root_volume_size
      volume_type           = var.root_volume_type
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = var.monitoring
  }

  disable_api_termination = var.termination_protection

  ebs_optimized = var.ebs_optimized

  iam_instance_profile {
    name = var.ec2_role_name
  }

  image_id                             = var.controller_ami_id != "" ? var.controller_ami_id : local.ami_id
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

    tags = { Name = local.ctr_tag }
  }

  tag_specifications {
    resource_type = "volume"

    tags = { Name = local.ctr_tag }
  }

  user_data = var.user_data
}

data "aws_default_tags" "current" {}

resource "aws_autoscaling_group" "avtx_ctrl" {
  name                      = "avtx_controller"
  max_size                  = 1
  min_size                  = 0
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1
  force_delete              = true
  suspended_processes       = var.controller_ha_enabled ? null : ["Launch", "Terminate", "HealthCheck", "ReplaceUnhealthy"]

  launch_template {
    id      = aws_launch_template.avtx-controller.id
    version = "$Latest"
  }

  vpc_zone_identifier = var.use_existing_vpc ? var.subnet_ids : tolist([aws_subnet.subnet[0].id, aws_subnet.subnet_ha[0].id])
  target_group_arns   = [aws_lb_target_group.avtx-controller.arn]

  warm_pool {
    pool_state                  = var.ha_distribution == "inter-az" ? var.standby_instance_state : null
    min_size                    = var.ha_distribution == "inter-az" ? 1 : null
    max_group_prepared_capacity = var.ha_distribution == "inter-az" ? 1 : null
  }

  initial_lifecycle_hook {
    name                 = "init"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 1200
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"

    notification_target_arn = aws_sns_topic.controller_updates.arn
    role_arn                = "arn:${local.iam_type}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
  }

  tag {
    key                 = "Aviatrix"
    value               = "Controller"
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

resource "aws_sqs_queue" "controller_updates_queue" {
  #checkov:skip=CKV_AWS_27: Ensure all data stored in the SQS queue is encrypted - AVXIT-7575
  name = "controller-ha-updates-queue"
}

resource "aws_sns_topic" "controller_updates" {
  #checkov:skip=CKV_AWS_26: Ensure all data stored in the SNS topic is encrypted - AVXIT-7576
  name = "controller-ha-updates"
}

# Test notifications are not caught by EventBridge rules, so we'll filter them from getting to SQS also
resource "aws_sns_topic_subscription" "asg_updates_for_sqs" {
  topic_arn           = aws_sns_topic.controller_updates.arn
  protocol            = "sqs"
  endpoint            = aws_sqs_queue.controller_updates_queue.arn
  filter_policy       = jsonencode({ "LifecycleTransition" = ["autoscaling:EC2_INSTANCE_LAUNCHING"] })
  filter_policy_scope = "MessageBody"
}

resource "aws_sns_topic_subscription" "asg_updates_for_notif_email" {
  topic_arn = aws_sns_topic.controller_updates.arn
  protocol  = "email"
  endpoint  = var.asg_notif_email
}

resource "aws_sqs_queue_policy" "test" {
  queue_url = aws_sqs_queue.controller_updates_queue.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "SendMessage",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.controller_updates_queue.arn}",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "${aws_sns_topic.controller_updates.arn}"
        }
      }
    },
    {
      "Sid": "ReceiveMessage",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sqs:ReceiveMessage",
      "Resource": "${aws_sqs_queue.controller_updates_queue.arn}"
    }
  ]
}
POLICY
}

module "aviatrix_eventbridge" {
  source = "./modules/terraform-aws-eventbridge"

  create_bus        = false
  create_role       = false
  attach_ecs_policy = true
  ecs_target_arns = [
    trimsuffix(aws_ecs_task_definition.task_def.arn, ":${aws_ecs_task_definition.task_def.revision}")
  ]

  rules = {
    ha_controller_event = {
      name        = "ha-controller-event"
      description = "Captures HA Controller events"
      event_pattern = jsonencode({
        source = [
          "aws.autoscaling"
        ],
        detail-type = [
          "EC2 Instance Launch Successful",
          "EC2 Instance Terminate Successful",
          "EC2 Instance Launch Unsuccessful",
          "EC2 Instance Terminate Unsuccessful",
          "EC2 Instance-launch Lifecycle Action",
          "EC2 Instance-terminate Lifecycle Action"
        ],
        detail = {
          AutoScalingGroupName = [
            "avtx_controller",
            "avtx_copilot"
          ]
          LifecycleTransition = [
            "autoscaling:EC2_INSTANCE_LAUNCHING"
          ]
        }
      })
    }
  }

  targets = {
    ha_controller_event = [
      {
        name            = "ecs_task_target"
        arn             = module.ecs_cluster.cluster_arn
        attach_role_arn = var.attach_eventbridge_role_arn

        ecs_target = {
          task_count = 1
          # Remove the revision number so that the latest revision of the task definition is invoked
          task_definition_arn = trimsuffix(aws_ecs_task_definition.task_def.arn, ":${aws_ecs_task_definition.task_def.revision}")
          launch_type         = "FARGATE"
          network_configuration = {
            subnets          = var.use_existing_vpc ? var.subnet_ids : tolist([aws_subnet.subnet[0].id, aws_subnet.subnet_ha[0].id])
            security_groups  = [aws_security_group.AviatrixSecurityGroup.id]
            assign_public_ip = true
          }
        }
      }
    ]
  }

  archives = {
    ha_controller_event = [
      {
        name        = "ha-controller-event-archive"
        description = "Captures HA Controller events"
        event_pattern = jsonencode({
          source = [
            "aws.autoscaling"
          ],
          detail-type = [
            "EC2 Instance Launch Successful",
            "EC2 Instance Terminate Successful",
            "EC2 Instance Launch Unsuccessful",
            "EC2 Instance Terminate Unsuccessful",
            "EC2 Instance-launch Lifecycle Action",
            "EC2 Instance-terminate Lifecycle Action"
          ],
          detail = {
            AutoScalingGroupName = [
              "avtx_controller"
            ]
            LifecycleTransition = [
              "autoscaling:EC2_INSTANCE_LAUNCHING"
            ]
          }
        })
      }
    ]
  }
}

module "ecs_cluster" {
  #checkov:skip=CKV_AWS_224: Ensure ECS Cluster logging is enabled and client to container communication uses CMK - AVXIT-7611
  #checkov:skip=CKV_AWS_65: Ensure container insights are enabled on ECS cluster - AVXIT-7612
  source = "./modules/terraform-aws-ecs"

  cluster_name = "avx_platform_ha"
  cluster_settings = {
    "name" : "containerInsights",
    "value" : "disabled"
  }

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

resource "aws_cloudwatch_log_group" "log_group" {
  #checkov:skip=CKV_AWS_158: Ensure that CloudWatch Log Group is encrypted by KMS - AVXIT-7577
  name              = "/aws/ecs/avx_platform_ha"
  retention_in_days = 0

  tags = local.common_tags
}

locals {
  controller_eip     = var.use_existing_eip ? var.existing_eip : aws_eip.controller_eip[0].public_ip
  argument_stop_task = format("--region %s --cluster %s", var.region, "avx_platform_ha")
  argument_delete_sg = var.use_existing_vpc ? null : format("--region %s --vpc %s", var.region, aws_vpc.vpc[0].id)
}

resource "null_resource" "stop_ecs_tasks_script" {
  triggers = {
    argument_stop_task = local.argument_stop_task
  }

  provisioner "local-exec" {
    when       = destroy
    command    = "python3 -W ignore ${path.module}/stop_ecs_tasks.py ${self.triggers.argument_stop_task}"
    on_failure = continue
  }

  depends_on = [
    module.ecs_cluster
  ]
}

resource "null_resource" "delete_sg_script" {
  count = var.use_existing_vpc ? 0 : 1
  triggers = {
    argument_delete_sg = local.argument_delete_sg
  }

  provisioner "local-exec" {
    when       = destroy
    command    = "python3 -W ignore ${path.module}/delete_sg.py ${self.triggers.argument_delete_sg}"
    on_failure = continue
  }

  depends_on = [
    aws_vpc.vpc[0]
  ]
}
