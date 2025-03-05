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
				"lambda:GetFunctionConfiguration",
        "lambda:UpdateFunctionConfiguration"
			],
			"Effect": "Allow",
      "Resource": "arn:aws:lambda:*:*:function:*"
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
      "Resource": "arn:${local.iam_type}:ssm::${data.aws_caller_identity.current.account_id}:parameter${var.avx_password_ssm_path}"
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
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
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
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
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
  count    = var.ha_distribution == "inter-region-v2" && !var.use_existing_vpc ? 1 : 0
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


data "archive_file" "healthcheck" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/healthcheck.py"
  output_path = "healthcheck_payload.zip"
}

# Region 1

resource "aws_security_group" "AviatrixHealthcheckSecurityGroup_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  name        = "${local.name_prefix}AviatrixHealthcheckSecurityGroup"
  description = "Aviatrix - Healthcheck Security Group"
  vpc_id      = module.region1[0].vpc_id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}AviatrixHealthcheckSecurityGroup"
  })
}

resource "aws_security_group_rule" "healthcheck_egress_rule_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixHealthcheckSecurityGroup_region1[0].id
}

resource "aws_lambda_function" "healthcheck_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  filename         = "healthcheck_payload.zip"
  function_name    = "aviatrix-ha-healthcheck"
  role             = aws_iam_role.iam_for_healthcheck[0].arn
  handler          = "healthcheck.lambda_handler"
  source_code_hash = data.archive_file.healthcheck[0].output_base64sha256
  runtime          = "python3.12"
  timeout          = 900

  environment {
    variables = {
      bucket_name_1      = aws_s3_bucket.stop_region1[0].id
      bucket_name_2      = aws_s3_bucket.stop_region2[0].id
      ecs_cluster        = module.region1[0].ecs_cluster_name
      ecs_security_group = module.region1[0].aviatrix_sg_id
      ecs_subnet_1       = module.region1[0].subnet_id1
      ecs_subnet_2       = module.region1[0].subnet_id2
      ecs_task_def       = trimsuffix(module.region1[0].ecs_task_def.arn, ":${module.region1[0].ecs_task_def.revision}")
      health_check_rule  = aws_cloudwatch_event_rule.healthcheck_region1[0].name
      peer_eip           = ""
      peer_priv_ip       = ""
      peer_region        = var.dr_region
      region             = var.region
      region1            = var.region
      region2            = var.dr_region
      sns_topic_arn      = module.region1[0].sns_topic_arn
    }
  }

  vpc_config {
    subnet_ids         = var.use_existing_vpc ? var.healthcheck_subnet_ids : module.region1[0].healthcheck_subnet_ids
    security_group_ids = [aws_security_group.AviatrixHealthcheckSecurityGroup_region1[0].id]
  }

  depends_on = [
    aws_vpc_peering_connection.region1_to_region2,
    aws_vpc_peering_connection_accepter.peer
  ]

  lifecycle {
    ignore_changes = [environment]
  }
}

resource "aws_cloudwatch_event_rule" "healthcheck_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  name                = "aviatrix-healthcheck-rule"
  description         = "Aviatrix Healthcheck"
  schedule_expression = "rate(${var.healthcheck_interval} minutes)"
  state               = var.controller_ha_enabled ? (local.is_region2_active ? "ENABLED" : "DISABLED") : "DISABLED"
}

resource "aws_cloudwatch_event_target" "healthcheck_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  target_id = "AviatrixHealthcheck"
  rule      = aws_cloudwatch_event_rule.healthcheck_region1[0].name
  arn       = aws_lambda_function.healthcheck_region1[0].arn
}

resource "aws_lambda_permission" "healthcheck_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.healthcheck_region1[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.healthcheck_region1[0].arn
}

# Region 2

resource "aws_security_group" "AviatrixHealthcheckSecurityGroup_region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2

  name        = "${local.name_prefix}AviatrixHealthcheckSecurityGroup"
  description = "Aviatrix - Healthcheck Security Group"
  vpc_id      = module.region2[0].vpc_id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}AviatrixHealthcheckSecurityGroup"
  })
}

resource "aws_security_group_rule" "healthcheck_egress_rule_region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2

  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.AviatrixHealthcheckSecurityGroup_region2[0].id
}

resource "aws_lambda_function" "healthcheck_region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2

  filename         = "healthcheck_payload.zip"
  function_name    = "aviatrix-ha-healthcheck"
  role             = aws_iam_role.iam_for_healthcheck[0].arn
  handler          = "healthcheck.lambda_handler"
  source_code_hash = data.archive_file.healthcheck[0].output_base64sha256
  runtime          = "python3.12"
  timeout          = 900

  environment {
    variables = {
      bucket_name_1      = aws_s3_bucket.stop_region1[0].id
      bucket_name_2      = aws_s3_bucket.stop_region2[0].id
      ecs_cluster        = module.region2[0].ecs_cluster_name
      ecs_security_group = module.region2[0].aviatrix_sg_id
      ecs_subnet_1       = module.region2[0].subnet_id1
      ecs_subnet_2       = module.region2[0].subnet_id2
      ecs_task_def       = trimsuffix(module.region2[0].ecs_task_def.arn, ":${module.region2[0].ecs_task_def.revision}")
      health_check_rule  = aws_cloudwatch_event_rule.healthcheck_region2[0].name
      peer_eip           = ""
      peer_priv_ip       = ""
      peer_region        = var.region
      region             = var.dr_region
      region1            = var.region
      region2            = var.dr_region
      sns_topic_arn      = module.region2[0].sns_topic_arn
    }
  }

  vpc_config {
    subnet_ids         = var.use_existing_vpc ? var.healthcheck_dr_subnet_ids : module.region2[0].healthcheck_subnet_ids
    security_group_ids = [aws_security_group.AviatrixHealthcheckSecurityGroup_region2[0].id]
  }

  depends_on = [
    aws_vpc_peering_connection.region1_to_region2,
    aws_vpc_peering_connection_accepter.peer
  ]

  lifecycle {
    ignore_changes = [environment]
  }
}

resource "aws_cloudwatch_event_rule" "healthcheck_region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2

  name                = "aviatrix-healthcheck-rule"
  description         = "Aviatrix Healthcheck"
  schedule_expression = "rate(${var.healthcheck_interval} minutes)"
  state               = var.controller_ha_enabled ? (local.is_region2_active ? "DISABLED" : "ENABLED") : "DISABLED"
}

resource "aws_cloudwatch_event_target" "healthcheck_region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2

  target_id = "AviatrixHealthcheck"
  rule      = aws_cloudwatch_event_rule.healthcheck_region2[0].name
  arn       = aws_lambda_function.healthcheck_region2[0].arn
}

resource "aws_lambda_permission" "healthcheck_region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2

  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.healthcheck_region2[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.healthcheck_region2[0].arn
}

### STOP (Standby Takes Over Primary)
### https://aws.amazon.com/blogs/networking-and-content-delivery/creating-disaster-recovery-mechanisms-using-amazon-route-53/

resource "aws_route53_record" "primary" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  zone_id = data.aws_route53_zone.avx_zone[0].zone_id
  name    = var.record_name
  type    = "CNAME"
  ttl     = 60
  records = [module.region1[0].lb_dns_name]

  failover_routing_policy {
    type = "PRIMARY"
  }

  set_identifier  = "primary-stop"
  health_check_id = aws_route53_health_check.calculated[0].id
}

resource "aws_route53_record" "secondary" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  zone_id = data.aws_route53_zone.avx_zone[0].zone_id
  name    = var.record_name
  type    = "CNAME"
  ttl     = 60
  records = [module.region2[0].lb_dns_name]

  failover_routing_policy {
    type = "SECONDARY"
  }

  set_identifier = "secondary-stop"
}

resource "aws_s3_bucket" "stop_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  bucket_prefix = "aviatrix-ha-region1-"
  force_destroy = true
}

resource "aws_s3_bucket" "stop_region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2

  bucket_prefix = "aviatrix-ha-region2-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "stop_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  bucket                  = aws_s3_bucket.stop_region1[0].id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_public_access_block" "stop_region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2

  bucket                  = aws_s3_bucket.stop_region2[0].id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "stop_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  bucket = aws_s3_bucket.stop_region1[0].id
  policy = data.aws_iam_policy_document.getobject_region1[0].json

  depends_on = [aws_s3_bucket_public_access_block.stop_region1]
}

resource "aws_s3_bucket_policy" "stop_region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2

  bucket = aws_s3_bucket.stop_region2[0].id
  policy = data.aws_iam_policy_document.getobject_region2[0].json

  depends_on = [aws_s3_bucket_public_access_block.stop_region2]
}

data "aws_iam_policy_document" "getobject_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
    ]

    resources = [
      aws_s3_bucket.stop_region1[0].arn,
      "${aws_s3_bucket.stop_region1[0].arn}/*",
    ]
  }
}

data "aws_iam_policy_document" "getobject_region2" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
    ]

    resources = [
      aws_s3_bucket.stop_region2[0].arn,
      "${aws_s3_bucket.stop_region2[0].arn}/*"
    ]
  }
}

resource "aws_route53_health_check" "stop_region1" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  fqdn               = aws_s3_bucket.stop_region1[0].bucket_regional_domain_name
  port               = 443
  type               = "HTTPS"
  resource_path      = "/initiate-failover.html"
  failure_threshold  = "5"
  request_interval   = "30"
  invert_healthcheck = true

  tags = {
    Name = "Aviatrix-HA-Region1-Health-Check"
  }
}

resource "aws_route53_health_check" "stop_region2" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  fqdn               = aws_s3_bucket.stop_region2[0].bucket_regional_domain_name
  port               = 443
  type               = "HTTPS"
  resource_path      = "/initiate-failover.html"
  failure_threshold  = "5"
  request_interval   = "30"
  invert_healthcheck = true

  tags = {
    Name = "Aviatrix-HA-Region2-Health-Check"
  }
}

resource "aws_route53_health_check" "calculated" {
  count = var.ha_distribution == "inter-region-v2" ? 1 : 0

  type                   = "CALCULATED"
  child_health_threshold = 2
  child_healthchecks     = [aws_route53_health_check.stop_region1[0].id, aws_route53_health_check.stop_region2[0].id]

  tags = {
    Name = "Aviatrix-HA-Calculated-Health-Check"
  }
}

data "aws_s3_objects" "region1" {
  count  = var.ha_distribution == "inter-region-v2" ? 1 : 0
  bucket = aws_s3_bucket.stop_region1[0].id
}

data "aws_s3_objects" "region2" {
  count    = var.ha_distribution == "inter-region-v2" ? 1 : 0
  provider = aws.region2
  bucket   = aws_s3_bucket.stop_region2[0].id
}

locals {
  region1_object_exists = try(contains(data.aws_s3_objects.region1[0].keys, "initiate-failover.html"), false)
  region2_object_exists = try(contains(data.aws_s3_objects.region2[0].keys, "initiate-failover.html"), false)
  is_region2_active     = local.region1_object_exists || local.region2_object_exists
}
