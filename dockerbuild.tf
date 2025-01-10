# Create S3 Bucket for Docker artifacts
resource "aws_s3_bucket" "docker_artifacts" {
  bucket_prefix = "aviatrix-ha-docker-"
  force_destroy = true
}

# Configure S3 bucket access to block public access
resource "aws_s3_bucket_public_access_block" "docker_artifacts" {
  bucket = aws_s3_bucket.docker_artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Detect changes in the Docker source directory
resource "null_resource" "docker_source_change" {
  triggers = {
    files_hash = md5(join("", fileset("${path.module}/docker/", "**/*")))
  }
}

# Create ZIP archive of Docker source files
data "archive_file" "docker_source_zip" {
  type        = "zip"
  source_dir  = "${path.module}/docker/"
  output_path = "${path.module}/tmp/docker.zip"

  depends_on = [null_resource.docker_source_change]
}

# Upload Docker source ZIP file to S3
resource "aws_s3_object" "docker_source_upload" {
  bucket      = aws_s3_bucket.docker_artifacts.id
  key         = "docker.zip"
  source      = data.archive_file.docker_source_zip.output_path
  source_hash = md5(join("", fileset("${path.module}/docker/", "**/*")))

  depends_on = [
    aws_s3_bucket.docker_artifacts,
    aws_s3_bucket_public_access_block.docker_artifacts,
    null_resource.docker_source_change,
    data.archive_file.docker_source_zip,
    aws_iam_role.codebuild_role,
    data.aws_iam_policy_document.codebuild_assume_role,
    data.aws_iam_policy_document.codebuild_permissions,
    aws_iam_policy.codebuild_policy,
    aws_iam_role_policy_attachment.codebuild_policy_attachment,
    aws_codebuild_project.docker_build,
    aws_ecr_repository.aviatrix_ha_repo,
    aws_s3_bucket_notification.artifact_upload_notification,
    data.archive_file.lambda_function,
    aws_lambda_function.codebuild_trigger,
    aws_lambda_permission.s3_invoke_lambda,
    aws_iam_role.lambda_execution_role,
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_iam_role_policy.lambda_codebuild_start
  ]
}

# IAM role for CodeBuild
resource "aws_iam_role" "codebuild_role" {
  name               = "aviatrix-role-codebuild-execution-${random_id.aviatrix.hex}"
  assume_role_policy = data.aws_iam_policy_document.codebuild_assume_role.json
}

# IAM policy document for CodeBuild assume role
data "aws_iam_policy_document" "codebuild_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# IAM policy document for CodeBuild permissions
data "aws_iam_policy_document" "codebuild_permissions" {
  statement {
    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:GetAuthorizationToken",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["*"]
  }

  statement {
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.docker_artifacts.arn,
      "${aws_s3_bucket.docker_artifacts.arn}/*",
    ]
  }
}

# IAM policy for CodeBuild
resource "aws_iam_policy" "codebuild_policy" {
  name        = "aviatrix-codebuild-docker-policy-${random_id.aviatrix.hex}"
  description = "IAM policy for CodeBuild Docker project"
  policy      = data.aws_iam_policy_document.codebuild_permissions.json
}

# Attach CodeBuild policy to CodeBuild role
resource "aws_iam_role_policy_attachment" "codebuild_policy_attachment" {
  role       = aws_iam_role.codebuild_role.name
  policy_arn = aws_iam_policy.codebuild_policy.arn
}

# CodeBuild project for Docker image
resource "aws_codebuild_project" "docker_build" {
  name          = "Aviatrix_HA"
  description   = "Build Aviatrix HA Docker image and upload to ECR"
  build_timeout = 5
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  cache {
    type     = "S3"
    location = aws_s3_bucket.docker_artifacts.bucket
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "AWS_DEFAULT_REGION"
      value = var.region
    }

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = data.aws_caller_identity.current.account_id
    }

    environment_variable {
      name  = "IMAGE_REPO_NAME"
      value = aws_ecr_repository.aviatrix_ha_repo.name
    }

    environment_variable {
      name  = "IMAGE_TAG"
      value = "latest"
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "aviatrix-ha-build"
      stream_name = "build-log-stream"
    }

    s3_logs {
      status   = "ENABLED"
      location = "${aws_s3_bucket.docker_artifacts.id}/build-logs"
    }
  }

  source {
    type     = "S3"
    location = "${aws_s3_bucket.docker_artifacts.id}/docker.zip"
  }
}

# Create an ECR repository for Aviatrix HA
resource "aws_ecr_repository" "aviatrix_ha_repo" {
  name         = "aviatrix-ha"
  force_delete = true
}

# S3 bucket notification for triggering Lambda
resource "aws_s3_bucket_notification" "artifact_upload_notification" {
  bucket = aws_s3_bucket.docker_artifacts.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.codebuild_trigger.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "docker.zip"
  }

  depends_on = [aws_lambda_permission.s3_invoke_lambda]
}

# Create ZIP archive of Lambda function
data "archive_file" "lambda_function" {
  type        = "zip"
  source_file = "${path.module}/docker/lambda_function.py"
  output_path = "${path.module}/tmp/lambda_function.zip"
}

# Lambda function to trigger CodeBuild
resource "aws_lambda_function" "codebuild_trigger" {
  filename         = data.archive_file.lambda_function.output_path
  function_name    = "trigger-aviatrix-ha-build"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_function.output_base64sha256
}

# Lambda permission to allow S3 to invoke the function
resource "aws_lambda_permission" "s3_invoke_lambda" {
  statement_id  = "AllowS3Invocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.codebuild_trigger.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.docker_artifacts.arn
}

# IAM role for Lambda function
resource "aws_iam_role" "lambda_execution_role" {
  name = "aviatrix-role-lambda-codebuild-trigger-${random_id.aviatrix.hex}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Attach basic execution policy to Lambda role
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_execution_role.name
}

# IAM policy for Lambda to start CodeBuild
resource "aws_iam_role_policy" "lambda_codebuild_start" {
  name = "lambda_codebuild_start_policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "codebuild:StartBuild"
        ]
        Resource = aws_codebuild_project.docker_build.arn
      }
    ]
  })
}

