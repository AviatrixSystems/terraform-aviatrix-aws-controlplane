## Aviatrix with High Availability

### Goals

- Ensure that Aviatrix Controller and CoPilot are always deployed with high availability
- Optionally support a hot standby Controller instance which reduces Controller switchover time to under a minute

### Description

This Terraform module will create the following:

- An Auto Scaling Group (ASG) for Aviatrix Controller
  - The Controller will be initialized to the specified version (latest by default) and Controller backups will be configured.
- An Auto Scaling Group (ASG) for Aviatrix CoPilot
- An AWS load balancer with the Controller and CoPilot instances as targets
- An Elastic Container Service (ECS) cluster and task definition. ECS handles Controller and CoPilot failover events and restores the configuration from the latest backup automatically on new instances.
- An Amazon EventBridge event rule that monitors events from the ASGs and sends relevant events to ECS.
- An Amazon Simple Notification Service (SNS) topic that receives events from the ASGs.
- An Amazon Simple Queue Service (SQS) queue that is subscribed to the SNS topic. When EventBridge triggers ECS, ECS reads messages from the SQS queue and takes the appropriate actions.
- Additional roles for the resources above with corresponding role policies with required permissions
- If `ha_distribution` is set to "inter-region":
  - The resources listed above will also be deployed in a second region
  - A Route 53 record specified by `record_name` will be created in the zone specified by `zone_name`

### Prerequisites

Docker must be installed on the system where Terraform is run. Docker is required to create the Docker image that contains the Python code. This image is then uploaded to a private repository in Amazon Elastic Container Registry (ECR). Docker will only be required during the development/testing phase since we plan to publish a Docker image once the solution is GA.

The following resources should be created before running Terraform. The module will not create these resources.

- The S3 bucket used for Controller backups
- The Key Pair to be used by the Launch Templates in the Auto Scaling Groups
- The admin password required to initilaize the Controller should be set in the AWS Systems Manager parameter store at /aviatrix/controller/password in us-east-1.

  `aws ssm put-parameter --type "SecureString" --name "/aviatrix/controller/password" --value "XXXXXXXXX" --region="us-east-1"`

  For non-production deployments, the password can be specified by `avx_password`. This is not recommended for production because the password will be viewable in the container's environment variables.

- The customer ID required to license the Controller should be set in the AWS Systems Manager parameter store at /aviatrix/controller/customer_id in us-east-1.

  `aws ssm put-parameter --type "SecureString" --name "/aviatrix/controller/customer_id" --value "XXXXXXXXX" --region="us-east-1"`

  For non-production deployments, the customer ID can be specified by `avx_customer_id`. This is not recommended for production because the customer ID will be viewable in the container's environment variables.

- For CoPilot initialization, if a specific service account is used, and the `copilot_username` and `copilot_email` variables are provided, then the service account password should be set in the AWS Systems Manager parameter store. The path for the password may be provided via the `avx_copilot_password_ssm_path` variable, or the default path `/aviatrix/copilot/password` will be checked. The password should be stored in the region defined in the `avx_password_ssm_region` variable. Otherwise, the default region of `us-east-1` will be checked. If service account information is not provided via the `copilot_username` and the `copilot_email` variables, then the default `admin` account on the controller will be used as the service account to initialize the CoPilot.

  `aws ssm put-parameter --type "SecureString" --name "/aviatrix/copilot/password" --value "XXXXXXXXX" --region="us-east-1"`

- If `ha_distribution` is set to "inter-region", the hosted zone specified by `zone_name` must already exist in Route 53.

### Usage Example

#### Single-AZ

```
module "aws_controller_ha" {
  source              = "github.com/aviatrix-automation/Aviatrix_AWS_HA"
  keypair             = "keypair1"
  incoming_ssl_cidr   = ["x.x.x.x/32"]
  access_account_name = "AWS-Account"
  admin_email         = "admin@example.com"
  asg_notif_email     = "asg@example.com"
  s3_backup_bucket    = "backup-bucket"
  s3_backup_region    = "us-east-1"
}
```

#### Inter-AZ

```
module "aws_controller_ha" {
  source              = "github.com/aviatrix-automation/Aviatrix_AWS_HA"
  keypair             = "keypair1"
  incoming_ssl_cidr   = ["x.x.x.x/32"]
  access_account_name = "AWS-Account"
  admin_email         = "admin@example.com"
  asg_notif_email     = "asg@example.com"
  s3_backup_bucket    = "backup-bucket"
  s3_backup_region    = "us-east-1"
  ha_distribution     = "inter-az"
}
```

#### Inter-Region

```
module "aws_controller_ha" {
  source                      = "github.com/aviatrix-automation/Aviatrix_AWS_HA"
  keypair                     = "keypair1"
  incoming_ssl_cidr           = ["x.x.x.x/32"]
  access_account_name         = "AWS-Account"
  admin_email                 = "admin@example.com"
  asg_notif_email             = "asg@example.com"
  s3_backup_bucket            = "backup-bucket"
  s3_backup_region            = "us-east-1"
  ha_distribution             = "inter-az"
  zone_name                   = "example.com"
  record_name                 = "controller.example.com"
  inter_region_backup_enabled = true
}
```

### Variables

| Key                           | Default Value                              | Description                                                                                                                                                                                                                                    |
| ----------------------------- | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| access_account_name           |                                            | A friendly name mapping to your AWS account ID                                                                                                                                                                                                 |
| admin_email                   |                                            | The administrator's email address. This email address will be used for password recovery as well as for notifications from the Controller.                                                                                                     |
| asg_notif_email               |                                            | The email address for Controller failover notifications                                                                                                                                                                                        |
| app_role_name                 | aviatrix-role-app                          | The name of the Aviatrix App role                                                                                                                                                                                                              |
| avx_copilot_password_ssm_path | /aviatrix/copilot/password                 | The path to the Aviatrix CoPilot password                                                                                                                                                                                                      |
| avx_customer_id               |                                            | The Aviatrix customer ID. WARNING: The Customer ID will be viewable in the container's environment variables. It is recommended to store the customer ID in an SSM parameter and to not use `avx_customer_id` for production deployments.      |
| avx_customer_id_ssm_path      | /aviatrix/controller/customer_id           | The path to the Aviatrix customer ID. Only applicable if `avx_customer_id` is not specified.                                                                                                                                                   |
| avx_customer_id_ssm_region    | us-east-1                                  | The region the customer ID parameter is in. Only applicable if `avx_customer_id` is not specified.                                                                                                                                             |
| avx_password                  |                                            | The Aviatrix Controller admin password. WARNING: The password will be viewable in the container's environment variables. It is recommended to store the password in an SSM parameter and to not use `avx_password` for production deployments. |
| avx_password_ssm_path         | /aviatrix/controller/password              | The path to the Aviatrix password. Only applicable if `avx_password` is not specified.                                                                                                                                                         |
| avx_password_ssm_region       | us-east-1                                  | The region the password parameter is in. Only applicable if `avx_password` is not specified.                                                                                                                                                   |
| controller_version            | ""                                         | The initial version of the Aviatrix Controller at launch                                                                                                                                                                                       |
| cop_allowed_cidrs             | TCP 443, UDP 5000, UDP 31283 for 0.0.0.0/0 | CoPilot allowed CIDRs                                                                                                                                                                                                                          |
| cop_instance_type             | t3.2xlarge                                 | CoPilot instance size                                                                                                                                                                                                                          |
| cop_type                      | Copilot                                    | Type of billing, can be 'Copilot' or 'CopilotARM'                                                                                                                                                                                              |
| cop_root_volume_size          | 25GB                                       | Root volume disk size for CoPilot                                                                                                                                                                                                              |
| cop_root_volume_type          | gp3                                        | Root volume type for CoPilot                                                                                                                                                                                                                   |
| cop_default_data_volume_size  | 8GB                                        | Default data volume disk size for CoPilot                                                                                                                                                                                                      |
| cop_default_data_volume_type  | gp3                                        | Default data volume type for CoPilot                                                                                                                                                                                                           |
| copilot_email                 |                                            | CoPilot account email. See Prerequisites above for more information                                                                                                                                                                            |
| copilot_name                  |                                            | Name of CoPilot                                                                                                                                                                                                                                |
| copilot_username              |                                            | CoPilot account username. See Prerequisites above for more information                                                                                                                                                                         |
| create_iam_roles              | true                                       | Whether to create the IAM roles used to grant AWS API permissions to the Aviatrix Controller                                                                                                                                                   |
| dr_keypair                    | ""                                         | Key pair which should be used by DR Controller. Only applicable if `ha_distribution` is "inter-region".                                                                                                                                        |
| dr_region                     | "us-east-2"                                | Region to deploy the DR Controller. Only applicable if `ha_distribution` is "inter-region".                                                                                                                                                    |
| dr_subnet_names               |                                            | The list of existing subnets to deploy the Controller in. Only applicable if `use_existing_vpc` is true.                                                                                                                                       |
| dr_vpc                        | ""                                         | VPC to deploy DR Controlller. Only applicable if `use_existing_vpc` is true. Only applicable if `ha_distribution` is "inter-region".                                                                                                           |
| dr_vpc_cidr                   | 10.0.0.0/24                                | The CIDR for the VPC to create for the DR Controller. Only applicable if `ha_distribution` is "inter-region" and `use_existing_vpc` is false.                                                                                                  |
| dr_vpc_name                   | ""                                         | The name for the VPC to create for the DR Controller. Only applicable if `ha_distribution` is "inter-region" and `use_existing_vpc` is false.                                                                                                  |
| ec2_role_name                 | aviatrix-role-ec2                          | The name of the Aviatrix EC2 role                                                                                                                                                                                                              |
| ha_distribution               | single-az                                  | Desired Controller high availability distribution. Valid values are 'single-az', 'inter-az', and 'inter-region'.                                                                                                                               |
| incoming_ssl_cidr             |                                            | Incoming CIDR for security group used by Controller                                                                                                                                                                                            |
| instance_type                 | t3.xlarge                                  | Controller instance size                                                                                                                                                                                                                       |
| inter_region_backup_enabled   | false                                      | Whether to enable backups on the primary controller. Only applicable if `ha_distribution` is "inter-region".                                                                                                                                   |
| keypair                       |                                            | Key pair which should be used by Controller                                                                                                                                                                                                    |
| license_type                  | BYOL                                       | Type of billing, can be 'MeteredPlatinum', 'BYOL' or 'Custom'                                                                                                                                                                                  |
| name_prefix                   | avx                                        | Additional name prefix for resources created by this module                                                                                                                                                                                    |
| record_name                   | true                                       | The record name to be created under the exisitng route 53 zone specified by `zone_name`. Required if `ha_distribution` is 'inter-region'.                                                                                                      |
| region                        | "us-east-1"                                | Region to deploy the Controller and CoPilot                                                                                                                                                                                                    |
| root_volume_size              | 64                                         | Root volume disk size for Controller                                                                                                                                                                                                           |
| root_volume_type              | gp3                                        | Root volume type for Controller                                                                                                                                                                                                                |
| s3_backup_bucket              |                                            | S3 bucket for Controller DB backup                                                                                                                                                                                                             |
| s3_backup_region              |                                            | Region S3 backup bucket is in                                                                                                                                                                                                                  |
| subnet_name                   | Aviatrix-Public-Subnet                     | The subnet name to create for the Controller. Only applicable if `use_existing_vpc` is false.                                                                                                                                                  |
| subnet_names                  |                                            | The list of existing subnets to deploy the Controller in. Only applicable if `use_existing_vpc` is true.                                                                                                                                       |
| tags                          |                                            | Map of common tags which should be used for module resources                                                                                                                                                                                   |
| termination_protection        | true                                       | Whether to enable termination protection on the Controller, CoPilot and load balancers                                                                                                                                                         |
| use_existing_vpc              | false                                      | Set to true to deploy Controller and CoPilot to existing VPCs specified by `vpc` and `dr_vpc`.                                                                                                                                                 |
| vpc                           | ""                                         | VPC to deploy Controlller and CoPilot in. Only applicable if `use_existing_vpc` is true.                                                                                                                                                       |
| vpc_cidr                      | 10.0.0.0/24                                | The CIDR for the VPC to create for the Controller. Only applicable if `use_existing_vpc` is false.                                                                                                                                             |
| vpc_name                      | Aviatrix-VPC                               | The name for the VPC to create for the Controller. Only applicable if `use_existing_vpc` is false.                                                                                                                                             |
| zone_name                     | true                                       | The existing Route 53 zone to create a record in. Required if `ha_distribution` is 'inter-region'.                                                                                                                                             |
### Additional Information

When an SNS HA event is triggered there are 3 scenarios depending on what `autoscaling_source` and `autoscaling_destination` are set to:

1. When `autoscaling_source = EC2` and `autoscaling_destination = AutoScalingGroup`:

   - Assigns the EIP created through terraform to the new Controller.
   - Run initial setup and boot to latest version.
   - Set admin email and password.
   - Create primary AWS account.
   - Setup S3 backup.
   - Update environment variables in Lambda which will be used by next event.

2. When `autoscaling_source = EC2` and `autoscaling_destination = WarmPool`:

   - Update Name tag to indicate standby Controller.
   - Run initial setup and boot to specific version parsed from DB backup.

3. When `autoscaling_source = WarmPool` and `autoscaling_destination = AutoScalingGroup`:

   - Update Name tag to indicate standby instance is now active.
   - Assign the EIP to the new Controller.
   - Login and create temp AWS account.
   - Restore configuration from backup.
   - Update environment variables in Lambda.
