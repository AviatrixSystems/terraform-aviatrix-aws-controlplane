## Aviatrix with High Availability

### Goals

- Ensure an Aviatrix Controller is always deployed with high availability
- Optionally support a hot standby Controller instance which reduces Controller switchover time to under a minute

### Description

This module creates AWS IAM credentials (IAM roles, policies, etc...), which are used to grant AWS API permissions to Aviatrix Controller in order to allow it to access resources in AWS account(s). This Terraform module should be run in the AWS account where you are installing the Controller.

The module will create the following:

1. An Aviatrix Role for Lambda with corresponding role policy with required permissions.
2. An Aviatrix Role for Controller with corresponding role policy with required permissions.
3. A Lambda function for handling Controller failover events and restoring configuration automatically on a new instance.
4. AWS launch template for Aviatrix Controller instance.
5. An Aviatrix Auto Scaling group with a size of 1 along with an optional warm pool instance.
6. An SNS topic to trigger Lambda.
7. An active Controller and a standby Controller which can be in running or stopped state.

### Prerequisites

- ~~This module assumes that customer already has a vpc with atleast 2 public subnets allocated for Controller deployment.~~
- The AWS Keypair should pre-exist and will be used by the lauch template to spin up Controller.
- The S3 bucket for Controller backup should pre-exist.
- The Auto Scaling group uses the AWS managed AWSServiceRoleForAutoScaling role for publishing alerts to SNS.
- The admin password required to initilaize the Controller should be set in the AWS Systems Manager parameter store at /aviatrix/controller/password.

  `aws ssm put-parameter --type "SecureString" --name "/aviatrix/controller/password" --value "XXXXXXXXX"`

### Usage Example

```
module "aws_controller_ha" {
  source              = "github.com/aviatrix-automation/AWS_Controller"
  region              = "us-east-1"
  dr_region           = "us-east-2"
  keypair             = "keypair1"
  dr_keypair          = "keypair2"
  incoming_ssl_cidr   = ["1.1.1.1/32"]
  access_account_name = "AWS-account"
  admin_email         = "admin@example.com"
  asg_notif_email     = "asg@example.com"
  s3_backup_bucket    = "backup-bucket"
  s3_backup_region    = "us-east-1"
}
```

### Variables

| Key                         | Default Value                              | Description                                                                                                                                   |
| --------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| access_account_name         |                                            | A friendly name mapping to your AWS account ID                                                                                                |
| admin_email                 |                                            | The administrator's email address. This email address will be used for password recovery as well as for notifications from the Controller.    |
| asg_notif_email             |                                            | The email address for Controller failover notifications                                                                                       |
| app_role_name               | aviatrix-role-app                          | The name of the Aviatrix App role                                                                                                             |
| controller_version          | ""                                         | The initial version of the Aviatrix Controller at launch                                                                                      |
| cop_allowed_cidrs           | TCP 443, UDP 5000, UDP 31283 for 0.0.0.0/0 | CoPilot allowed CIDRs                                                                                                                         |
| cop_instance_type           | t3.2xlarge                                 | CoPilot instance size                                                                                                                         |
| cop_type                    | Copilot                                    | Type of billing, can be 'Copilot' or 'CopilotARM'                                                                                             |
| cop_root_volume_size        | 2000                                       | Root volume disk size for CoPilot                                                                                                             |
| cop_root_volume_type        | gp3                                        | Root volume type for CoPilot                                                                                                                  |
| copilot_name                |                                            | Name of CoPilot                                                                                                                               |
| create_iam_roles            | true                                       | Whether to create the IAM roles used to grant AWS API permissions to the Aviatrix Controller                                                  |
| dr_keypair                  |                                            | Key pair which should be used by DR Controller                                                                                                |
| dr_region                   | ""                                         | Region to deploy the DR Controller                                                                                                            |
| dr_subnet_names             |                                            | The list of existing subnets to deploy the Controller in. Only applicable if `use_existing_vpc` is true.                                      |
| dr_vpc                      | ""                                         | VPC to deploy DR Controlller. Only applicable if `use_existing_vpc` is true).                                                                 |
| dr_vpc_cidr                 | 10.0.0.0/24                                | The CIDR for the VPC to create for the DR Controller. Only applicable if `ha_distribution` is "inter-region" and `use_existing_vpc` is false. |
| dr_vpc_name                 | ""                                         | The name for the VPC to create for the DR Controller. Only applicable if `ha_distribution` is "inter-region" and `use_existing_vpc` is false. |
| ec2_role_name               | aviatrix-role-ec2                          | The name of the Aviatrix EC2 role                                                                                                             |
| ha_distribution             | single-az                                  | Desired Controller high availability distribution. Valid values are 'single-az', 'inter-az', and 'inter-region'.                              |
| incoming_ssl_cidr           |                                            | Incoming CIDR for security group used by Controller                                                                                           |
| instance_type               | t3.xlarge                                  | Controller instance size                                                                                                                      |
| inter_region_backup_enabled | false                                      | Whether to enable backups on the primary controller. Only applicable if `ha_distribution` is "inter-region".                                  |
| keypair                     |                                            | Key pair which should be used by Controller                                                                                                   |
| license_type                | BYOL                                       | Type of billing, can be 'MeteredPlatinum', 'BYOL' or 'Custom'                                                                                 |
| name_prefix                 | avx                                        | Additional name prefix for resources created by this module                                                                                   |
| preemptive                  | false                                      | Whether to switch back to the primary Controller when it comes back online.                                                                   |
| record_name                 | true                                       | The record name to be created under the exisitng route 53 zone specified by `zone_name`. Required if `ha_distribution` is 'inter-region'.     |
| region                      |                                            | Region to deploy the Controller and CoPilot                                                                                                   |
| root_volume_size            | 64                                         | Root volume disk size for Controller                                                                                                          |
| root_volume_type            | gp3                                        | Root volume type for Controller                                                                                                               |
| s3_backup_bucket            |                                            | S3 bucket for Controller DB backup                                                                                                            |
| s3_backup_region            |                                            | Region S3 backup bucket is in                                                                                                                 |
| subnet_name                 | Aviatrix-Public-Subnet                     | The subnet name to create for the Controller. Only applicable if `use_existing_vpc` is false.                                                 |
| subnet_names                |                                            | The list of existing subnets to deploy the Controller in. Only applicable if `use_existing_vpc` is true.                                      |
| tags                        |                                            | Map of common tags which should be used for module resources                                                                                  |
| termination_protection      | true                                       | Whether to enable termination protection on the Controller, CoPilot and load balancers                                                        |
| use_existing_vpc            | false                                      | Set to true to deploy Controller and CoPilot to existing VPCs specified by `vpc` and `dr_vpc`.                                                |
| vpc                         | ""                                         | VPC to deploy Controlller and CoPilot in. Only applicable if `use_existing_vpc` is true.                                                      |
| vpc_cidr                    | 10.0.0.0/24                                | The CIDR for the VPC to create for the Controller. Only applicable if `use_existing_vpc` is false.                                            |
| vpc_name                    | Aviatrix-VPC                               | The name for the VPC to create for the Controller. Only applicable if `use_existing_vpc` is false.                                            |
| zone_name                   | true                                       | The existing Route 53 zone to create a record in. Required if `ha_distribution` is 'inter-region'.                                            |

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
