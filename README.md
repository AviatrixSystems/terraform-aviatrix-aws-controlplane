## Aviatrix with High Availability

### Goals:
1. Ensure Aviatrix Controller is always deployed with high availability

2. Support a hot standby Controller instance to reduce the Controller switchover time to under a minute

### Description:
This module creates AWS IAM credentials (IAM roles, policies, etc...), which are used to grant AWS API
permissions to Aviatrix Controller in order to allow it to access resources in AWS account(s). This
Terraform module should be run in the AWS account where you are installing the Controller.

This script will create the following:

1. An Aviatrix Role for Lambda with corresponding role policy with required permissions. 

2. An Aviatrix Role for Controller with corresponding role policy with required permissions.

3. A lambda function for handling Controller failover events and restoring configuration automatically on a new instance.

4. AWS launch template for Aviatrix controller instance.

5. An Aviatrix Autoscaling group with size 1 along with a warm pool instance.

6. SNS topic to trigger lambda.

7. Deploys 1 active Controller and another standby Controller which can be in running or stopped state.

### Pre-requisites:
- This module assumes that customer already has a vpc with atleast 2 public subnets allocated for Controller deployment.
- AWS Keypair should pre-exist and will be used by the lauch template to spin up Controller.
- S3 bucket for Controller backup should pre-exist.
- ASG uses the AWS managed AWSServiceRoleForAutoScaling role for publishing alert to SNS
- The admin password required to initilaize the Controller should be available in AWS Systems Manager parameter store at /aviatrix/controller/password
    aws ssm put-parameter --type "SecureString" --name "/aviatrix/controller/password" --value "XXXXXXXXX"
    

### Step by step Procedure:
1. Edit terraform.tfvars with approprite variables.
    ```
    keypair = "aviatrix"
    s3_backup_bucket = "aviatrix-backup"
    s3_backup_region = "us-east-1"
    termination_protection = false
    admin_email = "username@aviatrix.com"
    asg_notif_email = "username@aviatrix.com"
    access_account_name = "primary-avx"
    aws_account_id = "2945643167690"
    subnet_names = ["subnet-0eae17dc69a55b4c6","subnet-05050d18292ee5de7"]
    ```
2. Terraform apply

### Additional Information:
When SNS HA event is triggered there are 3 scenarios depending on `autoscaling_source` and `autoscaling_destination`:

1. When `autoscaling_source = EC2` and `autoscaling_destination = AutoScalingGroup`:

    i) Assigns the EIP created through terraform to the new Controller.

    ii) Run initial setup and boot to latest version.

    iii) Set admin email and password.

    iv) Create primary AWS account.

    v) Setup S3 backup.

    vi) Update environment variables in lambda which will be used by next event.

2. When `autoscaling_source = EC2` and `autoscaling_destination = WarmPool`:

    i) Update Name tag to indicate standby Controller.

    ii) Run initial setup and boot to specific version parsed from DB backup.

3. When `autoscaling_source = WarmPool` and `autoscaling_destination = AutoScalingGroup`:

    i) Update Name tag to indicate standby instance is now active.

    ii) Assign the EIP to the new Controller.

    iii) Login and create temp AWS account.

    iv) Restore configuration from backup.

    v) Update environment variables in lambda.
