![Aviatrix Logo](.github/images/Aviatrix_logo.png)
# Terraform Module Usage in AWS

## Prerequisites

Check the following before getting started:

*   [Terraform CLI](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) is installed on your local machine.
*   You have an AWS account with the necessary permissions.
*   [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) is installed and configured.

### AWS CLI Authentication

Terraform will automatically use your default CLI credentials to interact with AWS.

You can set these credentials via `aws configure` command. You will be prompted to enter your Access Key, Secret Key, and default region:

```bash
aws configure
```

Prompt:

    AWS Access Key ID [None]: YOUR_ACCESS_KEY
    AWS Secret Access Key [None]: YOUR_SECRET_KEY
    Default region name [None]: us-west-2
    Default output format [None]: json

For more details on how to configure aws-cli, please visit the [official documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html).

## Using the Module

Specify the module source and version in your `.tf` file, along with any required inputs.

```hcl
module "vpc" {
    source  = "aviatrix/controlplane-aws" // TODO: Update when in registry
    version = "0.10.5" // Only available using terraform registry

    ha_distribution         = "inter-az"
    access_account_name     = "AWS-Account"
    admin_email             = "admin@example.com"
    asg_notif_email         = "asg@example.com"
    incoming_ssl_cidr       = ["x.x.x.x/32"]
    cop_incoming_https_cidr = ["x.x.x.x/32"]
    keypair                 = "keypair1" // Must create manually
    s3_backup_bucket        = "backup-bucket" // Must create manually
    s3_backup_region        = "us-east-1"

    // Optional
    avx_customer_id = "aviatrix.com-abu-aBcd123-123456789.456789" // Update with your customer_id
}
```

### Initialize and Apply Configuration

Once you've set up your configuration, initialize and apply it:

Enter the following into your terminal.
1. `terraform init`
2. `terraform apply`

*Note: You will have to enter 'yes' in your cli to confirm your changes for `terraform apply`.

Deployment takes ~25 minutes to complete. Grab a coffee or read more about what Aviatrix can do [here](https://aviatrix.com/secure-cloud-networking/)

For more details on how to use terraform, please visit the [official documentation](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/infrastructure-as-code)

## Last Words

Remember to use `terraform plan` before applying a configuration. It'll give you handy preview.

And one final tip, it is always a good practice to version control your Terraform configurations.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.13 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~>5.16.1 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~>5.16.1 |
| <a name="provider_http"></a> [http](#provider\_http) | n/a |
| <a name="provider_null"></a> [null](#provider\_null) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_aviatrix-iam-roles"></a> [aviatrix-iam-roles](#module\_aviatrix-iam-roles) | ./aviatrix-controller-iam-roles | n/a |
| <a name="module_region1"></a> [region1](#module\_region1) | ./region-build | n/a |
| <a name="module_region2"></a> [region2](#module\_region2) | ./region-build | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_iam_policy.ecs-policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.eventbridge-policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.iam_for_ecs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.iam_for_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy_attachment.attach-policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.eventbridge-attach-policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_route53_record.avx_primary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [null_resource.region_conflict](https://registry.terraform.io/providers/hashicorp/null/latest/docs/resources/resource) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_route53_zone.avx_zone](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/route53_zone) | data source |
| [http_http.avx_iam_id](https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http) | data source |
| [http_http.copilot_iam_id](https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_access_account_name"></a> [access\_account\_name](#input\_access\_account\_name) | The controller account friendly name (mapping to the AWS account ID) | `string` | n/a | yes |
| <a name="input_admin_email"></a> [admin\_email](#input\_admin\_email) | Controller admin email address | `string` | n/a | yes |
| <a name="input_app_role_name"></a> [app\_role\_name](#input\_app\_role\_name) | n/a | `string` | `"aviatrix-role-app"` | no |
| <a name="input_asg_notif_email"></a> [asg\_notif\_email](#input\_asg\_notif\_email) | Email address for Controller failover notifications | `string` | n/a | yes |
| <a name="input_avx_copilot_password"></a> [avx\_copilot\_password](#input\_avx\_copilot\_password) | The service account password for the Aviatrix CoPilot | `string` | `""` | no |
| <a name="input_avx_copilot_password_ssm_path"></a> [avx\_copilot\_password\_ssm\_path](#input\_avx\_copilot\_password\_ssm\_path) | The path to the password for CoPilot | `string` | `"/aviatrix/copilot/password"` | no |
| <a name="input_avx_customer_id"></a> [avx\_customer\_id](#input\_avx\_customer\_id) | The customer ID | `string` | `""` | no |
| <a name="input_avx_customer_id_ssm_path"></a> [avx\_customer\_id\_ssm\_path](#input\_avx\_customer\_id\_ssm\_path) | The path to the Aviatrix customer ID | `string` | `"/aviatrix/controller/customer_id"` | no |
| <a name="input_avx_customer_id_ssm_region"></a> [avx\_customer\_id\_ssm\_region](#input\_avx\_customer\_id\_ssm\_region) | The region the customer ID parameter is in | `string` | `"us-east-1"` | no |
| <a name="input_avx_password"></a> [avx\_password](#input\_avx\_password) | The admin password for the Aviatrix Controller | `string` | `""` | no |
| <a name="input_avx_password_ssm_path"></a> [avx\_password\_ssm\_path](#input\_avx\_password\_ssm\_path) | The path to the Aviatrix password | `string` | `"/aviatrix/controller/password"` | no |
| <a name="input_avx_password_ssm_region"></a> [avx\_password\_ssm\_region](#input\_avx\_password\_ssm\_region) | The region the password parameter is in | `string` | `"us-east-1"` | no |
| <a name="input_controller_ha_enabled"></a> [controller\_ha\_enabled](#input\_controller\_ha\_enabled) | Whether HA is enabled for the Controller | `bool` | `true` | no |
| <a name="input_controller_name"></a> [controller\_name](#input\_controller\_name) | Name of controller that will be launched | `string` | `""` | no |
| <a name="input_controller_version"></a> [controller\_version](#input\_controller\_version) | The initial version of the Aviatrix Controller at launch | `string` | `"latest"` | no |
| <a name="input_cop_controller_auth_ip"></a> [cop\_controller\_auth\_ip](#input\_cop\_controller\_auth\_ip) | Controller IP type to be used by CoPilot for authentication - public, or private | `string` | `"public"` | no |
| <a name="input_cop_default_data_volume_size"></a> [cop\_default\_data\_volume\_size](#input\_cop\_default\_data\_volume\_size) | Default data volume disk size for Copilot | `number` | `8` | no |
| <a name="input_cop_default_data_volume_type"></a> [cop\_default\_data\_volume\_type](#input\_cop\_default\_data\_volume\_type) | Default data volume type for Copilot | `string` | `"gp3"` | no |
| <a name="input_cop_incoming_https_cidr"></a> [cop\_incoming\_https\_cidr](#input\_cop\_incoming\_https\_cidr) | Incoming CIDR for HTTPS access to the CoPilot | `list(string)` | n/a | yes |
| <a name="input_cop_incoming_netflow_cidr"></a> [cop\_incoming\_netflow\_cidr](#input\_cop\_incoming\_netflow\_cidr) | Incoming CIDR for Netflow sources to the CoPilot | `list(string)` | <pre>[<br>  "0.0.0.0/0"<br>]</pre> | no |
| <a name="input_cop_incoming_syslog_cidr"></a> [cop\_incoming\_syslog\_cidr](#input\_cop\_incoming\_syslog\_cidr) | Incoming CIDR for Syslog sources to the CoPilot | `list(string)` | <pre>[<br>  "0.0.0.0/0"<br>]</pre> | no |
| <a name="input_cop_instance_type"></a> [cop\_instance\_type](#input\_cop\_instance\_type) | CoPilot instance size | `string` | `"t3.2xlarge"` | no |
| <a name="input_cop_root_volume_size"></a> [cop\_root\_volume\_size](#input\_cop\_root\_volume\_size) | Root volume disk size for Copilot | `number` | `25` | no |
| <a name="input_cop_root_volume_type"></a> [cop\_root\_volume\_type](#input\_cop\_root\_volume\_type) | Root volume type for Copilot | `string` | `"gp3"` | no |
| <a name="input_cop_type"></a> [cop\_type](#input\_cop\_type) | Type of billing, can be 'Copilot' or 'CopilotARM' | `string` | `"Copilot"` | no |
| <a name="input_copilot_data_node_count"></a> [copilot\_data\_node\_count](#input\_copilot\_data\_node\_count) | Desired number of CoPilot data nodes in a Fault-Tolerant deployment | `number` | `3` | no |
| <a name="input_copilot_deployment"></a> [copilot\_deployment](#input\_copilot\_deployment) | Desired CoPilot deployment type | `string` | `"simple"` | no |
| <a name="input_copilot_email"></a> [copilot\_email](#input\_copilot\_email) | CoPilot user email address, if desired | `string` | `""` | no |
| <a name="input_copilot_ha_enabled"></a> [copilot\_ha\_enabled](#input\_copilot\_ha\_enabled) | Whether HA is enabled for CoPilot | `bool` | `true` | no |
| <a name="input_copilot_name"></a> [copilot\_name](#input\_copilot\_name) | Name of copilot that will be launched | `string` | `""` | no |
| <a name="input_copilot_username"></a> [copilot\_username](#input\_copilot\_username) | CoPilot service account username, if desired | `string` | `""` | no |
| <a name="input_create_iam_roles"></a> [create\_iam\_roles](#input\_create\_iam\_roles) | n/a | `bool` | `true` | no |
| <a name="input_dr_keypair"></a> [dr\_keypair](#input\_dr\_keypair) | Key pair which should be used by Aviatrix controller | `string` | `""` | no |
| <a name="input_dr_region"></a> [dr\_region](#input\_dr\_region) | DR Region for Aviatrix Controller | `string` | `"us-east-2"` | no |
| <a name="input_dr_subnet_ids"></a> [dr\_subnet\_ids](#input\_dr\_subnet\_ids) | n/a | `list(string)` | `[]` | no |
| <a name="input_dr_vpc"></a> [dr\_vpc](#input\_dr\_vpc) | VPC in which you want launch Aviatrix controller | `string` | `""` | no |
| <a name="input_dr_vpc_cidr"></a> [dr\_vpc\_cidr](#input\_dr\_vpc\_cidr) | n/a | `string` | `"10.0.1.0/24"` | no |
| <a name="input_dr_vpc_name"></a> [dr\_vpc\_name](#input\_dr\_vpc\_name) | n/a | `string` | `"Aviatrix-DR-VPC"` | no |
| <a name="input_ec2_role_name"></a> [ec2\_role\_name](#input\_ec2\_role\_name) | n/a | `string` | `"aviatrix-role-ec2"` | no |
| <a name="input_existing_copilot_dr_eip"></a> [existing\_copilot\_dr\_eip](#input\_existing\_copilot\_dr\_eip) | Existing EIP to associate with the DR Aviatrix CoPilot | `string` | `""` | no |
| <a name="input_existing_copilot_eip"></a> [existing\_copilot\_eip](#input\_existing\_copilot\_eip) | Existing EIP to associate with the Aviatrix CoPilot (Main Node, in a Fault-Tolerant deployment) | `string` | `""` | no |
| <a name="input_existing_dr_eip"></a> [existing\_dr\_eip](#input\_existing\_dr\_eip) | Existing EIP to associate with the DR Aviatrix Controller | `string` | `""` | no |
| <a name="input_existing_eip"></a> [existing\_eip](#input\_existing\_eip) | Existing EIP to associate with the Aviatrix Controller | `string` | `""` | no |
| <a name="input_ha_distribution"></a> [ha\_distribution](#input\_ha\_distribution) | Desired Controller high availability distribution | `string` | `"single-az"` | no |
| <a name="input_incoming_ssl_cidr"></a> [incoming\_ssl\_cidr](#input\_incoming\_ssl\_cidr) | Incoming cidr for security group used by controller | `list(string)` | n/a | yes |
| <a name="input_instance_type"></a> [instance\_type](#input\_instance\_type) | Controller instance size | `string` | `"t3.large"` | no |
| <a name="input_inter_region_backup_enabled"></a> [inter\_region\_backup\_enabled](#input\_inter\_region\_backup\_enabled) | Specifies whether backups should be enabled on the primary controller in an inter-region deployment | `bool` | `false` | no |
| <a name="input_keypair"></a> [keypair](#input\_keypair) | Key pair which should be used by Aviatrix controller | `string` | n/a | yes |
| <a name="input_license_type"></a> [license\_type](#input\_license\_type) | Type of billing, can be 'MeteredPlatinum', 'BYOL' or 'Custom' | `string` | `"BYOL"` | no |
| <a name="input_name_prefix"></a> [name\_prefix](#input\_name\_prefix) | Additional name prefix for your environment resources | `string` | `"avx"` | no |
| <a name="input_private_zone"></a> [private\_zone](#input\_private\_zone) | private hostzone definition | `bool` | `false` | no |
| <a name="input_record_name"></a> [record\_name](#input\_record\_name) | The record name to be created under exisitng route 53 zone | `string` | `true` | no |
| <a name="input_region"></a> [region](#input\_region) | The region to deploy this module in | `string` | `"us-east-1"` | no |
| <a name="input_root_volume_size"></a> [root\_volume\_size](#input\_root\_volume\_size) | Root volume disk size for controller | `number` | `64` | no |
| <a name="input_root_volume_type"></a> [root\_volume\_type](#input\_root\_volume\_type) | Root volume type for Controller | `string` | `"gp3"` | no |
| <a name="input_s3_backup_bucket"></a> [s3\_backup\_bucket](#input\_s3\_backup\_bucket) | S3 bucket for Controller DB backup | `string` | n/a | yes |
| <a name="input_s3_backup_region"></a> [s3\_backup\_region](#input\_s3\_backup\_region) | AWS region of S3 backup bucket | `string` | n/a | yes |
| <a name="input_standby_instance_state"></a> [standby\_instance\_state](#input\_standby\_instance\_state) | Standby instance state definition | `string` | `"Running"` | no |
| <a name="input_subnet_ids"></a> [subnet\_ids](#input\_subnet\_ids) | n/a | `list(string)` | `[]` | no |
| <a name="input_subnet_name"></a> [subnet\_name](#input\_subnet\_name) | n/a | `string` | `"Aviatrix-Public-Subnet"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Map of common tags which should be used for module resources | `map(string)` | `{}` | no |
| <a name="input_termination_protection"></a> [termination\_protection](#input\_termination\_protection) | Enable/disable switch for termination protection | `bool` | `true` | no |
| <a name="input_use_existing_copilot_eip"></a> [use\_existing\_copilot\_eip](#input\_use\_existing\_copilot\_eip) | Set to true if using an existing EIP for CoPilot | `bool` | `false` | no |
| <a name="input_use_existing_eip"></a> [use\_existing\_eip](#input\_use\_existing\_eip) | Set to true if using an existing EIP | `bool` | `false` | no |
| <a name="input_use_existing_vpc"></a> [use\_existing\_vpc](#input\_use\_existing\_vpc) | Set to true to use existing VPC. | `bool` | `false` | no |
| <a name="input_vpc"></a> [vpc](#input\_vpc) | VPC in which you want launch Aviatrix controller | `string` | `""` | no |
| <a name="input_vpc_cidr"></a> [vpc\_cidr](#input\_vpc\_cidr) | n/a | `string` | `"10.0.0.0/24"` | no |
| <a name="input_vpc_name"></a> [vpc\_name](#input\_vpc\_name) | n/a | `string` | `"Aviatrix-VPC"` | no |
| <a name="input_zone_name"></a> [zone\_name](#input\_zone\_name) | The exisitng route 53 zone name | `string` | `true` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_controller_name"></a> [controller\_name](#output\_controller\_name) | n/a |
| <a name="output_controller_public_ip"></a> [controller\_public\_ip](#output\_controller\_public\_ip) | n/a |
| <a name="output_copilot_name"></a> [copilot\_name](#output\_copilot\_name) | n/a |
| <a name="output_copilot_public_ip"></a> [copilot\_public\_ip](#output\_copilot\_public\_ip) | n/a |
| <a name="output_dr_controller_public_ip"></a> [dr\_controller\_public\_ip](#output\_dr\_controller\_public\_ip) | n/a |
| <a name="output_dr_copilot_public_ip"></a> [dr\_copilot\_public\_ip](#output\_dr\_copilot\_public\_ip) | n/a |
| <a name="output_dr_lb_dns_name"></a> [dr\_lb\_dns\_name](#output\_dr\_lb\_dns\_name) | n/a |
| <a name="output_dr_region"></a> [dr\_region](#output\_dr\_region) | n/a |
| <a name="output_ha_distribution"></a> [ha\_distribution](#output\_ha\_distribution) | n/a |
| <a name="output_lb_dns_name"></a> [lb\_dns\_name](#output\_lb\_dns\_name) | n/a |
| <a name="output_log_group_name"></a> [log\_group\_name](#output\_log\_group\_name) | n/a |
| <a name="output_record_name"></a> [record\_name](#output\_record\_name) | n/a |
| <a name="output_region"></a> [region](#output\_region) | n/a |
| <a name="output_s3_backup_bucket"></a> [s3\_backup\_bucket](#output\_s3\_backup\_bucket) | n/a |
| <a name="output_s3_backup_region"></a> [s3\_backup\_region](#output\_s3\_backup\_region) | n/a |
| <a name="output_zone_name"></a> [zone\_name](#output\_zone\_name) | n/a |
<!-- END_TF_DOCS -->