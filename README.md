## Providers

| Name | Version |
|------|---------|
| <a name="provider_terraform"></a> [terraform](#provider\_terraform) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_controller_build"></a> [controller\_build](#module\_controller\_build) | ./modules/controller_build | n/a |
| <a name="module_controller_init"></a> [controller\_init](#module\_controller\_init) | terraform-aviatrix-modules/controller-init/aviatrix | v1.0.3 |
| <a name="module_copilot_build"></a> [copilot\_build](#module\_copilot\_build) | ./modules/copilot_build | n/a |
| <a name="module_copilot_init"></a> [copilot\_init](#module\_copilot\_init) | terraform-aviatrix-modules/copilot-init/aviatrix | v1.0.3 |
| <a name="module_iam"></a> [iam](#module\_iam) | ./modules/iam_roles | n/a |

## Resources

| Name | Type |
|------|------|
| [terraform_data.input_checks](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_account_email"></a> [account\_email](#input\_account\_email) | aviatrix controller access account email | `string` | n/a | yes |
| <a name="input_controller_admin_email"></a> [controller\_admin\_email](#input\_controller\_admin\_email) | aviatrix controller admin email address | `string` | n/a | yes |
| <a name="input_controller_admin_password"></a> [controller\_admin\_password](#input\_controller\_admin\_password) | aviatrix controller admin password | `string` | n/a | yes |
| <a name="input_controller_ami_id"></a> [controller\_ami\_id](#input\_controller\_ami\_id) | AMI ID for controller. If unset, use official image. | `string` | `""` | no |
| <a name="input_controller_name"></a> [controller\_name](#input\_controller\_name) | Customized Name for Aviatrix Controller | `string` | `"Aviatrix-Controller"` | no |
| <a name="input_controller_user_data"></a> [controller\_user\_data](#input\_controller\_user\_data) | User data for starting the controller | `string` | `""` | no |
| <a name="input_controller_version"></a> [controller\_version](#input\_controller\_version) | Aviatrix Controller version | `string` | `"latest"` | no |
| <a name="input_controller_virtual_machine_admin_password"></a> [controller\_virtual\_machine\_admin\_password](#input\_controller\_virtual\_machine\_admin\_password) | Admin Password for the controller virtual machine. | `string` | `"aviatrix1234!"` | no |
| <a name="input_controller_virtual_machine_admin_username"></a> [controller\_virtual\_machine\_admin\_username](#input\_controller\_virtual\_machine\_admin\_username) | Admin Username for the controller virtual machine. | `string` | `"aviatrix"` | no |
| <a name="input_controller_virtual_machine_size"></a> [controller\_virtual\_machine\_size](#input\_controller\_virtual\_machine\_size) | Virtual Machine size for the controller. | `string` | `"t3a.large"` | no |
| <a name="input_controller_wait_for_setup_duration"></a> [controller\_wait\_for\_setup\_duration](#input\_controller\_wait\_for\_setup\_duration) | Duration to wait for controller setup to complete | `string` | `"10m"` | no |
| <a name="input_controlplane_subnet_cidr"></a> [controlplane\_subnet\_cidr](#input\_controlplane\_subnet\_cidr) | CIDR for controlplane subnet. | `string` | `"10.0.0.0/24"` | no |
| <a name="input_copilot_name"></a> [copilot\_name](#input\_copilot\_name) | Customized Name for Aviatrix Copilot | `string` | `"Aviatrix-Copilot"` | no |
| <a name="input_customer_id"></a> [customer\_id](#input\_customer\_id) | aviatrix customer license id | `string` | n/a | yes |
| <a name="input_incoming_ssl_cidrs"></a> [incoming\_ssl\_cidrs](#input\_incoming\_ssl\_cidrs) | Incoming cidrs for security group used by controller | `list(string)` | n/a | yes |
| <a name="input_key_pair_name"></a> [key\_pair\_name](#input\_key\_pair\_name) | Key pair name | `string` | `""` | no |
| <a name="input_module_config"></a> [module\_config](#input\_module\_config) | n/a | `map` | <pre>{<br/>  "controller_deployment": true,<br/>  "controller_iam": true,<br/>  "controller_initialization": true,<br/>  "copilot_deployment": true,<br/>  "copilot_initialization": true<br/>}</pre> | no |
| <a name="input_region"></a> [region](#input\_region) | Deployment region for Aviatrix Controller | `string` | `"us-east-1"` | no |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | Subnet ID, only required when use\_existing\_vpc is true | `string` | `""` | no |
| <a name="input_subnet_name"></a> [subnet\_name](#input\_subnet\_name) | subnet name, only required when use\_existing\_vpc is true | `string` | `""` | no |
| <a name="input_use_existing_keypair"></a> [use\_existing\_keypair](#input\_use\_existing\_keypair) | Flag to indicate whether to use an existing key pair | `bool` | `false` | no |
| <a name="input_use_existing_vpc"></a> [use\_existing\_vpc](#input\_use\_existing\_vpc) | Flag to indicate whether to use an existing VPC | `bool` | `false` | no |
| <a name="input_virtual_machine_admin_password"></a> [virtual\_machine\_admin\_password](#input\_virtual\_machine\_admin\_password) | n/a | `string` | `""` | no |
| <a name="input_virtual_machine_admin_username"></a> [virtual\_machine\_admin\_username](#input\_virtual\_machine\_admin\_username) | n/a | `string` | `"avx_admin"` | no |
| <a name="input_vpc_name"></a> [vpc\_name](#input\_vpc\_name) | VPC name, only required when use\_existing\_vpc is true | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_controller_private_ip"></a> [controller\_private\_ip](#output\_controller\_private\_ip) | n/a |
| <a name="output_controller_public_ip"></a> [controller\_public\_ip](#output\_controller\_public\_ip) | n/a |
| <a name="output_copilot_private_ip"></a> [copilot\_private\_ip](#output\_copilot\_private\_ip) | n/a |
| <a name="output_copilot_public_ip"></a> [copilot\_public\_ip](#output\_copilot\_public\_ip) | n/a |
