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