keypair                = "avx-ohio"
dr_keypair = "Aviatrix-ireland"
s3_backup_bucket       = "test-aviatrix-backup"
s3_backup_region       = "us-east-2"
termination_protection = false
admin_email            = "pbomma@aviatrix.com"
asg_notif_email        = "pbomma@aviatrix.com"
access_account_name    = "pbomma-avx"
create_iam_roles = false
use_existing_vpc = false
# subnet_names           = ["subnet-04262f4d3b52cbc1e", "subnet-0d9db21881453147c"]
# vpc                    = "vpc-07a080e59b83698a1"
region = "us-east-1"
dr_region = "us-east-2"
incoming_ssl_cidr      = ["0.0.0.0/0"]
controller_version     = "6.6"
ha_distribution        = "single-az"
cop_allowed_cidrs = {
  "tcp_cidrs" = {
    protocol = "tcp"
    port     = "443"
    cidrs    = ["0.0.0.0/0"]
  }
  "udp_cidrs_1" = {
    protocol = "udp"
    port     = "5000"
    cidrs    = ["0.0.0.0/0"]
  }
  "udp_cidrs_2" = {
    protocol = "udp"
    port     = "31283"
    cidrs    = ["0.0.0.0/0"]
  }
}

enable_inter_region = false