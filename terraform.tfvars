keypair                = "aviatrix"
dr_keypair             = "avx-ohio"
s3_backup_bucket       = "test-aviatrix-backup"
s3_backup_region       = "us-east-2"
termination_protection = false
admin_email            = "test@aviatrix.com"
asg_notif_email        = "test@aviatrix.com"
access_account_name    = "test-avx"
create_iam_roles       = false
use_existing_vpc       = false
region                 = "us-east-1"
dr_region              = "us-east-2"
incoming_ssl_cidr      = ["x.x.x.x/32"]
controller_version     = "6.6"
ha_distribution        = "inter-region"
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

dr_vpc_cidr = "10.100.0.0/24"

zone_name         = "aviatrix.link"
record_name       = "controller.aviatrix.link"