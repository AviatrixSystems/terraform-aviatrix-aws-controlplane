resource "aws_lb" "avtx-controller" {
  name                             = "${local.name_prefix}AviatrixControllerLB"
  internal                         = false
  load_balancer_type               = var.load_balancer_type
  security_groups                  = var.load_balancer_type == "application" ? tolist([aws_security_group.AviatrixSecurityGroup.id,aws_security_group.AviatrixCopilotSecurityGroup.id]) : null
  enable_cross_zone_load_balancing = true
  idle_timeout                     = var.load_balancer_type == "application" ? "900" : "300"
  subnets                          = var.use_existing_vpc ? var.subnet_ids : tolist([aws_subnet.subnet[0].id, aws_subnet.subnet_ha[0].id])

  tags = {
    Name = "${local.name_prefix}AviatrixControllerLB"
  }

  depends_on = [
    aws_internet_gateway.igw
  ]
}

# Define a listener
data "aws_acm_certificate" "avtx_ctrl" {
  count             = var.load_balancer_type == "application" ? 1 : 0
  domain            = var.cert_domain_name
  statuses          = ["ISSUED"]
}

resource "aws_lb_listener" "avtx-ctrl" {
  load_balancer_arn = aws_lb.avtx-controller.arn
  port              = "443"
  protocol          = var.load_balancer_type == "application" ? "HTTPS" : "TCP"
  certificate_arn   = var.load_balancer_type == "application" ? data.aws_acm_certificate.avtx_ctrl[0].arn : null 

  default_action {
    target_group_arn = aws_lb_target_group.avtx-controller.arn
    type             = "forward"
  }
}

resource "aws_lb_target_group" "avtx-controller" {
  name     = "${local.name_prefix}controller"
  port     = 443
  protocol = var.load_balancer_type == "application" ? "HTTPS" : "TCP"
  vpc_id   = var.use_existing_vpc ? var.vpc : aws_vpc.vpc[0].id

  depends_on = [aws_lb.avtx-controller]

  lifecycle {
    create_before_destroy = true
  }
}

module "controller_alb_waf" {
  source = "./modules/terraform-aws-waf"

  configure_waf                                = var.configure_waf
  alb_waf_name                                 =  "aviatrix_controller_waf"
  alb_arn                                      = aws_lb.avtx-controller.arn
  waf_managed_rules                                = var.waf_managed_rules
  waf_ip_set_rules                                 = var.waf_ip_set_rules
  waf_geo_match_rules                              = var.waf_geo_match_rules
  depends_on = [ aws_lb.avtx-controller ]
}