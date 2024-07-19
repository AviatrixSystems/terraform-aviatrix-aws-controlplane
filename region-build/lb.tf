resource "aws_lb" "avtx-controller" {
  #checkov:skip=CKV_AWS_150: Ensure that Load Balancer has deletion protection enabled - AVXIT-7569
  #checkov:skip=CKV_AWS_91: Ensure the ELBv2 (Application/Network) has access logging enabled - AVXIT-7570
  name                             = "${local.name_prefix}AviatrixControllerLB"
  internal                         = false
  load_balancer_type               = var.load_balancer_type
  security_groups                  = tolist([aws_security_group.AviatrixSecurityGroup.id, aws_security_group.AviatrixCopilotSecurityGroup.id])
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

resource "aws_lb_listener" "avtx-ctrl" {
  #checkov:skip=CKV_AWS_2: Ensure ALB protocol is HTTPS - AVXIT-7571
  load_balancer_arn = aws_lb.avtx-controller.arn
  port              = "443"
  protocol          = var.load_balancer_type == "application" ? "HTTPS" : "TCP"
  certificate_arn   = var.load_balancer_type == "application" ? var.alb_cert_arn : null

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
  count  = var.configure_waf ? 1 : 0
  source = "./modules/terraform-aws-waf"

  alb_waf_name = "aviatrix_controller_waf"
  alb_arn      = aws_lb.avtx-controller.arn
  depends_on   = [aws_lb.avtx-controller]
}
