resource "aws_lb" "avtx-controller" {
  name                             = "${local.name_prefix}AviatrixControllerLB"
  internal                         = false
  load_balancer_type               = "network"
  enable_cross_zone_load_balancing = true
  idle_timeout                     = "300"
  subnets                          = var.use_existing_vpc ? var.subnet_names : tolist([aws_subnet.subnet[0].id, aws_subnet.subnet_ha[0].id])
  enable_deletion_protection       = var.termination_protection

  tags = {
    Name = "${local.name_prefix}AviatrixControllerLB"
  }
}

# Define a listener
resource "aws_lb_listener" "avtx-ctrl" {
  load_balancer_arn = aws_lb.avtx-controller.arn
  port              = "443"
  protocol          = "TCP"

  default_action {
    target_group_arn = aws_lb_target_group.avtx-controller.arn
    type             = "forward"
  }
}

resource "aws_lb_target_group" "avtx-controller" {
  name     = "${local.name_prefix}controller"
  port     = 443
  protocol = "TCP"
  vpc_id   = var.use_existing_vpc ? var.vpc : aws_vpc.vpc[0].id

  depends_on = [aws_lb.avtx-controller]

  lifecycle {
    create_before_destroy = true
  }
}
