output "loadbalancer" {
  value = module.region1.lb
}

output "lb_dns_name" {
  value = module.region1.lb.dns_name
}
