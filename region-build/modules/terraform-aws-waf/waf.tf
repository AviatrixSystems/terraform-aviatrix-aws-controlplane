resource "aws_wafv2_web_acl" "waf_acl" {
  count       = var.configure_waf == true ? 1 : 0
  name        = var.alb_waf_name
  scope       = var.scope
  description = join(" ", ["Aviatrix MGMT", var.scope, "WAF"])
  tags        = var.tags

  default_action {
    dynamic "block" {
      for_each = var.default_action == "block" ? ["block"] : []
      content {}
    }
    dynamic "allow" {
      for_each = var.default_action == "allow" ? ["allow"] : []
      content {}
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = var.visibility_config_cloudwatch_metrics_enabled
    metric_name                = var.visibility_config_metric_name == null ? var.alb_waf_name : var.visibility_config_metric_name
    sampled_requests_enabled   = var.visibility_config_sampled_requests_enabled
  }

  dynamic "rule" {
    for_each = var.waf_managed_rules
    content {
      name     = rule.value.name
      priority = rule.value.priority


      override_action {
        dynamic "count" {
          for_each = lookup(rule.value, "rule_override_action", "none") == "count" ? ["count"] : []
          content {}
        }
        dynamic "none" {
          for_each = lookup(rule.value, "rule_override_action", "none") == "none" ? ["none"] : []
          content {}
        }
      }

      statement {
        dynamic "managed_rule_group_statement" {
          for_each = lookup(rule.value, "name", null) == null ? [] : [rule]
          content {
            name        = rule.value.name
            vendor_name = rule.value.vendor_name
            dynamic "rule_action_override" {
              for_each = lookup(rule.value, "name", null) == null ? [] : [rule]
              content {
                name = rule.value.name # the name must give
                action_to_use {
                  dynamic "count" {
                    for_each = lookup(rule.value,"rule_group_override_action",null) == "count" ? ["count"] : []
                    content{} 
                  }
                  dynamic "block" {
                    for_each = lookup(rule.value,"rule_group_override_action",null) == "block" ? ["block"] : []
                    content{} 
                  }
                  dynamic "allow" {
                    for_each = lookup(rule.value,"rule_group_override_action",null) == "allow" ? ["allow"] : []
                    content{} 
                  }
                  dynamic "captcha" {
                    for_each = lookup(rule.value,"rule_group_override_action",null) == "captcha" ? ["captcha"] : []
                    content{} 
                  }
                  dynamic "challenge" {
                    for_each = lookup(rule.value,"rule_group_override_action",null) == "challenge" ? ["block"] : []
                    content{} 
                  }
                }
              }
            }
            dynamic "scope_down_statement" {
              for_each = lookup(rule.value, "saml_endpoint_name_bypass", null) == null ? [] : [rule]
              content {
                  and_statement {
                    statement {
                      not_statement {
                        statement {
                          label_match_statement {
                            key   = rule.value.saml_bypass_rule_label
                            scope = "LABEL"
                          }
                        }
                      }
                    }
                    statement {
                      not_statement {
                        statement {
                          byte_match_statement {
                            positional_constraint = "EXACTLY"
                            search_string         = "/flask/saml/sso/${rule.value.saml_endpoint_name_bypass}"
                            field_to_match {
                              uri_path {}
                            }
                            text_transformation {
                              priority = 0
                              type     = "NONE"
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = lookup(rule.value, "cloudwatch_metrics_enabled", true)
        metric_name                = rule.value.name
        sampled_requests_enabled   = lookup(rule.value, "sampled_requests_enabled", true)
      }
    }
  }

  dynamic "rule" {
    for_each = var.waf_ip_set_rules
    content {
      name     = join(var.delimiter, [var.alb_waf_name, rule.value.name, lookup(rule.value, "action", "count")])
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = lookup(rule.value, "action", "none") == "allow" ? ["allow"] : []
          content {}
        }
        dynamic "block" {
          for_each = lookup(rule.value, "action", "none") == "block" ? ["block"] : []
          content {}
        }
        dynamic "count" {
          for_each = lookup(rule.value, "action", "count") == "count" ? ["count"] : []
          content {}
        }
      }

      statement {
        dynamic "ip_set_reference_statement" {
          for_each = lookup(rule.value, "name", null) == null ? [] : [rule]
          content {
            arn = aws_wafv2_ip_set.default[rule.key].arn
            dynamic "ip_set_forwarded_ip_config" {
              for_each = lookup(rule.value, "ip_set_forwarded_ip_config", null) == null ? [] : [rule.value.ip_set_forwarded_ip_config]
              content {
                fallback_behavior = lookup(ip_set_forwarded_ip_config.value, "fallback_behavior", null)
                header_name       = lookup(ip_set_forwarded_ip_config.value, "header_name", null)
                position          = lookup(ip_set_forwarded_ip_config.value, "position", null)
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = lookup(rule.value, "cloudwatch_metrics_enabled", true)
        metric_name                = join(var.delimiter, [var.alb_waf_name, rule.value.name, lookup(rule.value, "action", "count")])
        sampled_requests_enabled   = lookup(rule.value, "sampled_requests_enabled", true)
      }
    }
  }

  dynamic "rule" {
    for_each = var.waf_geo_match_rules
    content {
      name     = join(var.delimiter, [var.alb_waf_name, "geo-match", rule.value.priority, lookup(rule.value, "action", "count")])
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = lookup(rule.value, "action", "none") == "allow" ? ["allow"] : []
          content {}
        }
        dynamic "block" {
          for_each = lookup(rule.value, "action", "none") == "block" ? ["block"] : []
          content {}
        }
        dynamic "count" {
          for_each = lookup(rule.value, "action", "count") == "count" ? ["count"] : []
          content {}
        }
      }

      statement {
        dynamic "geo_match_statement" {
          for_each = lookup(rule.value, "country_codes", null) == null ? [] : [rule]
          content {
            country_codes = rule.value.country_codes
            dynamic "forwarded_ip_config" {
              for_each = lookup(geo_match_statement.value, "forwarded_ip_config", null) == null ? [] : [geo_match_statement]
              content {
                fallback_behavior = lookup(rule.value.forwarded_ip_config, "fallback_behavior", null)
                header_name       = lookup(rule.value.forwarded_ip_config, "header_name", null)
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = lookup(rule.value, "cloudwatch_metrics_enabled", true)
        metric_name                = join(var.delimiter, [var.alb_waf_name, "geo-match", rule.value.priority, lookup(rule.value, "action", "count")])
        sampled_requests_enabled   = lookup(rule.value, "sampled_requests_enabled", true)
      }
    }
  }
}

resource "aws_wafv2_ip_set" "default" {
  count = var.configure_waf == true ? length(var.waf_ip_set_rules) : 0
  name  = join(var.delimiter, [var.alb_waf_name, var.waf_ip_set_rules[count.index].name])
  tags  = var.tags

  scope              = var.scope
  ip_address_version = lookup(var.waf_ip_set_rules[count.index], "ip_address_version", "IPV4")
  addresses          = var.waf_ip_set_rules[count.index].addresses

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_web_acl_association" "associate_alb" {
  count       = var.configure_waf != true ? 0 : var.scope == "REGIONAL" ? 1 : 0
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.waf_acl[0].arn
}
