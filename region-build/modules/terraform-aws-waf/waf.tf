resource "aws_wafv2_web_acl" "waf_acl" {
  #checkov:skip=CKV2_AWS_31: Ensure WAF2 has a Logging Configuration - AVXIT-7602
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
                    for_each = lookup(rule.value, "rule_group_override_action", null) == "count" ? ["count"] : []
                    content {}
                  }
                  dynamic "block" {
                    for_each = lookup(rule.value, "rule_group_override_action", null) == "block" ? ["block"] : []
                    content {}
                  }
                  dynamic "allow" {
                    for_each = lookup(rule.value, "rule_group_override_action", null) == "allow" ? ["allow"] : []
                    content {}
                  }
                  dynamic "captcha" {
                    for_each = lookup(rule.value, "rule_group_override_action", null) == "captcha" ? ["captcha"] : []
                    content {}
                  }
                  dynamic "challenge" {
                    for_each = lookup(rule.value, "rule_group_override_action", null) == "challenge" ? ["block"] : []
                    content {}
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
}

resource "aws_wafv2_web_acl_association" "associate_alb" {
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.waf_acl.arn
}
