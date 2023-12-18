variable "configure_waf" {
  type = bool
  description = "Whether WAF is enabled for the controller"
  default = false
}

variable "scope" {
  type        = string
  description = "Deployment WAF deployment scope"
  default     = "REGIONAL"
  validation {
    condition = contains(["REGIONAL"], var.scope)
    error_message = "Valid values for var: scope is (REGIONAL)"
  }
}
variable "default_action" {
  type        = string
  description = " Action to perform if none of the rules contained in the WebACL match"
  default     = "allow"
  validation {
    condition = contains(["allow","block"], var.default_action)
    error_message = "Valid values for var: default_action are (allow , block)"
  }
}

variable "waf_managed_rules" {
    type = list
    description = " WAF default managed group rules by AWS offering"
    default = [
        {
            name                       = "AWSManagedRulesCommonRuleSet"
            vendor_name                = "AWS"
            priority                   = 10
            rule_override_action       = "none" #rule_override_action
            rule_group_override_action = "block" # rule_group_override_action 
            saml_endpoint_name_bypass  = "avx_controller"
            saml_bypass_rule_label     = "awswaf:managed:aws:core-rule-set:SizeRestrictions_Body" # ref.: https://repost.aws/knowledge-center/waf-http-request-body-inspection
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesKnownBadInputsRuleSet"
            vendor_name                = "AWS"
            priority                   = 20
            rule_override_action       = "none"
            rule_group_override_action = "block"
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesAmazonIpReputationList"
            vendor_name                = "AWS"
            priority                   = 30
            rule_override_action       = "none"
            rule_group_override_action = "block"
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesAnonymousIpList"
            vendor_name                = "AWS"
            priority                   = 40
            rule_override_action       = "none"
            rule_group_override_action = "block"
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesSQLiRuleSet"
            vendor_name                = "AWS"
            priority                   = 50
            rule_override_action       = "none"
            rule_group_override_action = "block"
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesLinuxRuleSet"
            vendor_name                = "AWS"
            priority                   = 60
            rule_override_action       = "none"
            rule_group_override_action = "block"
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesUnixRuleSet"
            vendor_name                = "AWS"
            priority                   = 70
            rule_override_action       = "none"
            rule_group_override_action = "block"
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        }
]
}

variable "delimiter" {
  type        = string
  description = "seperator for aws waf naming"
  default     = "_"
}

variable "visibility_config_cloudwatch_metrics_enabled" {
  type = bool
  description = "Whether the associated resource sends metrics to CloudWatch"
  default     = true
}

variable "visibility_config_sampled_requests_enabled" {
  type = bool
  description = "Whether AWS WAF should store a sampling of the web requests that match the rules"
  default     = true
}

variable "visibility_config_metric_name" {
  type = string
  description = "A friendly name of the CloudWatch metric"
  default     = "aviatrix_controller_waf_logs"
}

variable "alb_waf_name" {
  type = string
  description = "Name of WAF that will be launched"
  default = "aviatrix_controller_waf"
}

variable "alb_arn" {
  type = string
  description = "AWS ALB ARN id for WAF association"
  default = null
}

variable "tags" {
  type = map
  description = "Tags of WAF resource"
  default = {
    Name = "Aviatrix-WAF"
  }
}
