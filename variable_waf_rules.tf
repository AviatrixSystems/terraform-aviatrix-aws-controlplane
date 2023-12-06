variable "configure_waf" {
  type = bool
  description = "Whether WAF is enabled for the controller"
  default = false
}

variable "waf_managed_rules" {
    type = list
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
            rule_group_override_action = "challenge"
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

variable "waf_ip_set_rules" {
    type = list
    default = [
        # {
        #     name = "ipser1"
        #     priority = 0
        #     action = "allow"
        #     ip_address_version = "IPV4"
        #     addresses = ["x.x.x.x./32"] 
        #     forwarded_ip_config = {
        #         fallback_behavior = "MATCH"
        #         header_name = "Header"
        #     }
        #     cloudwatch_metrics_enabled = true
        #     sampled_requests_enabled = true
        # }
    ]
} 

variable "waf_geo_match_rules" {
    type = list 
    default = [
        # {
        #     country_codes = ["US"]
        #     priority = 1
        #     action = "block"
        #     forwarded_ip_config = {
        #         fallback_behavior = "MATCH"
        #         header_name = "Header"
        #     }
        #     cloudwatch_metrics_enabled = true
        #     sampled_requests_enabled = true
        # }
    ]
}