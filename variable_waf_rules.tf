variable "waf_managed_rules" {
    type = list
    default = [
        {
            name                       = "AWSManagedRulesCommonRuleSet"
            vendor_name                = "AWS"
            priority                   = 10
            override_action            = "count"
            excluded_rule              = null
            saml_endpoint_name_bypass  = "avx_controller"
            saml_bypass_rule_label     = "awswaf:managed:aws:core-rule-set:SizeRestrictions_Body" # ref.: https://repost.aws/knowledge-center/waf-http-request-body-inspection
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesKnownBadInputsRuleSet"
            vendor_name                = "AWS"
            priority                   = 20
            override_action            = "count"
            excluded_rule              = null
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesAmazonIpReputationList"
            vendor_name                = "AWS"
            priority                   = 30
            override_action            = "count"
            excluded_rule              = null
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesAnonymousIpList"
            vendor_name                = "AWS"
            priority                   = 40
            override_action            = "count"
            excluded_rule              = null
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesSQLiRuleSet"
            vendor_name                = "AWS"
            priority                   = 50
            override_action            = "count"
            excluded_rule              = null
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesLinuxRuleSet"
            vendor_name                = "AWS"
            priority                   = 60
            override_action            = "count"
            excluded_rule              = null
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        },
        {
            name                       = "AWSManagedRulesUnixRuleSet"
            vendor_name                = "AWS"
            priority                   = 70
            override_action            = "count"
            excluded_rule              = null
            saml_endpoint_name_bypass  = null
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
        }
]
}

variable "waf_ip_set_rules" {
    type = list 
    default = []
} 

variable "waf_geo_match_rules" {
    type = list 
    default = []
}