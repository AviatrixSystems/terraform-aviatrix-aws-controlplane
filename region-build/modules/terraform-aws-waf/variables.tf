variable "configure_waf" {
  type = bool
  description = "Weather WAF is enabled for the controller"
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

variable "managed_rules" {
  type        = list(any)
  default     = []
  description = <<EOF
  A rule statement used to run the rules that are defined in a managed rule group. A list of maps with the following syntax:

  managed_rules = [
    {
      name                       = "AWSManagedRulesCommonRuleSet"    (string)                                                       (Required) The name of the managed rule group
      vendor_name                = "AWS"                             (string)                                                       (Required) The name of the managed rule group vendor
      priority                   = 0                                 (number)                                                       (Required) If you define more than one Rule in a WebACL, AWS WAF evaluates each request against the rules in order based on the value of priority. AWS WAF processes rules with lower priority first
      override_action            = "none"                            (string, "none" or "count",                defaults to none)   (Optional) The override_action block supports the following arguments: count - Override the rule action setting to count (i.e., only count matches). none - Don't override the rule action setting
      excluded_rule              = "first_rule second_rule"          (string, list of space seperated values    defaults to null)   (Optional) The names of the rule to exclude whose actions are set to COUNT by the web ACL, regardless of the action that is set on the rule. If the rule group is managed by AWS, see the documentation for a list of names in the appropriate rule group in use. https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
      cloudwatch_metrics_enabled = true                              (bool,   true or false,                    defaults to true)   (Optional) A boolean indicating whether the associated resource sends metrics to CloudWatch
      sampled_requests_enabled   = true                              (bool,   true or false,                    defaults to true)   (Optional) A boolean indicating whether AWS WAF should store a sampling of the web requests that match the rules
    }
  ]
EOF
}

variable "ip_set_rules" {
  type        = list(any)
  default     = []
  description = <<EOF
  A rule statement used to detect web requests coming from particular IP addresses or address ranges. A list of maps with the following syntax:

  ip_set_rules = [
    {
      name = "default-endpoints"                (string)
      priority = 0                              (number)                                                   (Required) If you define more than one Rule in a WebACL, AWS WAF evaluates each request against the rules in order based on the value of priority. AWS WAF processes rules with lower priority first
      action = "count"                          (string, "count", "allow" or "block", defaults to count)   (Optional) The action block supports the following arguments: allow - Instructs AWS WAF to allow the web request. block - Instructs AWS WAF to block the web request. count - Instructs AWS WAF to count the web request and allow it
      ip_address_version = "IPV4"               (string, "IPV4" or "IPV6",            defaults to count)   (Required) Specify IPV4 or IPV6
      addresses = ["0.0.0.0/0"]                 (list(string))                                             (Required) Contains an array of strings that specify one or more IP addresses or blocks of IP addresses in Classless Inter-Domain Routing (CIDR) notation. AWS WAF supports all address ranges for IP versions IPv4 and IPv6.
      ip_set_forwarded_ip_config = {                                                                       (Optional) The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin
        fallback_behavior = "MATCH"             (string, "MATCH" or "NO_MATCH",       defaults to null)    (Optional) The match status to assign to the web request if the request doesn't have a valid IP address in the specified position
        header_name       = "Header"            (string,                              defaults to null)    (Optional) The name of the HTTP header to use for the IP address
        position          = "FIRST"             (string, "FIRST" or "LAST" or "ANY",  defaults to null)    (Optional) The position in the header to search for the IP address. If ANY is specified and the header contains more than 10 IP addresses, AWS WAFv2 inspects the last 10
      }
      cloudwatch_metrics_enabled = true         (bool,   true or false,               defaults to true)    (Optional) A boolean indicating whether the associated resource sends metrics to CloudWatch
      sampled_requests_enabled   = true         (bool,   true or false,               defaults to true)    (Optional) A boolean indicating whether AWS WAF should store a sampling of the web requests that match the rules
    }
  ]
EOF
}

variable "geo_match_rules" {
  type        = list(any)
  default     = []
  description = <<EOF
  A rule statement used to identify web requests based on country of origin. A list of maps with the following syntax:

  ip_set_rules = [
    {
      country_codes = ["RU","CN"]               (list(string))                                             (Required) An array of two-character country codes, for example, [ "US", "CN" ], from the alpha-2 country ISO codes of the ISO 3166 international standard. See the documentation for valid values. https://docs.aws.amazon.com/waf/latest/APIReference/API_GeoMatchStatement.html
      priority = 0                              (number)                                                   (Required) If you define more than one Rule in a WebACL, AWS WAF evaluates each request against the rules in order based on the value of priority. AWS WAF processes rules with lower priority first
      action = "count"                          (string, "count", "allow" or "block", defaults to count)   (Optional) The action block supports the following arguments: allow - Instructs AWS WAF to allow the web request. block - Instructs AWS WAF to block the web request. count - Instructs AWS WAF to count the web request and allow it
      forwarded_ip_config = {                                                                              (Optional) The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name. If the specified header isn't present in the request, AWS WAFv2 doesn't apply the rule to the web request at all. AWS WAFv2 only evaluates the first IP address found in the specified HTTP header
        fallback_behavior = "MATCH"             (string, "MATCH" or "NO_MATCH",       defaults to null)    (Optional) The match status to assign to the web request if the request doesn't have a valid IP address in the specified position
        header_name       = "Header"            (string,                              defaults to null)    (Optional) The name of the HTTP header to use for the IP address
      }
      cloudwatch_metrics_enabled = true         (bool,   true or false,               defaults to true)    (Optional) A boolean indicating whether the associated resource sends metrics to CloudWatch
      sampled_requests_enabled   = true         (bool,   true or false,               defaults to true)    (Optional) A boolean indicating whether AWS WAF should store a sampling of the web requests that match the rules
    }
  ]
EOF
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
