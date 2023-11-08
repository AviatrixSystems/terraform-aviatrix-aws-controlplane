output waf_id {
  value       = concat(aws_wafv2_web_acl.waf_acl.*.id, [""])[0]
  description = "The ID of the WAF WebACL."
}

output waf_arn {
  value       = concat(aws_wafv2_web_acl.waf_acl.*.arn, [""])[0]
  description = "The ARN of the WAF WebACL"
}
