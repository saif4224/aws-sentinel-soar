output "step_function_arn" {
  description = "ARN of the Sentinel Orchestrator Step Function"
  value       = aws_sfn_state_machine.sentinel_orchestrator.arn
}

output "audit_table_name" {
  description = "Name of the DynamoDB Audit Table"
  value       = aws_dynamodb_table.audit_log.name
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge Rule trigger"
  value       = aws_cloudwatch_event_rule.config_compliance.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS Topic for Alerts (Subscribe your email here)"
  value       = aws_sns_topic.security_alerts.arn
}