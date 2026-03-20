provider "aws" {
  region = "us-east-1"
}

# DynamoDB table for immutable audit logging of remediation actions
resource "aws_dynamodb_table" "audit_log" {
  name           = "SentinelAuditLog"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "ResourceId"
  range_key      = "Timestamp"

  attribute {
    name = "ResourceId"
    type = "S"
  }

  attribute {
    name = "Timestamp"
    type = "S"
  }

  tags = {
    Project = "Sentinel-SOAR"
    Environment = "Production"
  }
}

# SNS Topic for real-time security alerts (Email/Slack/SMS)
resource "aws_sns_topic" "security_alerts" {
  name = "Sentinel-Security-Alerts"
}

# Orchestration logic for routing Config findings to specific remediation functions
resource "aws_sfn_state_machine" "sentinel_orchestrator" {
  name     = "Sentinel-Orchestrator"
  role_arn = aws_iam_role.step_functions_role.arn

  # Workflow definition: Detect threat type -> Route to handler -> Log result
  definition = <<EOF
{
  "Comment": "Sentinel SOAR Enterprise Logic",
  "StartAt": "DetermineThreatType",
  "States": {
    "DetermineThreatType": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.detail.configRuleName",
          "StringMatches": "s3-*",
          "Next": "RemediateS3"
        },
        {
          "Variable": "$.detail.configRuleName",
          "StringEquals": "restricted-ssh",
          "Next": "RemediateSecurityGroup"
        },
        {
          "Variable": "$.detail.configRuleName",
          "StringEquals": "rds-instance-public-access-check",
          "Next": "RemediateRDS"
        },
        {
          "Variable": "$.detail.configRuleName",
          "StringEquals": "ec2-ebs-encryption-by-default",
          "Next": "RemediateEBS"
        }
      ],
      "Default": "ManualReview"
    },
    "RemediateS3": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.fix_s3.arn}",
      "Parameters": {
        "resource_id.$": "$.detail.resourceId",
        "rule_name.$": "$.detail.configRuleName"
      },
      "End": true
    },
    "RemediateSecurityGroup": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.fix_sg.arn}",
      "Parameters": {
        "resource_id.$": "$.detail.resourceId"
      },
      "End": true
    },
    "RemediateRDS": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.fix_rds.arn}",
      "Parameters": {
        "resource_id.$": "$.detail.resourceId"
      },
      "End": true
    },
    "RemediateEBS": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.fix_ebs.arn}",
      "Parameters": {
        "resource_id.$": "$.detail.resourceId"
      },
      "End": true
    },
    "ManualReview": {
      "Type": "Pass",
      "End": true
    }
  }
}
EOF
}

# EventBridge rule to capture specific NON_COMPLIANT config changes
resource "aws_cloudwatch_event_rule" "config_compliance" {
  name        = "Sentinel-Auto-Remediate"
  description = "Triggers remediation workflow when compliance rules fail"

  event_pattern = jsonencode({
    source      = ["aws.config"],
    detail-type = ["Config Rules Compliance Change"],
    detail = {
      messageType = ["ComplianceChangeNotification"],
      configRuleName = [
        "s3-bucket-versioning-enabled",
        "s3-bucket-level-public-access-prohibited",
        "restricted-ssh",
        "rds-instance-public-access-check",
        "ec2-ebs-encryption-by-default"
      ],
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "step_function_target" {
  rule      = aws_cloudwatch_event_rule.config_compliance.name
  target_id = "SendToStepFunctions"
  arn       = aws_sfn_state_machine.sentinel_orchestrator.arn
  role_arn  = aws_iam_role.eventbridge_role.arn
}