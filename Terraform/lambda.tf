# Package Python source code for Lambda deployment
data "archive_file" "zip_sg" {
  type        = "zip"
  source_file = "../lambda/fix_sg_v3.py"
  output_path = "fix_sg.zip"
}

data "archive_file" "zip_s3" {
  type        = "zip"
  source_file = "../lambda/fix_s3_v4.py"
  output_path = "fix_s3.zip"
}

data "archive_file" "zip_rds" {
  type        = "zip"
  source_file = "../lambda/fix_rds_v2.py"
  output_path = "fix_rds.zip"
}

data "archive_file" "zip_ebs" {
  type        = "zip"
  source_file = "../lambda/fix_ebs.py"
  output_path = "fix_ebs.zip"
}

# Remediation function for Network Security Groups
resource "aws_lambda_function" "fix_sg" {
  function_name    = "Sentinel-Fix-SecurityGroup"
  filename         = data.archive_file.zip_sg.output_path
  source_code_hash = data.archive_file.zip_sg.output_base64sha256
  role             = aws_iam_role.lambda_remediation_role.arn
  handler          = "fix_sg_v3.lambda_handler"
  runtime          = "python3.9"
  timeout          = 10

  environment {
    variables = {
      TARGET_REGION = "us-east-1"
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }
}

# Remediation function for S3 compliance (Encryption, Versioning, Public Access)
resource "aws_lambda_function" "fix_s3" {
  function_name    = "Sentinel-Fix-S3"
  filename         = data.archive_file.zip_s3.output_path
  source_code_hash = data.archive_file.zip_s3.output_base64sha256
  role             = aws_iam_role.lambda_remediation_role.arn
  handler          = "fix_s3_v4.lambda_handler"
  runtime          = "python3.9"
  timeout          = 10

  environment {
    variables = {
      TARGET_REGION = "us-east-1"
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }
}

# Remediation function for RDS Public Access
resource "aws_lambda_function" "fix_rds" {
  function_name    = "Sentinel-Fix-RDS"
  filename         = data.archive_file.zip_rds.output_path
  source_code_hash = data.archive_file.zip_rds.output_base64sha256
  role             = aws_iam_role.lambda_remediation_role.arn
  handler          = "fix_rds_v2.lambda_handler"
  runtime          = "python3.9"
  # Increased timeout to accommodate RDS API response latency
  timeout          = 60 

  environment {
    variables = {
      TARGET_REGION = "us-east-1"
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }
}

# Remediation function for Account-level EBS Encryption
resource "aws_lambda_function" "fix_ebs" {
  function_name    = "Sentinel-Fix-EBS"
  filename         = data.archive_file.zip_ebs.output_path
  source_code_hash = data.archive_file.zip_ebs.output_base64sha256
  role             = aws_iam_role.lambda_remediation_role.arn
  handler          = "fix_ebs.lambda_handler"
  runtime          = "python3.9"
  timeout          = 10

  environment {
    variables = {
      TARGET_REGION = "us-east-1"
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }
}