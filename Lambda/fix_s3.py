import boto3
import json
import time
import os

# Initialize clients
target_region = os.environ.get('TARGET_REGION', os.environ['AWS_REGION'])
s3_client = boto3.client('s3', region_name=target_region)
dynamodb = boto3.resource('dynamodb', region_name=target_region)
sns = boto3.client('sns', region_name=target_region) # Added SNS Client
table = dynamodb.Table('SentinelAuditLog')

def lambda_handler(event, context):
    bucket_name = event['resource_id']
    rule_name = event.get('rule_name', 'UNKNOWN')
    
    print(f"Starting remediation for Bucket: {bucket_name} | Violation: {rule_name}")
    
    status = "UNKNOWN"
    message = ""
    action_taken = ""

    try:
        # --- LOGIC BRANCHING ---
        
        # CASE 1: Versioning Disabled (Ransomware Risk)
        if rule_name == 's3-bucket-versioning-enabled':
            action_taken = "EnableVersioning"
            s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            message = f"Enabled Versioning on {bucket_name}"

        # CASE 2: Public Access Allowed (Leak Risk)
        elif rule_name == 's3-bucket-level-public-access-prohibited':
            action_taken = "BlockPublicAccess"
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            message = f"Enabled 'Block All Public Access' on {bucket_name}"

        else:
            action_taken = "NoAction"
            message = f"Rule '{rule_name}' not recognized by auto-remediation."
            status = "SKIPPED"

        if status == "UNKNOWN": status = "SUCCESS"

    except Exception as e:
        status = "FAILED"
        message = str(e)
        print(f"Error: {message}")

    # --- AUDIT LOGGING ---
    try:
        table.put_item(
            Item={
                'ResourceId': bucket_name,
                'Timestamp': str(time.time()),
                'Action': action_taken,
                'Status': status,
                'Message': message,
                'Region': target_region,
                'TriggeredRule': rule_name
            }
        )
    except Exception as e:
        print(f"Db Error: {str(e)}")

    # --- SNS NOTIFICATION (NEW) ---
    try:
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        if sns_topic_arn and status == 'SUCCESS':
            sns.publish(
                TopicArn=sns_topic_arn,
                Subject=f"Sentinel Alert: Remediated S3 Risk ({bucket_name})",
                Message=f"Storage Violation Detected!\n\nResource: {bucket_name}\nViolation: {rule_name}\nAction: {message}\nRegion: {target_region}\nStatus: REMEDIATED"
            )
            print("SNS Notification sent.")
    except Exception as e:
        print(f"Failed to send SNS: {str(e)}")

    return {"status": status, "resource": bucket_name, "message": message}