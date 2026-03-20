import boto3
import time
import os

# Initialize clients
target_region = os.environ.get('TARGET_REGION', os.environ['AWS_REGION'])
ec2 = boto3.client('ec2', region_name=target_region)
dynamodb = boto3.resource('dynamodb', region_name=target_region)
sns = boto3.client('sns', region_name=target_region) # Added SNS Client
table = dynamodb.Table('SentinelAuditLog')

def lambda_handler(event, context):
    print(f"Checking EBS Encryption settings in {target_region}...")
    
    status = "UNKNOWN"
    message = ""

    try:
        # Enable EBS Encryption by Default
        ec2.enable_ebs_encryption_by_default()
        
        status = "SUCCESS"
        message = f"Enabled EBS Encryption by Default in region {target_region}."
        print(message)

    except Exception as e:
        status = "FAILED"
        message = str(e)
        print(f"Error: {message}")

    # Log to DynamoDB
    try:
        resource_id = f"Account-Settings-{target_region}"
        table.put_item(
            Item={
                'ResourceId': resource_id,
                'Timestamp': str(time.time()),
                'Action': 'EnableEBSEncryption',
                'Status': status,
                'Message': message,
                'Region': target_region
            }
        )
    except Exception as e:
        print(f"Db Error: {str(e)}")

    # Send SNS (NEW)
    try:
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        if sns_topic_arn and status == 'SUCCESS':
            sns.publish(
                TopicArn=sns_topic_arn,
                Subject="Sentinel Alert: Remediated Account Compliance (EBS)",
                Message=f"Compliance Violation Detected!\n\nAction: Enabled EBS Encryption by Default\nRegion: {target_region}\nStatus: REMEDIATED"
            )
    except Exception as e:
        print(f"Failed to send SNS: {str(e)}")

    return {"status": status, "message": message}