import boto3
import os
import time

# Region setup
target_region = os.environ.get('TARGET_REGION', os.environ['AWS_REGION'])
rds = boto3.client('rds', region_name=target_region)
dynamodb = boto3.resource('dynamodb', region_name=target_region)
sns = boto3.client('sns', region_name=target_region) # Added SNS Client
table = dynamodb.Table('SentinelAuditLog')

def lambda_handler(event, context):
    resource_id = event.get('resource_id')
    if not resource_id and 'detail' in event:
        resource_id = event['detail'].get('resourceId')

    print(f"Received Resource ID: {resource_id} in region {target_region}")

    db_identifier = None
    status = "FAILED"
    message = ""

    try:
        # Find DB Identifier from Resource ID
        response = rds.describe_db_instances()
        for db in response['DBInstances']:
            if db['DbiResourceId'] == resource_id:
                db_identifier = db['DBInstanceIdentifier']
                break
        
        if not db_identifier:
            db_identifier = resource_id # Fallback

        # Modify DB
        rds.modify_db_instance(
            DBInstanceIdentifier=db_identifier,
            PubliclyAccessible=False,
            ApplyImmediately=True
        )
        
        status = "SUCCESS"
        message = f"Removed Public Access from RDS Instance: {db_identifier}"
        print(message)

    except Exception as e:
        message = f"Error: {str(e)}"
        print(message)

    # Log to DynamoDB
    try:
        table.put_item(
            Item={
                'ResourceId': str(resource_id),
                'Timestamp': str(time.time()),
                'Action': 'DisablePublicAccess',
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
                Subject=f"Sentinel Alert: Remediated Database Risk ({db_identifier})",
                Message=f"Database Violation Detected!\n\nResource: {db_identifier}\nAction: Public Access Disabled\nRegion: {target_region}\nStatus: REMEDIATED"
            )
    except Exception as e:
        print(f"Failed to send SNS: {str(e)}")

    return {"status": status, "message": message}