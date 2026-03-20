import boto3
import time
import json
import os

# Initialize clients
target_region = os.environ.get('TARGET_REGION', os.environ['AWS_REGION'])
print(f"DEBUG: Initializing clients for region: {target_region}")

ec2 = boto3.client('ec2', region_name=target_region)
dynamodb = boto3.resource('dynamodb', region_name=target_region)
sns = boto3.client('sns', region_name=target_region) # Added SNS Client
table = dynamodb.Table('SentinelAuditLog')

def lambda_handler(event, context):
    print(f"DEBUG: Lambda started. Full Event: {json.dumps(event)}")

    status = "UNKNOWN"
    message = ""
    group_id = "UNKNOWN_SG"

    try:
        # 1. Parse Input
        if 'resource_id' in event:
            group_id = event['resource_id']
        else:
            group_id = event.get('detail', {}).get('resourceId', "UNKNOWN_SG")
        
        print(f"Targeting Security Group: {group_id}")

        if group_id == "UNKNOWN_SG":
            raise ValueError("Could not find Security Group ID in event input.")

        # 2. DESCRIBE to inspect rules
        response = ec2.describe_security_groups(GroupIds=[group_id])
        ip_permissions = response['SecurityGroups'][0]['IpPermissions']
        
        revoke_list = []
        
        for permission in ip_permissions:
            from_port = permission.get('FromPort', -1)
            to_port = permission.get('ToPort', -1)
            ip_protocol = permission.get('IpProtocol', '-1')
            
            # Check for SSH (22)
            is_ssh = False
            if ip_protocol == '-1': 
                is_ssh = True
            elif from_port <= 22 and to_port >= 22:
                is_ssh = True
            elif from_port == 22:
                is_ssh = True
                
            if is_ssh:
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', 'N/A')
                    if cidr == '0.0.0.0/0':
                        print(" -> MATCH! This is an open rule.")
                        revoke_list.append({
                            'IpProtocol': ip_protocol,
                            'FromPort': from_port,
                            'ToPort': to_port,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        })

        # 3. Revoke
        if len(revoke_list) > 0:
            ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=revoke_list)
            status = "SUCCESS"
            message = f"Revoked {len(revoke_list)} insecure rules (Port 22 open to world)."
        else:
            status = "SKIPPED"
            message = f"No '0.0.0.0/0' SSH rules found in {target_region}."

    except Exception as e:
        status = "FAILED"
        message = f"Error: {str(e)}"
        print(message)

    # 4. Log to DynamoDB
    try:
        table.put_item(
            Item={
                'ResourceId': group_id,
                'Timestamp': str(time.time()),
                'Action': 'RevokeSecurityGroupIngress',
                'Status': status,
                'Message': message,
                'Region': target_region
            }
        )
    except Exception as e:
        print(f"CRITICAL: Failed to write to DB. Error: {str(e)}")

    # 5. Send SNS Notification (NEW)
    try:
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        if sns_topic_arn and status == 'SUCCESS':
            sns.publish(
                TopicArn=sns_topic_arn,
                Subject=f"Sentinel Alert: Remediated Network Risk ({group_id})",
                Message=f"Security Group Violation Detected!\n\nResource: {group_id}\nAction: {message}\nRegion: {target_region}\nStatus: REMEDIATED"
            )
            print("SNS Notification sent.")
    except Exception as e:
        print(f"Failed to send SNS: {str(e)}")
    
    return {"status": status, "resource": group_id, "message": message}