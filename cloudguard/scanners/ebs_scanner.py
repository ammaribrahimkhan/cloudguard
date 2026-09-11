import boto3
import json
import hashlib
from datetime import datetime, timezone

def lambda_handler(event, context):
    ec2 = boto3.client('ec2', region_name='ap-south-1')
    dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
    table = dynamodb.Table('cloudguard-findings')
    account_id = boto3.client('sts').get_caller_identity()['Account']
    region = 'ap-south-1'
    findings = []

    response = ec2.describe_volumes()
    volumes = response['Volumes']

    for volume in volumes:
        volume_id = volume['VolumeId']
        volume_size = volume['Size']
        volume_state = volume['State']
        create_time = volume['CreateTime']
        attachments = volume['Attachments']

        now = datetime.now(timezone.utc)
        age_days = (now - create_time).days

        if volume_state == 'available' and len(attachments) == 0:
            estimated_monthly_cost = round(volume_size * 0.10, 2)

            if age_days > 30:
                risk_score = 75
                severity = 'HIGH'
            elif age_days > 14:
                risk_score = 45
                severity = 'MEDIUM'
            else:
                risk_score = 20
                severity = 'LOW'

            # Generate deterministic finding_id based on resource
            # Same volume always gets same finding_id — no duplicates
            finding_id = 'FIN-EBS-' + hashlib.md5(f"FIN-001-{volume_id}".encode()).hexdigest()[:8].upper()
            timestamp = datetime.now(timezone.utc).isoformat()

            # Check if finding already exists
            existing = table.get_item(
                Key={'finding_id': finding_id, 'timestamp': timestamp}
            )

            # Use query to check by finding_id
            existing_check = table.query(
                KeyConditionExpression=boto3.dynamodb.conditions.Key('finding_id').eq(finding_id),
                Limit=1
            )

            if existing_check['Count'] > 0:
                # Update age and cost but don't create duplicate
                existing_item = existing_check['Items'][0]
                table.update_item(
                    Key={'finding_id': finding_id, 'timestamp': existing_item['timestamp']},
                    UpdateExpression='SET age_days = :a, estimated_monthly_cost_usd = :c, last_seen = :l, severity = :s, risk_score = :r',
                    ExpressionAttributeValues={
                        ':a': age_days,
                        ':c': str(estimated_monthly_cost),
                        ':l': datetime.now(timezone.utc).isoformat(),
                        ':s': severity,
                        ':r': risk_score
                    }
                )
                print(f"Updated existing finding: {finding_id} | Volume: {volume_id}")
            else:
                finding = {
                    'finding_id': finding_id,
                    'timestamp': timestamp,
                    'account_id': account_id,
                    'region': region,
                    'resource_id': volume_id,
                    'resource_type': 'EBS_VOLUME',
                    'rule_id': 'FIN-001',
                    'title': 'Unattached EBS Volume',
                    'description': f'EBS volume {volume_id} has been unattached for {age_days} days. Size: {volume_size}GB.',
                    'severity': severity,
                    'risk_score': risk_score,
                    'estimated_monthly_cost_usd': str(estimated_monthly_cost),
                    'age_days': age_days,
                    'status': 'OPEN',
                    'recommendation': 'Snapshot the volume, verify it is not needed, then delete it to stop incurring charges.',
                    'category': 'FINOPS',
                    'last_seen': datetime.now(timezone.utc).isoformat()
                }
                table.put_item(Item=finding)
                findings.append(finding)
                print(f"New finding: {finding_id} | Volume: {volume_id} | Age: {age_days}d | Cost: ${estimated_monthly_cost}/mo")

    if len(findings) == 0:
        print("No new unattached EBS volumes found.")

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': f'EBS scan complete. {len(findings)} new findings.',
            'findings_count': len(findings)
        }, default=str)
    }