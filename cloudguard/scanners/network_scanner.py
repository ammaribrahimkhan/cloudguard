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
    all_findings = []

    def make_id(rule, resource):
        return rule + '-' + hashlib.md5(f"{rule}-{resource}".encode()).hexdigest()[:8].upper()

    def save_finding(f):
        fid = f['finding_id']
        existing = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('finding_id').eq(fid),
            Limit=1
        )
        if existing['Count'] > 0:
            item = existing['Items'][0]
            table.update_item(
                Key={'finding_id': fid, 'timestamp': item['timestamp']},
                UpdateExpression='SET last_seen = :l',
                ExpressionAttributeValues={':l': datetime.now(timezone.utc).isoformat()}
            )
            print(f"Already exists: {fid}")
            return False
        table.put_item(Item=f)
        print(f"New finding: {fid}")
        return True

    # ─────────────────────────────────────────
    # NET-001: Unassociated Elastic IPs
    # Each EIP costs ~$3.60/month when not attached
    # ─────────────────────────────────────────
    try:
        addresses = ec2.describe_addresses()['Addresses']
        for addr in addresses:
            if 'AssociationId' not in addr:
                alloc_id = addr.get('AllocationId', addr.get('PublicIp'))
                public_ip = addr.get('PublicIp', 'Unknown')
                finding_id = make_id('NET-EIP', alloc_id)
                f = {
                    'finding_id': finding_id,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'account_id': account_id,
                    'region': region,
                    'resource_id': public_ip,
                    'resource_type': 'ELASTIC_IP',
                    'rule_id': 'NET-001',
                    'title': 'Unassociated Elastic IP Address',
                    'description': f'Elastic IP {public_ip} is allocated but not associated with any running instance. AWS charges approximately $3.60/month for unattached Elastic IPs.',
                    'severity': 'LOW',
                    'risk_score': 30,
                    'estimated_monthly_cost_usd': '3.60',
                    'status': 'OPEN',
                    'recommendation': 'Release this Elastic IP if it is not needed. Go to EC2 → Elastic IPs → select the IP → Actions → Release Elastic IP address.',
                    'category': 'FINOPS',
                    'last_seen': datetime.now(timezone.utc).isoformat()
                }
                if save_finding(f):
                    all_findings.append(f)
    except Exception as e:
        print(f"EIP scan error: {str(e)}")

    # ─────────────────────────────────────────
    # NET-002: Default VPC Security Group Open
    # Default SGs that allow all traffic are risky
    # ─────────────────────────────────────────
    try:
        sgs = ec2.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': ['default']}]
        )['SecurityGroups']
        for sg in sgs:
            sg_id = sg['GroupId']
            vpc_id = sg.get('VpcId', 'unknown')
            has_open_ingress = any(
                not rule.get('IpRanges') and not rule.get('Ipv6Ranges') and not rule.get('UserIdGroupPairs')
                or any(r.get('CidrIp') == '0.0.0.0/0' for r in rule.get('IpRanges', []))
                for rule in sg.get('IpPermissions', [])
            )
            if sg.get('IpPermissions'):
                finding_id = make_id('NET-DEFSG', sg_id)
                f = {
                    'finding_id': finding_id,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'account_id': account_id,
                    'region': region,
                    'resource_id': sg_id,
                    'resource_type': 'SECURITY_GROUP',
                    'rule_id': 'NET-002',
                    'title': 'Default VPC Security Group Has Inbound Rules',
                    'description': f'The default security group in VPC {vpc_id} has inbound rules configured. AWS best practice is to keep default security groups with no rules and use custom security groups instead.',
                    'severity': 'MEDIUM',
                    'risk_score': 55,
                    'status': 'OPEN',
                    'recommendation': 'Remove all inbound and outbound rules from the default security group. Create purpose-specific security groups for your resources instead.',
                    'category': 'SECURITY',
                    'last_seen': datetime.now(timezone.utc).isoformat()
                }
                if save_finding(f):
                    all_findings.append(f)
    except Exception as e:
        print(f"Default SG scan error: {str(e)}")

    # ─────────────────────────────────────────
    # NET-003: EC2 Instances with Public IPs
    # ─────────────────────────────────────────
    try:
        instances = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                public_ip = instance.get('PublicIpAddress')
                if public_ip:
                    name = ''
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            name = tag['Value']
                    finding_id = make_id('NET-PUBIP', instance_id)
                    f = {
                        'finding_id': finding_id,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'account_id': account_id,
                        'region': region,
                        'resource_id': instance_id,
                        'resource_type': 'EC2_INSTANCE',
                        'rule_id': 'NET-003',
                        'title': 'EC2 Instance Has Public IP Address',
                        'description': f'EC2 instance {instance_id} ({name}) has a public IP address {public_ip}. Instances should ideally sit behind a load balancer or in a private subnet.',
                        'severity': 'LOW',
                        'risk_score': 35,
                        'status': 'OPEN',
                        'recommendation': 'Move this instance to a private subnet and access it through a load balancer or VPN. If a public IP is required, ensure security groups are strictly configured.',
                        'category': 'SECURITY',
                        'last_seen': datetime.now(timezone.utc).isoformat()
                    }
                    if save_finding(f):
                        all_findings.append(f)
    except Exception as e:
        print(f"Public IP scan error: {str(e)}")

    print(f"Network scan complete. {len(all_findings)} new findings.")
    return {
        'statusCode': 200,
        'body': json.dumps({'findings_count': len(all_findings)}, default=str)
    }