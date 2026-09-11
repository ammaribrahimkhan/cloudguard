import boto3
import json
import hashlib
from datetime import datetime, timezone

# Buckets to ignore — CloudGuard's own infrastructure
WHITELIST = ['cloudguard-dashboard-104299473009']

def lambda_handler(event, context):
    dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
    table = dynamodb.Table('cloudguard-findings')
    account_id = boto3.client('sts').get_caller_identity()['Account']
    region = 'ap-south-1'
    all_findings = []

    def save_finding(finding):
        finding_id = finding['finding_id']
        existing_check = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('finding_id').eq(finding_id),
            Limit=1
        )
        if existing_check['Count'] > 0:
            existing_item = existing_check['Items'][0]
            table.update_item(
                Key={'finding_id': finding_id, 'timestamp': existing_item['timestamp']},
                UpdateExpression='SET last_seen = :l, #st = :s',
                ExpressionAttributeNames={'#st': 'status'},
                ExpressionAttributeValues={
                    ':l': datetime.now(timezone.utc).isoformat(),
                    ':s': existing_item.get('status', 'OPEN')
                }
            )
            print(f"Already exists, updated last_seen: {finding_id}")
            return False
        else:
            table.put_item(Item=finding)
            print(f"New finding saved: {finding_id}")
            return True

    def make_id(rule_id, resource_id):
        return rule_id + '-' + hashlib.md5(f"{rule_id}-{resource_id}".encode()).hexdigest()[:8].upper()

    # ─────────────────────────────────────────
    # SEC-001: S3 Public Access Not Blocked
    # ─────────────────────────────────────────
    s3 = boto3.client('s3')
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            bucket_name = bucket['Name']
            if bucket_name in WHITELIST:
                print(f"Skipping whitelisted bucket: {bucket_name}")
                continue
            try:
                public_access = s3.get_public_access_block(Bucket=bucket_name)
                config = public_access['PublicAccessBlockConfiguration']
                all_blocked = (
                    config.get('BlockPublicAcls', False) and
                    config.get('IgnorePublicAcls', False) and
                    config.get('BlockPublicPolicy', False) and
                    config.get('RestrictPublicBuckets', False)
                )
                if not all_blocked:
                    finding_id = make_id('SEC-S3', bucket_name)
                    f = {
                        'finding_id': finding_id,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'account_id': account_id,
                        'region': 'global',
                        'resource_id': bucket_name,
                        'resource_type': 'S3_BUCKET',
                        'rule_id': 'SEC-001',
                        'title': 'S3 Bucket Public Access Not Fully Blocked',
                        'description': f'S3 bucket {bucket_name} does not have all public access block settings enabled.',
                        'severity': 'HIGH',
                        'risk_score': 85,
                        'status': 'OPEN',
                        'recommendation': 'Enable all four public access block settings on this bucket immediately.',
                        'category': 'SECURITY',
                        'last_seen': datetime.now(timezone.utc).isoformat()
                    }
                    if save_finding(f):
                        all_findings.append(f)
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                finding_id = make_id('SEC-S3-NOBLOCK', bucket_name)
                f = {
                    'finding_id': finding_id,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'account_id': account_id,
                    'region': 'global',
                    'resource_id': bucket_name,
                    'resource_type': 'S3_BUCKET',
                    'rule_id': 'SEC-001',
                    'title': 'S3 Bucket Has No Public Access Block Configuration',
                    'description': f'S3 bucket {bucket_name} has no public access block configuration at all.',
                    'severity': 'CRITICAL',
                    'risk_score': 95,
                    'status': 'OPEN',
                    'recommendation': 'Immediately enable all public access block settings on this bucket.',
                    'category': 'SECURITY',
                    'last_seen': datetime.now(timezone.utc).isoformat()
                }
                if save_finding(f):
                    all_findings.append(f)
            except Exception as e:
                print(f"Could not check bucket {bucket_name}: {str(e)}")
    except Exception as e:
        print(f"S3 scan error: {str(e)}")

    # ─────────────────────────────────────────
    # SEC-002: Open SSH
    # ─────────────────────────────────────────
    try:
        ec2 = boto3.client('ec2', region_name='ap-south-1')
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                ip_ranges = rule.get('IpRanges', [])
                ipv6_ranges = rule.get('Ipv6Ranges', [])
                is_ssh = (from_port <= 22 <= to_port)
                open_all = any(r.get('CidrIp') == '0.0.0.0/0' for r in ip_ranges)
                open_v6 = any(r.get('CidrIpv6') == '::/0' for r in ipv6_ranges)
                if is_ssh and (open_all or open_v6):
                    finding_id = make_id('SEC-SSH', sg_id)
                    f = {
                        'finding_id': finding_id,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'account_id': account_id,
                        'region': region,
                        'resource_id': sg_id,
                        'resource_type': 'SECURITY_GROUP',
                        'rule_id': 'SEC-002',
                        'title': 'SSH Port Open to Internet',
                        'description': f'Security group {sg_id} ({sg_name}) allows inbound SSH (port 22) from 0.0.0.0/0.',
                        'severity': 'CRITICAL',
                        'risk_score': 92,
                        'status': 'OPEN',
                        'recommendation': 'Restrict SSH access to specific trusted IP addresses only.',
                        'category': 'SECURITY',
                        'last_seen': datetime.now(timezone.utc).isoformat()
                    }
                    if save_finding(f):
                        all_findings.append(f)
    except Exception as e:
        print(f"SG scan error: {str(e)}")

    # ─────────────────────────────────────────
    # SEC-003: Open RDP
    # ─────────────────────────────────────────
    try:
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                ip_ranges = rule.get('IpRanges', [])
                ipv6_ranges = rule.get('Ipv6Ranges', [])
                is_rdp = (from_port <= 3389 <= to_port)
                open_all = any(r.get('CidrIp') == '0.0.0.0/0' for r in ip_ranges)
                open_v6 = any(r.get('CidrIpv6') == '::/0' for r in ipv6_ranges)
                if is_rdp and (open_all or open_v6):
                    finding_id = make_id('SEC-RDP', sg_id)
                    f = {
                        'finding_id': finding_id,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'account_id': account_id,
                        'region': region,
                        'resource_id': sg_id,
                        'resource_type': 'SECURITY_GROUP',
                        'rule_id': 'SEC-003',
                        'title': 'RDP Port Open to Internet',
                        'description': f'Security group {sg_id} ({sg_name}) allows inbound RDP (port 3389) from 0.0.0.0/0.',
                        'severity': 'CRITICAL',
                        'risk_score': 92,
                        'status': 'OPEN',
                        'recommendation': 'Restrict RDP access to specific trusted IP addresses only.',
                        'category': 'SECURITY',
                        'last_seen': datetime.now(timezone.utc).isoformat()
                    }
                    if save_finding(f):
                        all_findings.append(f)
    except Exception as e:
        print(f"RDP scan error: {str(e)}")

    # ─────────────────────────────────────────
    # SEC-004: IAM Users Without MFA
    # ─────────────────────────────────────────
    try:
        iam = boto3.client('iam')
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
            if len(mfa_devices) == 0:
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False
                if has_console:
                    finding_id = make_id('SEC-MFA', username)
                    f = {
                        'finding_id': finding_id,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'account_id': account_id,
                        'region': 'global',
                        'resource_id': username,
                        'resource_type': 'IAM_USER',
                        'rule_id': 'SEC-004',
                        'title': 'IAM User Has Console Access Without MFA',
                        'description': f'IAM user {username} has AWS Console access but no MFA device configured.',
                        'severity': 'HIGH',
                        'risk_score': 80,
                        'status': 'OPEN',
                        'recommendation': 'Enable MFA immediately for all IAM users with console access.',
                        'category': 'SECURITY',
                        'last_seen': datetime.now(timezone.utc).isoformat()
                    }
                    if save_finding(f):
                        all_findings.append(f)
    except Exception as e:
        print(f"IAM MFA scan error: {str(e)}")

    # ─────────────────────────────────────────
    # SEC-005: Old Access Keys (90+ days)
    # ─────────────────────────────────────────
    try:
        for user in users:
            username = user['UserName']
            access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in access_keys:
                if key['Status'] == 'Active':
                    key_age = (datetime.now(timezone.utc) - key['CreateDate']).days
                    if key_age > 90:
                        finding_id = make_id('SEC-KEY', f"{username}-{key['AccessKeyId']}")
                        f = {
                            'finding_id': finding_id,
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'account_id': account_id,
                            'region': 'global',
                            'resource_id': username,
                            'resource_type': 'IAM_ACCESS_KEY',
                            'rule_id': 'SEC-005',
                            'title': 'IAM Access Key Not Rotated in 90+ Days',
                            'description': f'IAM user {username} has an active access key that is {key_age} days old.',
                            'severity': 'MEDIUM',
                            'risk_score': 60,
                            'status': 'OPEN',
                            'recommendation': 'Rotate access keys every 90 days.',
                            'category': 'SECURITY',
                            'last_seen': datetime.now(timezone.utc).isoformat()
                        }
                        if save_finding(f):
                            all_findings.append(f)
    except Exception as e:
        print(f"IAM key scan error: {str(e)}")

    print(f"Security scan complete. {len(all_findings)} new findings.")
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': f'Security scan complete. {len(all_findings)} new findings.',
            'findings_count': len(all_findings)
        }, default=str)
    }