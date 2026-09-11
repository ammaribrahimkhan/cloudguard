import boto3
import json
import time
from datetime import datetime, timezone
from decimal import Decimal

def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

def wait_for_snapshot(ec2, snapshot_id, max_wait_seconds=240):
    print(f"Waiting for snapshot {snapshot_id} to complete...")
    waited = 0
    while waited < max_wait_seconds:
        resp = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
        state = resp['Snapshots'][0]['State']
        progress = resp['Snapshots'][0].get('Progress', '0%')
        print(f"Snapshot state: {state} | Progress: {progress}")
        if state == 'completed':
            return True
        if state == 'error':
            return False
        time.sleep(15)
        waited += 15
    return False

def lambda_handler(event, context):
    dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
    table = dynamodb.Table('cloudguard-findings')
    ec2 = boto3.client('ec2', region_name='ap-south-1')

    results = {
        'auto_deleted': [],
        'snapshot_only': [],
        'flagged_for_approval': [],
        'skipped': []
    }

    response = table.scan(
        FilterExpression=boto3.dynamodb.conditions.Attr('status').eq('OPEN')
    )
    findings = response['Items']
    while 'LastEvaluatedKey' in response:
        response = table.scan(
            ExclusiveStartKey=response['LastEvaluatedKey'],
            FilterExpression=boto3.dynamodb.conditions.Attr('status').eq('OPEN')
        )
        findings.extend(response['Items'])

    print(f"Found {len(findings)} open findings to evaluate.")

    for finding in findings:
        finding_id = finding['finding_id']
        rule_id = finding.get('rule_id', '')
        risk_score = int(finding.get('risk_score', 0))
        resource_id = finding.get('resource_id', '')
        severity = finding.get('severity', '')

        # ─────────────────────────────────────────
        # FIN-001: Unattached EBS Volume
        # LOW/MEDIUM → snapshot then DELETE
        # HIGH → snapshot only, flag for approval
        # ─────────────────────────────────────────
        if rule_id == 'FIN-001':
            if severity in ['LOW', 'MEDIUM']:
                try:
                    # Step 1: Create snapshot
                    print(f"Creating snapshot for volume: {resource_id}")
                    snapshot = ec2.create_snapshot(
                        VolumeId=resource_id,
                        Description=f'CloudGuard auto-remediation | {finding_id} | Safe to delete after this',
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'CloudGuard', 'Value': 'true'},
                                {'Key': 'FindingId', 'Value': finding_id},
                                {'Key': 'CreatedBy', 'Value': 'cloudguard-remediation-engine'},
                                {'Key': 'OriginalVolume', 'Value': resource_id},
                                {'Key': 'Reason', 'Value': 'Auto-remediation of unattached EBS volume'}
                            ]
                        }]
                    )
                    snapshot_id = snapshot['SnapshotId']
                    print(f"Snapshot created: {snapshot_id}")

                    # Step 2: Wait for snapshot to complete
                    snapshot_ready = wait_for_snapshot(ec2, snapshot_id)

                    if snapshot_ready:
                        # Step 3: Delete the volume now that snapshot is safe
                        print(f"Snapshot complete. Deleting volume: {resource_id}")
                        ec2.delete_volume(VolumeId=resource_id)
                        print(f"Volume deleted: {resource_id}")

                        # Step 4: Update finding
                        table.update_item(
                            Key={'finding_id': finding_id, 'timestamp': finding['timestamp']},
                            UpdateExpression='SET #s = :s, remediation_action = :a, remediation_timestamp = :t, snapshot_id = :snap, deleted_at = :d',
                            ExpressionAttributeNames={'#s': 'status'},
                            ExpressionAttributeValues={
                                ':s': 'REMEDIATED',
                                ':a': f'Snapshot {snapshot_id} completed successfully. Volume {resource_id} deleted automatically by CloudGuard.',
                                ':t': datetime.now(timezone.utc).isoformat(),
                                ':snap': snapshot_id,
                                ':d': datetime.now(timezone.utc).isoformat()
                            }
                        )

                        results['auto_deleted'].append({
                            'finding_id': finding_id,
                            'resource_id': resource_id,
                            'snapshot_id': snapshot_id,
                            'action': 'Snapshot created and volume deleted automatically'
                        })
                        print(f"AUTO-DELETED: {finding_id} | Volume: {resource_id} | Snapshot: {snapshot_id}")

                    else:
                        # Snapshot didn't complete in time — tag volume but don't delete
                        print(f"Snapshot not ready in time. Tagging volume for manual review.")
                        ec2.create_tags(
                            Resources=[resource_id],
                            Tags=[
                                {'Key': 'CloudGuard-Status', 'Value': 'SNAPSHOT_PENDING'},
                                {'Key': 'CloudGuard-SnapshotId', 'Value': snapshot_id},
                                {'Key': 'CloudGuard-FindingId', 'Value': finding_id}
                            ]
                        )
                        table.update_item(
                            Key={'finding_id': finding_id, 'timestamp': finding['timestamp']},
                            UpdateExpression='SET #s = :s, remediation_action = :a, snapshot_id = :snap',
                            ExpressionAttributeNames={'#s': 'status'},
                            ExpressionAttributeValues={
                                ':s': 'AWAITING_APPROVAL',
                                ':a': f'Snapshot {snapshot_id} still in progress. Volume tagged. Will retry next scan.',
                                ':snap': snapshot_id
                            }
                        )
                        results['snapshot_only'].append({
                            'finding_id': finding_id,
                            'resource_id': resource_id,
                            'snapshot_id': snapshot_id,
                            'action': 'Snapshot in progress, volume not yet deleted'
                        })

                except Exception as e:
                    print(f"EBS remediation failed for {finding_id}: {str(e)}")
                    results['skipped'].append({'finding_id': finding_id, 'reason': str(e)})

            elif severity == 'HIGH':
                # High risk EBS — snapshot only, require approval to delete
                try:
                    snapshot = ec2.create_snapshot(
                        VolumeId=resource_id,
                        Description=f'CloudGuard safety snapshot | {finding_id} | Awaiting approval to delete',
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'CloudGuard', 'Value': 'true'},
                                {'Key': 'FindingId', 'Value': finding_id},
                                {'Key': 'Reason', 'Value': 'HIGH severity — awaiting human approval to delete'}
                            ]
                        }]
                    )
                    snapshot_id = snapshot['SnapshotId']
                    table.update_item(
                        Key={'finding_id': finding_id, 'timestamp': finding['timestamp']},
                        UpdateExpression='SET #s = :s, remediation_action = :a, snapshot_id = :snap',
                        ExpressionAttributeNames={'#s': 'status'},
                        ExpressionAttributeValues={
                            ':s': 'AWAITING_APPROVAL',
                            ':a': f'Safety snapshot {snapshot_id} created. HIGH severity — human must approve deletion.',
                            ':snap': snapshot_id
                        }
                    )
                    results['flagged_for_approval'].append({
                        'finding_id': finding_id,
                        'resource_id': resource_id,
                        'reason': 'HIGH severity — snapshot taken, deletion requires approval'
                    })
                    print(f"APPROVAL REQUIRED: {finding_id} | Volume: {resource_id}")
                except Exception as e:
                    print(f"Snapshot failed for HIGH volume {finding_id}: {str(e)}")
                    results['skipped'].append({'finding_id': finding_id, 'reason': str(e)})

        # ─────────────────────────────────────────
        # NET-001: Unassociated Elastic IP
        # Always auto-release — safe, no data loss risk
        # ─────────────────────────────────────────
        elif rule_id == 'NET-001':
            try:
                addresses = ec2.describe_addresses(
                    Filters=[{'Name': 'public-ip', 'Values': [resource_id]}]
                )['Addresses']
                if addresses:
                    alloc_id = addresses[0].get('AllocationId')
                    if alloc_id:
                        ec2.release_address(AllocationId=alloc_id)
                    else:
                        ec2.release_address(PublicIp=resource_id)

                    table.update_item(
                        Key={'finding_id': finding_id, 'timestamp': finding['timestamp']},
                        UpdateExpression='SET #s = :s, remediation_action = :a, remediation_timestamp = :t',
                        ExpressionAttributeNames={'#s': 'status'},
                        ExpressionAttributeValues={
                            ':s': 'REMEDIATED',
                            ':a': f'Elastic IP {resource_id} released automatically. Billing stopped.',
                            ':t': datetime.now(timezone.utc).isoformat()
                        }
                    )
                    results['auto_deleted'].append({
                        'finding_id': finding_id,
                        'resource_id': resource_id,
                        'action': f'Elastic IP {resource_id} released automatically'
                    })
                    print(f"AUTO-RELEASED: {finding_id} | Elastic IP: {resource_id}")
                else:
                    print(f"Elastic IP {resource_id} not found — may already be released.")
                    table.update_item(
                        Key={'finding_id': finding_id, 'timestamp': finding['timestamp']},
                        UpdateExpression='SET #s = :s',
                        ExpressionAttributeNames={'#s': 'status'},
                        ExpressionAttributeValues={':s': 'REMEDIATED'}
                    )
            except Exception as e:
                print(f"Elastic IP release failed for {finding_id}: {str(e)}")
                results['skipped'].append({'finding_id': finding_id, 'reason': str(e)})

        # ─────────────────────────────────────────
        # All security findings — never auto-fix
        # Always flag for human approval
        # ─────────────────────────────────────────
        elif finding.get('category') == 'SECURITY':
            table.update_item(
                Key={'finding_id': finding_id, 'timestamp': finding['timestamp']},
                UpdateExpression='SET #s = :s',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'AWAITING_APPROVAL'}
            )
            results['flagged_for_approval'].append({
                'finding_id': finding_id,
                'resource_id': resource_id,
                'reason': f'Security finding ({rule_id}) — always requires human approval before any changes'
            })
            print(f"APPROVAL REQUIRED (Security): {finding_id} | {resource_id}")

    print(f"\nRemediation complete.")
    print(f"Auto-deleted/released: {len(results['auto_deleted'])}")
    print(f"Snapshot only (pending): {len(results['snapshot_only'])}")
    print(f"Flagged for approval: {len(results['flagged_for_approval'])}")
    print(f"Skipped: {len(results['skipped'])}")

    return {
        'statusCode': 200,
        'body': json.dumps(results, default=decimal_default)
    }