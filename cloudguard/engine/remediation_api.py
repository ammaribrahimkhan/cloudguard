import boto3
import json
import time
from datetime import datetime, timezone
from decimal import Decimal

def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

def wait_for_snapshot(ec2, snapshot_id, max_wait_seconds=180):
    print(f"Waiting for snapshot {snapshot_id}...")
    waited = 0
    while waited < max_wait_seconds:
        resp = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
        state = resp['Snapshots'][0]['State']
        if state == 'completed':
            return True
        if state == 'error':
            return False
        time.sleep(15)
        waited += 15
    return False

def lambda_handler(event, context):
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Content-Type': 'application/json'
    }

    if event.get('requestContext', {}).get('http', {}).get('method') == 'OPTIONS':
        return {'statusCode': 200, 'headers': headers, 'body': ''}

    try:
        body = json.loads(event.get('body', '{}'))
        finding_id = body.get('finding_id')
        action = body.get('action')

        if not finding_id or not action:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({'error': 'finding_id and action are required'})
            }

        dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
        table = dynamodb.Table('cloudguard-findings')
        ec2 = boto3.client('ec2', region_name='ap-south-1')

        existing = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('finding_id').eq(finding_id),
            Limit=1
        )
        if existing['Count'] == 0:
            return {
                'statusCode': 404,
                'headers': headers,
                'body': json.dumps({'error': 'Finding not found'})
            }

        finding = existing['Items'][0]
        rule_id = finding.get('rule_id', '')
        resource_id = finding.get('resource_id', '')
        severity = finding.get('severity', '')
        timestamp = finding['timestamp']
        result_message = ''

        # ─────────────────────────────────────────
        # DISMISS — works on any finding
        # ─────────────────────────────────────────
        if action == 'dismiss':
            table.update_item(
                Key={'finding_id': finding_id, 'timestamp': timestamp},
                UpdateExpression='SET #s = :s, dismissed_at = :t',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={
                    ':s': 'DISMISSED',
                    ':t': datetime.now(timezone.utc).isoformat()
                }
            )
            result_message = f'Finding {finding_id} dismissed.'

        elif action == 'approve':

            # ─────────────────────────────────────────
            # FIN-001: EBS Volume — snapshot then delete
            # ─────────────────────────────────────────
            if rule_id == 'FIN-001':
                try:
                    # Mark as in-progress immediately so UI updates
                    table.update_item(
                        Key={'finding_id': finding_id, 'timestamp': timestamp},
                        UpdateExpression='SET #s = :s, remediation_action = :a',
                        ExpressionAttributeNames={'#s': 'status'},
                        ExpressionAttributeValues={
                            ':s': 'AWAITING_APPROVAL',
                            ':a': 'Snapshot in progress — volume will be deleted once snapshot completes.'
                        }
                    )

                    snapshot = ec2.create_snapshot(
                        VolumeId=resource_id,
                        Description=f'CloudGuard manual remediation | {finding_id}',
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'CloudGuard', 'Value': 'true'},
                                {'Key': 'FindingId', 'Value': finding_id},
                                {'Key': 'CreatedBy', 'Value': 'cloudguard-remediation-api'},
                                {'Key': 'OriginalVolume', 'Value': resource_id}
                            ]
                        }]
                    )
                    snapshot_id = snapshot['SnapshotId']
                    print(f"Snapshot started: {snapshot_id}")

                    snapshot_ready = wait_for_snapshot(ec2, snapshot_id)

                    if snapshot_ready:
                        ec2.delete_volume(VolumeId=resource_id)
                        print(f"Volume deleted: {resource_id}")

                        table.update_item(
                            Key={'finding_id': finding_id, 'timestamp': timestamp},
                            UpdateExpression='SET #s = :s, remediation_action = :a, remediation_timestamp = :t, snapshot_id = :snap, deleted_at = :d',
                            ExpressionAttributeNames={'#s': 'status'},
                            ExpressionAttributeValues={
                                ':s': 'REMEDIATED',
                                ':a': f'Snapshot {snapshot_id} completed. Volume {resource_id} deleted. Billing stopped.',
                                ':t': datetime.now(timezone.utc).isoformat(),
                                ':snap': snapshot_id,
                                ':d': datetime.now(timezone.utc).isoformat()
                            }
                        )
                        result_message = f'Snapshot {snapshot_id} completed. Volume {resource_id} deleted successfully. You will no longer be charged for this volume.'
                    else:
                        result_message = f'Snapshot {snapshot_id} is still in progress. Volume not deleted yet. Run the remediation engine again to complete.'

                except Exception as e:
                    result_message = f'Remediation failed: {str(e)}'

            # ─────────────────────────────────────────
            # NET-001: Elastic IP — release immediately
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
                            Key={'finding_id': finding_id, 'timestamp': timestamp},
                            UpdateExpression='SET #s = :s, remediation_action = :a, remediation_timestamp = :t',
                            ExpressionAttributeNames={'#s': 'status'},
                            ExpressionAttributeValues={
                                ':s': 'REMEDIATED',
                                ':a': f'Elastic IP {resource_id} released. Billing stopped immediately.',
                                ':t': datetime.now(timezone.utc).isoformat()
                            }
                        )
                        result_message = f'Elastic IP {resource_id} released successfully. You will no longer be charged for it.'
                    else:
                        result_message = 'Elastic IP not found — may already be released.'
                except Exception as e:
                    result_message = f'Release failed: {str(e)}'

            # ─────────────────────────────────────────
            # Security findings — mark approved, never auto-change
            # ─────────────────────────────────────────
            else:
                table.update_item(
                    Key={'finding_id': finding_id, 'timestamp': timestamp},
                    UpdateExpression='SET #s = :s, approved_at = :t',
                    ExpressionAttributeNames={'#s': 'status'},
                    ExpressionAttributeValues={
                        ':s': 'APPROVED_FOR_FIX',
                        ':t': datetime.now(timezone.utc).isoformat()
                    }
                )
                result_message = f'Security finding approved for manual remediation. Go to AWS Console and apply the fix described in the AI explanation.'

        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({'success': True, 'message': result_message})
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'error': str(e)})
        }