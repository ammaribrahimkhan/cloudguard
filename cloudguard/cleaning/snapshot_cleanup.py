import boto3
import json
from datetime import datetime, timezone, timedelta

def lambda_handler(event, context):
    ec2 = boto3.client('ec2', region_name='ap-south-1')
    
    # Get all CloudGuard snapshots
    snapshots = ec2.describe_snapshots(
        Filters=[
            {'Name': 'tag:CloudGuard', 'Values': ['true']},
            {'Name': 'status', 'Values': ['completed']}
        ],
        OwnerIds=['self']
    )['Snapshots']
    
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    deleted = []
    kept = []
    
    for snap in snapshots:
        snap_id = snap['SnapshotId']
        start_time = snap['StartTime']
        age_days = (datetime.now(timezone.utc) - start_time).days
        
        if start_time < cutoff:
            try:
                ec2.delete_snapshot(SnapshotId=snap_id)
                deleted.append(snap_id)
                print(f"Deleted old snapshot: {snap_id} (age: {age_days} days)")
            except Exception as e:
                print(f"Could not delete {snap_id}: {str(e)}")
        else:
            kept.append(snap_id)
            print(f"Keeping recent snapshot: {snap_id} (age: {age_days} days)")
    
    print(f"Done. Deleted: {len(deleted)}, Kept: {len(kept)}")
    return {
        'statusCode': 200,
        'body': json.dumps({
            'deleted_snapshots': deleted,
            'kept_snapshots': kept,
            'deleted_count': len(deleted),
            'kept_count': len(kept)
        })
    }