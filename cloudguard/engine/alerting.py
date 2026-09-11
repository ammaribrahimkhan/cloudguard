import boto3
import json
from datetime import datetime, timezone
from decimal import Decimal

SNS_ARN = 'arn:aws:sns:ap-south-1:104299473009:cloudguard-alerts'

def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

def lambda_handler(event, context):
    dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
    table = dynamodb.Table('cloudguard-findings')
    sns = boto3.client('sns', region_name='ap-south-1')
    
    # Get CRITICAL and HIGH findings that are still OPEN or AWAITING_APPROVAL
    response = table.scan(
        FilterExpression=(
            boto3.dynamodb.conditions.Attr('severity').is_in(['CRITICAL', 'HIGH']) &
            boto3.dynamodb.conditions.Attr('status').is_in(['OPEN', 'AWAITING_APPROVAL'])
        )
    )
    findings = response['Items']
    
    while 'LastEvaluatedKey' in response:
        response = table.scan(
            ExclusiveStartKey=response['LastEvaluatedKey'],
            FilterExpression=(
                boto3.dynamodb.conditions.Attr('severity').is_in(['CRITICAL', 'HIGH']) &
                boto3.dynamodb.conditions.Attr('status').is_in(['OPEN', 'AWAITING_APPROVAL'])
            )
        )
        findings.extend(response['Items'])
    
    if len(findings) == 0:
        print("No critical/high findings to alert on.")
        return {'statusCode': 200, 'body': 'No alerts needed.'}
    
    critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
    high_count = len([f for f in findings if f.get('severity') == 'HIGH'])
    
    # Build email message
    message_lines = [
        "=" * 60,
        "CLOUDGUARD SECURITY & FINOPS ALERT",
        "=" * 60,
        f"Scan Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Account: 104299473009",
        f"Region: ap-south-1 (Mumbai)",
        "",
        f"SUMMARY",
        f"-------",
        f"Critical Findings: {critical_count}",
        f"High Findings:     {high_count}",
        f"Total Urgent:      {len(findings)}",
        "",
        "FINDINGS REQUIRING ATTENTION",
        "-" * 40,
    ]
    
    for f in sorted(findings, key=lambda x: int(x.get('risk_score', 0)), reverse=True):
        message_lines.extend([
            "",
            f"[{f.get('severity')}] {f.get('title')}",
            f"  Finding ID:   {f.get('finding_id')}",
            f"  Resource:     {f.get('resource_id')}",
            f"  Type:         {f.get('resource_type')}",
            f"  Risk Score:   {f.get('risk_score')}/100",
            f"  Status:       {f.get('status')}",
            f"  Category:     {f.get('category')}",
            f"  Description:  {f.get('description')}",
            f"  Action:       {f.get('recommendation')}",
        ])
    
    message_lines.extend([
        "",
        "=" * 60,
        "CloudGuard AWS Governance Platform",
        "Log into your AWS Console to review and remediate.",
        "=" * 60
    ])
    
    full_message = "\n".join(message_lines)
    
    subject = f"[CloudGuard] {critical_count} Critical, {high_count} High Findings — Action Required"
    
    sns.publish(
        TopicArn=SNS_ARN,
        Subject=subject,
        Message=full_message
    )
    
    print(f"Alert sent. Critical: {critical_count}, High: {high_count}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'alert_sent': True,
            'critical': critical_count,
            'high': high_count,
            'total_alerted': len(findings)
        })
    }