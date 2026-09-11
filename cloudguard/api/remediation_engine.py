import boto3
import json
from datetime import datetime, timezone
from decimal import Decimal

def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

def lambda_handler(event, context):
    dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
    table = dynamodb.Table('cloudguard-findings')
    
    response = table.scan()
    findings = response['Items']
    
    # Keep paginating if there are more items
    while 'LastEvaluatedKey' in response:
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        findings.extend(response['Items'])
    
    # Summary stats
    total = len(findings)
    critical = len([f for f in findings if f.get('severity') == 'CRITICAL'])
    high = len([f for f in findings if f.get('severity') == 'HIGH'])
    medium = len([f for f in findings if f.get('severity') == 'MEDIUM'])
    low = len([f for f in findings if f.get('severity') == 'LOW'])
    security = len([f for f in findings if f.get('category') == 'SECURITY'])
    finops = len([f for f in findings if f.get('category') == 'FINOPS'])
    
    total_monthly_cost = sum(
        float(f.get('estimated_monthly_cost_usd', 0))
        for f in findings
        if f.get('estimated_monthly_cost_usd')
    )
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json'
        },
        'body': json.dumps({
            'summary': {
                'total_findings': total,
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'security_findings': security,
                'finops_findings': finops,
                'estimated_monthly_waste_usd': round(total_monthly_cost, 2)
            },
            'findings': sorted(findings, key=lambda x: int(x.get('risk_score', 0)), reverse=True)
        }, default=decimal_default)
    }