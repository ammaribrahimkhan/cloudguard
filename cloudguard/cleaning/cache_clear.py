import boto3
import json
from decimal import Decimal

def lambda_handler(event, context):
    dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
    table = dynamodb.Table('cloudguard-findings')
    
    response = table.scan()
    items = response['Items']
    while 'LastEvaluatedKey' in response:
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        items.extend(response['Items'])
    
    cleared = 0
    for item in items:
        try:
            table.update_item(
                Key={'finding_id': item['finding_id'], 'timestamp': item['timestamp']},
                UpdateExpression='REMOVE ai_explanation, ai_generated_at'
            )
            cleared += 1
        except Exception as e:
            print(f"Error clearing {item['finding_id']}: {str(e)}")
    
    print(f"Cleared AI cache for {cleared} findings.")
    return {'statusCode': 200, 'body': json.dumps({'cleared': cleared})}