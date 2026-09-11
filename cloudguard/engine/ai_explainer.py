import boto3
import json
from datetime import datetime, timezone
from decimal import Decimal

def lambda_handler(event, context):
    dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
    table = dynamodb.Table('cloudguard-findings')

    # Try us-east-1 first, fall back to ap-south-1
    regions_to_try = ['us-east-1', 'ap-south-1', 'us-west-2']
    
    # Models to try in order
    models_to_try = [
        'anthropic.claude-3-5-haiku-20241022-v1:0',
        'anthropic.claude-3-haiku-20240307-v1:0',
        'amazon.titan-text-lite-v1'
    ]

    response = table.scan(
        FilterExpression=boto3.dynamodb.conditions.Attr('ai_explanation').not_exists()
    )
    findings = response['Items']

    while 'LastEvaluatedKey' in response:
        response = table.scan(
            ExclusiveStartKey=response['LastEvaluatedKey'],
            FilterExpression=boto3.dynamodb.conditions.Attr('ai_explanation').not_exists()
        )
        findings.extend(response['Items'])

    print(f"Found {len(findings)} findings needing AI explanations.")
    processed = 0

    for finding in findings:
        finding_id = finding['finding_id']
        ai_text = None

        for region in regions_to_try:
            if ai_text:
                break
            bedrock = boto3.client('bedrock-runtime', region_name=region)

            for model_id in models_to_try:
                try:
                    if 'titan' in model_id:
                        body = json.dumps({
                            'inputText': f"""You are a cloud security expert. Explain this AWS finding in 2-3 plain English sentences for a non-technical manager.

Title: {finding.get('title')}
Resource: {finding.get('resource_id')} ({finding.get('resource_type')})
Severity: {finding.get('severity')} - Risk Score: {finding.get('risk_score')}/100
Description: {finding.get('description')}
Recommended fix: {finding.get('recommendation')}

Explain what it means, why it matters, and what to do. Be direct.""",
                            'textGenerationConfig': {
                                'maxTokenCount': 200,
                                'temperature': 0.3
                            }
                        })
                        resp = bedrock.invoke_model(
                            modelId=model_id,
                            contentType='application/json',
                            accept='application/json',
                            body=body
                        )
                        result = json.loads(resp['body'].read())
                        ai_text = result['results'][0]['outputText'].strip()
                    else:
                        body = json.dumps({
                            'anthropic_version': 'bedrock-2023-05-31',
                            'max_tokens': 200,
                            'messages': [{
                                'role': 'user',
                                'content': f"""You are a cloud security expert. Explain this AWS finding in 2-3 plain English sentences for a non-technical manager.

Title: {finding.get('title')}
Resource: {finding.get('resource_id')} ({finding.get('resource_type')})
Severity: {finding.get('severity')} - Risk Score: {finding.get('risk_score')}/100
Description: {finding.get('description')}
Recommended fix: {finding.get('recommendation')}

Explain what it means, why it matters, and what to do. Be direct. No bullet points."""
                            }]
                        })
                        resp = bedrock.invoke_model(
                            modelId=model_id,
                            contentType='application/json',
                            accept='application/json',
                            body=body
                        )
                        result = json.loads(resp['body'].read())
                        ai_text = result['content'][0]['text'].strip()

                    print(f"Success with {model_id} in {region} for {finding_id}")
                    break

                except Exception as e:
                    print(f"Failed {model_id} in {region}: {str(e)}")
                    continue

        # If all AI attempts failed, generate a smart rule-based explanation
        if not ai_text:
            rule_id = finding.get('rule_id', '')
            severity = finding.get('severity', 'MEDIUM')
            resource = finding.get('resource_id', 'this resource')

            explanations = {
                'SEC-001': f'The S3 bucket "{resource}" is potentially accessible to the public internet. This means sensitive files stored in it could be read, downloaded, or exposed by anyone online. This should be fixed immediately by enabling all four public access block settings in the S3 console.',
                'SEC-002': f'Port 22 (SSH) on security group "{resource}" is open to the entire internet (0.0.0.0/0). This allows any computer in the world to attempt to log into your servers, making it a prime target for automated hacking attempts. Restrict SSH to your office IP address only.',
                'SEC-003': f'Port 3389 (RDP) on security group "{resource}" is open to the entire internet. This exposes any Windows server using this group to brute-force login attacks from anywhere in the world. Restrict RDP to trusted IP addresses immediately.',
                'SEC-004': f'The IAM user "{resource}" can log into the AWS Console but has no MFA (two-factor authentication) device set up. If their password is stolen or guessed, an attacker would have full access to your AWS account. Enable MFA immediately.',
                'SEC-005': f'The AWS access key belonging to "{resource}" has not been rotated in over 90 days. Long-lived credentials are a security risk — if this key was ever exposed in code or logs, it could still be active. Create a new key and delete the old one.',
                'FIN-001': f'An EBS storage volume "{resource}" is not attached to any server and has been idle, but AWS is still charging for it every month. This is wasted spend. Take a snapshot backup of it first, then delete it to stop the charges.',
                'NET-001': f'An Elastic IP address "{resource}" is allocated to your account but not attached to any server. AWS charges approximately $3.60/month for unattached Elastic IPs. If you do not need this IP, release it to eliminate this unnecessary charge.',
                'NET-002': f'The default security group "{resource}" has inbound rules configured. AWS best practice requires default security groups to have no rules — all traffic should go through custom, purpose-specific security groups to reduce risk.',
                'NET-003': f'EC2 instance "{resource}" has a public IP address assigned directly to it. Best practice is to put instances in private subnets and expose them only through a load balancer, reducing the attack surface.'
            }

            ai_text = explanations.get(rule_id, f'This {severity.lower()} severity finding on resource "{resource}" requires attention. {finding.get("recommendation", "")}')
            print(f"Using rule-based explanation for {finding_id} (all AI attempts failed)")

        # Save to DynamoDB
        try:
            table.update_item(
                Key={'finding_id': finding_id, 'timestamp': finding['timestamp']},
                UpdateExpression='SET ai_explanation = :e, ai_generated_at = :t',
                ExpressionAttributeValues={
                    ':e': ai_text,
                    ':t': datetime.now(timezone.utc).isoformat()
                }
            )
            processed += 1
            print(f"Explanation saved: {finding_id}")
        except Exception as e:
            print(f"DynamoDB save failed for {finding_id}: {str(e)}")

    print(f"Done. Processed {processed} findings.")
    return {
        'statusCode': 200,
        'body': json.dumps({'processed': processed})
    }