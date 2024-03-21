import json
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    if event['RequestType'] == 'Delete':
        send_response(event, context, "SUCCESS")
        return

    responseData = {}
    index = event['ResourceProperties']['insightID']
    securityhub = boto3.client('securityhub')

    params = [
        {
            'Name': 'Summary Email - 01 - AWS Foundational Security Best practices findings by compliance status',
            'GroupByAttribute': 'ComplianceStatus',
            'Filters': {
                'Type': [{'Value': 'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices', 'Comparison': 'EQUALS'}],
                'WorkflowStatus': [{'Value': 'SUPPRESSED', 'Comparison': 'NOT_EQUALS'}],
                'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
            }
        },
        {
            'Name': 'Summary Email - 02 - Failed AWS Foundational Security Best practices findings by severity',
            'GroupByAttribute': 'SeverityLabel',
            'Filters': {
                'Type': [{'Value': 'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices', 'Comparison': 'EQUALS'}],
                'WorkflowStatus': [{'Value': 'SUPPRESSED', 'Comparison': 'NOT_EQUALS'}],
                'ComplianceStatus': [{'Value': 'FAILED', 'Comparison': 'EQUALS'}],
                'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
            }
        },
        # Add other params as needed
    ]

    try:
        response = securityhub.create_insight(Insight={
            'Name': params[index]['Name'],
            'Filters': params[index]['Filters']
        })

        responseData['ARN'] = response['InsightArn']
        send_response(event, context, "SUCCESS", responseData)
    except ClientError as e:
        responseData['Error'] = f"CreateInsight call failed: {str(e)}"
        send_response(event, context, "FAILED", responseData)

def send_response(event, context, responseStatus, responseData={}):
    responseUrl = event['ResponseURL']
    responseBody = {
        'Status': responseStatus,
        'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
        'PhysicalResourceId': context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': responseData
    }

    json_responseBody = json.dumps(responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = requests.put(
            responseUrl,
            data=json_responseBody,
            headers=headers
        )
        print("Response status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))