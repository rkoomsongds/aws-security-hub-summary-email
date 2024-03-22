import json
import http.client
import urllib.parse

SUCCESS = "SUCCESS"
FAILED = "FAILED"

def send(event, context, responseStatus, responseData, physicalResourceId, noEcho):
    responseBody = json.dumps({
        "Status": responseStatus,
        "Reason": "See the details in CloudWatch Log Stream: " + context.logStreamName,
        "PhysicalResourceId": physicalResourceId or context.logStreamName,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": noEcho or False,
        "Data": responseData
    })
    print("Response body:\n", responseBody)
    parsedUrl = urllib.parse.urlparse(event["ResponseURL"])
    conn = http.client.HTTPSConnection(parsedUrl.hostname, 443)
    headers = {
        "content-type": "",
        "content-length": str(len(responseBody))
    }
    conn.request("PUT", parsedUrl.path, body=responseBody, headers=headers)
    response = conn.getresponse()
    print("Status code: " + str(response.status))
    print("Status message: " + response.reason)
    conn.close()