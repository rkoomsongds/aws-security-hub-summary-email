var response = require('cfn-response');
exports.handler = function(event, context) {
    if (event.RequestType == 'Delete') {
        response.send(event, context, response.SUCCESS);
        return;
   }
   var AWS = require('aws-sdk');
   var responseData = {};
   var index = event.ResourceProperties.insightID
   const securityhub = new AWS.SecurityHub();
   var params = [];
   params['0'] = {Name: 'Summary Email - 01 - AWS Foundational Security Best practices findings by compliance status',
   GroupByAttribute: 'ComplianceStatus', 
   Filters: {Type:[{Value:'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices', Comparison:'EQUALS'}]
     ,WorkflowStatus:[{Value:'SUPPRESSED',Comparison:'NOT_EQUALS'}], RecordState:[{Value:'ACTIVE',Comparison:'EQUALS'}] }};   
   params['1'] = {Name: 'Summary Email - 02 - Failed AWS Foundational Security Best practices findings by severity',
   GroupByAttribute: 'SeverityLabel', 
   Filters: {Type:[{Value:'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices', Comparison:'EQUALS'}]
     ,WorkflowStatus:[{Value:'SUPPRESSED',Comparison:'NOT_EQUALS'}], ComplianceStatus: [{Value:'FAILED',Comparison:'EQUALS'}],RecordState: [{Value:'ACTIVE',Comparison:'EQUALS'}] }};   
   params['2'] = {Name: 'Summary Email - 03 - Count of Amazon GuardDuty findings by severity',
   GroupByAttribute: 'SeverityLabel', 
   Filters: {ProductName:[{Value:'GuardDuty', Comparison:'EQUALS'}]
         ,WorkflowStatus:[{Value:'SUPPRESSED',Comparison:'NOT_EQUALS'}], RecordState:[{Value:'ACTIVE',Comparison:'EQUALS'}] }};
   params['3'] = {Name: 'Summary Email - 04 - Count of IAM Access Analyzer findings by severity',
   GroupByAttribute: 'SeverityLabel', 
   Filters: {ProductName:[{Value:'IAM Access Analyzer', Comparison:'EQUALS'}]
         ,WorkflowStatus:[{Value:'SUPPRESSED',Comparison:'NOT_EQUALS'}], RecordState:[{Value:'ACTIVE',Comparison:'EQUALS'}] }};
   params['4'] = {Name: 'Summary Email - 05 - Count of all unresolved findings by severity',
   GroupByAttribute: 'SeverityLabel', 
   Filters: {WorkflowStatus:[{Value:'RESOLVED', Comparison:'NOT_EQUALS'},{Value:'SUPPRESSED',Comparison:'NOT_EQUALS'}]
         , RecordState:[{Value:'ACTIVE',Comparison:'EQUALS'}] }};
   params['5'] = {Name: 'Summary Email - 06 - new findings in the last 7 days',
   GroupByAttribute: 'ProductName', 
   Filters: {WorkflowStatus:[{Value:'RESOLVED', Comparison:'NOT_EQUALS'}, {Value:'SUPPRESSED',Comparison:'NOT_EQUALS'}], CreatedAt:[{DateRange:{Value:'7', Unit:'DAYS'}}]
         , RecordState:[{Value:'ACTIVE',Comparison:'EQUALS'}] }};  
   params['6'] = {Name: 'Summary Email - 07 - Top Resource Types with findings by count',
   GroupByAttribute: 'ResourceType', 
   Filters: {WorkflowStatus:[{Value:'SUPPRESSED',Comparison:'NOT_EQUALS'}], RecordState:[{Value:'ACTIVE',Comparison:'EQUALS'}] }};  
    securityhub.createInsight(params[index], function(err, createInsightResult) {
    if (err) {
        responseData = {Error: 'CreateInsight call failed'};
        console.log(responseData.Error , err);
        response.send(event, context, response.FAILED, responseData);
    }
    else {
        console.log(createInsightResult['InsightArn']);
        responseData['ARN'] = createInsightResult['InsightArn'];
        response.send(event, context, response.SUCCESS, responseData);
    }
});
}