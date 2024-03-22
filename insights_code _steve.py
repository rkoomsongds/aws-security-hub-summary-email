
customInsights = { 'insight01': {
'name': 'Summary Email - 01 - AWS Foundational Security Best practices findings by compliance status',
    'filter' : {
        'Type': [
            {'Value':'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices', 'Comparison':'EQUALS'
            }
        ],
        'WorkflowStatus': [
            {'Value':'SUPPRESSED','Comparison':'NOT_EQUALS'
            }
        ], 
        'RecordState': [
            {'Value':'ACTIVE','Comparison':'EQUALS'
            }
        ]
    },
            'GroupByAttribute': 'ComplianceStatus'
},
        'insight02': {
'name': 'Summary Email - 02 - Failed AWS Foundational Security Best practices findings by severity',
    'filter' : {
        'Type': [
            {'Value':'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices', 'Comparison':'EQUALS'
            }
        ],
        'WorkflowStatus': [
            {'Value':'SUPPRESSED','Comparison':'NOT_EQUALS'
            }
        ],
        'ComplianceStatus': [{'Value':'FAILED','Comparison':'EQUALS'}],
        'RecordState': [
            {'Value':'ACTIVE','Comparison':'EQUALS'
            }
        ]
    },
            'GroupByAttribute': 'SeverityLabel'
},
        'insight03': {
'name': 'Summary Email - 03 - Count of Amazon GuardDuty findings by severity',
    'filter' : {
        'ProductName': [
            {'Value':'GuardDuty', 'Comparison':'EQUALS'
            }
        ],
        'WorkflowStatus': [
            {'Value':'SUPPRESSED','Comparison':'NOT_EQUALS'
            }
        ], 
        'RecordState': [
            {'Value':'ACTIVE','Comparison':'EQUALS'
            }
        ]
    },
            'GroupByAttribute': 'SeverityLabel'
},
        'insight04': {
'name': 'Summary Email - 04 - Count of IAM Access Analyzer findings by severity',
    'filter' : {
        'ProductName': [
            {'Value':'IAM Access Analyzer', 'Comparison':'EQUALS'
            }
        ],
        'WorkflowStatus': [
            {'Value':'SUPPRESSED','Comparison':'NOT_EQUALS'
            }
        ], 
        'RecordState': [
            {'Value':'ACTIVE','Comparison':'EQUALS'
            }
        ]
    },
            'GroupByAttribute': 'SeverityLabel'
},
        'insight05': {
'name': 'Summary Email - 05 - Count of all unresolved findings by severity',
    'filter' : {
        'WorkflowStatus': [
            {'Value':'RESOLVED','Comparison':'NOT_EQUALS'
            }
        ],
        'RecordState': [
            {'Value':'ACTIVE','Comparison':'EQUALS'
            }
        ]
    },
            'GroupByAttribute': 'SeverityLabel'
},
        'insight06': {
'name': 'Summary Email - 06 - new findings in the last 7 days',
    'filter' : {
        'CreatedAt':[{'DateRange':{'Value':7, 'Unit':'DAYS'}}]
        ,
        'WorkflowStatus': [
            {'Value':'RESOLVED','Comparison':'NOT_EQUALS'
            }
        ], 
        'RecordState': [
            {'Value':'ACTIVE','Comparison':'EQUALS'
            }
        ]
    },
            'GroupByAttribute': 'ProductName'
},
        'insight07': {
'name': 'Summary Email - 07 - Top Resource Types with findings by count',
    'filter' : {
        'WorkflowStatus': [
            {'Value':'SUPPRESSED','Comparison':'NOT_EQUALS'
            }
        ], 
        'RecordState': [
            {'Value':'ACTIVE','Comparison':'EQUALS'
            }
        ]
    },
            'GroupByAttribute': 'ResourceType'
}
    }

security_hub = boto3.client('securityhub')

def create_custom_insights():
    Insights = security_hub.get_insights()
    insightList = Insights['Insights']

    for i in customInsights:
        name = customInsights[i]['name']
        
        createCustomInsight = True 
        for existingInsight in insightList:
            if name in existingInsight['Name']:
                createCustomInsight = False
                print(f"Insight {name} already exists, it will not be created")
                break
            
        if createCustomInsight:
            security_hub.create_insight(Name=customInsights[i]['name'], Filters=customInsights[i]['filter'], GroupByAttribute=customInsights[i]['GroupByAttribute'])
        