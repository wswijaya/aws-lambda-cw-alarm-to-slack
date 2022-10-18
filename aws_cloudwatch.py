import json
import logging
from datetime import timedelta, datetime
from collections import namedtuple

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def utc_str_to_local_str(utc_str: str, utc_format: str, local_format: str):
    """
    :param utc_str: UTC time string
    :param utc_format: format of UTC time string
    :param local_format: format of local time string
    :return: local time string
    """
    temp1 = datetime.strptime(utc_str, utc_format) + timedelta(hours=8)
    return temp1.strftime(local_format)

class AlertMessage:
    def __init__(self):
        self.Text = "Default Alert Message"

    def formatSubject(self, subject: str):
        if subject is None:
            return ""
        elif subject == "None":
            return ""
        else:
            return "*%s*:" % (subject)

    def generateMessage(self, localTimestamp: str, subject: str, messageList: list):
        messageBody = ""
        for messageObj in messageList:
            messageBody = "SNS Topic: *%s*, Message ID: %s \n" % (messageObj['TopicName'], messageObj['MessageId'])

        return "[%s] %s %s" % (localTimestamp, self.formatSubject(subject), messageBody)

class AlertMessageFromCloudWatchAlarm(AlertMessage):

    def generateMessage(self, localTimestamp: str, subject: str, messageList: list):
        messageBody = ""
        for messageObj in messageList:
            messageBody = "```%s```" % (messageObj['NewStateReason'])

        return "[%s] %s %s" % (localTimestamp, self.formatSubject(subject), messageBody)

class AlertMessageFromRDSNotification(AlertMessage):

    def generateMessage(self, localTimestamp: str, subject: str, messageList: list):
        messageBody = ""
        for messageObj in messageList:
            messageBody = "(%s) %s" % (messageObj['Source ID'], messageObj['Event Message'])

        return "[%s] %s %s" % (localTimestamp, self.formatSubject(subject), messageBody)

class AlertMessageFromDBInstanceEvent(AlertMessage):

    def generateMessage(self, localTimestamp: str, subject: str, messageList: list):
        messageBody = ""
        for messageObj in messageList:
            subject = messageObj['detail-type']
            messageBody = "Source Type is %s, (%s) ```%s```" % (messageObj['detail']['SourceType'], messageObj['detail']['SourceIdentifier'], messageObj['detail']['Message'])

        return "[%s] %s %s" % (localTimestamp, self.formatSubject(subject), messageBody)

class AlertMessageFromGuardDuty(AlertMessage):

    def generateMessage(self, localTimestamp: str, subject: str, messageList: list):
        subject = "AWS GuardDuty Notification"
        messageBody = ""
        for messageObj in messageList:
            event_message = "%s - %s " % (messageObj['detail']['type'], messageObj['detail']['description'])
            severity = messageObj['detail']['severity']
            if severity > 2:
                messageBody = "*%s* (Severity %s) %s" % (subject, severity, event_message)
            else:
                messageBody = ""

        return "[%s] %s %s" % (localTimestamp, self.formatSubject(subject), messageBody)

class AlertMessageFromServiceASG(AlertMessage):

    def generateMessage(self, localTimestamp: str, subject: str, messageList: list):
        messageBody = ""
        for messageObj in messageList:
            status_code = messageObj['StatusCode']
            cause = messageObj["Cause"]
            messageBody = "Status: %s , Cause: %s" % (status_code, cause)

        return "[%s] %s %s" % (localTimestamp, self.formatSubject(subject), messageBody)

### Alarm Message Creator
def alertMessageCreator(full_class_name: str):
    try:
        module_name, class_name = full_class_name.rsplit(".", 1)
        module = __import__(module_name)
        my_class = getattr(module, class_name)
        instance = my_class()
        return instance
    except ModuleNotFoundError as modNotFoundErr:
        print(modNotFoundErr)
    except AttributeError as attrErr:
        return AlertMessage()

AwsEventPatterns = {}
AwsEventPattern = namedtuple("AwsEventPattern", "ServiceName EventType AlertFormatter SendAlert")
AwsEventPatterns['Alarm'] = AwsEventPattern(ServiceName="CloudWatch Alarm", EventType="All Events", AlertFormatter="CloudWatchAlarm",SendAlert=True)
AwsEventPatterns['RDSNotification'] = AwsEventPattern(ServiceName="RDS Notification Event",EventType="All Events",AlertFormatter="RDSNotification",SendAlert=True)
AwsEventPatterns['aws.guardduty'] = AwsEventPattern(ServiceName="GuardDuty",EventType="All Events",AlertFormatter="GuardDuty",SendAlert=True)
AwsEventPatterns['aws.cloudtrail'] = AwsEventPattern(ServiceName="CloudTrail",EventType="All Events",AlertFormatter="CloudTrail",SendAlert=False)
AwsEventPatterns['aws.securityhub'] = AwsEventPattern(ServiceName="SecurityHub",EventType="All Events",AlertFormatter="SecurityHub",SendAlert=False)
AwsEventPatterns['aws.rds'] = AwsEventPattern(ServiceName="RDS",EventType="All Events",AlertFormatter="DBInstanceEvent",SendAlert=True)
AwsEventPatterns['aws.autoscaling'] = AwsEventPattern(ServiceName="Auto Scaling",EventType="All Events",AlertFormatter="AutoScaling",SendAlert=True)
AwsEventPatterns['UNKNOWN'] = AwsEventPattern(ServiceName="UNKNOWN",EventType="All Events",AlertFormatter="Unknown",SendAlert=True)

class AwsSns:

    def __init__(self, notification: dict):
        self.MessageList = []
        self.__load(notification)

    def __load(self, notification: dict):
        self.Type = notification['Type']
        self.MessageId = notification['MessageId']
        self.TopicArn = notification['TopicArn']
        self.TopicName = notification['TopicArn'].split(':')[5]
        self.Subject = notification['Subject']
        self.Timestamp = notification['Timestamp']
        utc_fmt = '%Y-%m-%dT%H:%M:%S.%fZ'
        local_fmt = '%Y-%m-%d %H:%M:%S+08:00'
        self.LocalTimestamp = utc_str_to_local_str(self.Timestamp, utc_fmt, local_fmt)
        self.SignatureVersion = notification['SignatureVersion']
        self.Signature = notification['Signature']
        self.SigningCertUrl = notification['SigningCertUrl']
        self.UnsubscribeUrl = notification['UnsubscribeUrl']
        self.__parseMessage(notification['Message'])
        self.MessageAttributesObj = {}
        self.EventOrigin = ""

    def __parseMessage(self, messageStr :str):
        messageObj = json.loads(messageStr)
        if isinstance(messageObj, list):
            self.MessageList = messageObj
        else:
            self.MessageList.append(messageObj)
        self.__classifyMessage()

    def __classifyMessage(self):
        for m in self.MessageList:
            m['MessageId'] = self.MessageId
            m['TopicName'] = self.TopicName
            if ('AlarmName' in m):
                ## All alerts created by CloudWatch Alarm
                m['Origin'] = AwsEventPatterns['Alarm']
            elif ('Event Source' in m):
                ## Some event can be generate by the service directly, e.g. RDS
                m['Origin'] = AwsEventPatterns['RDSNotification']
            elif ('source' in m):
                ## All alerts created in CloudWatch Event will be processed here.
                 try:
                    m['Origin'] = AwsEventPatterns[m['source']]
                 except KeyError as err:
                     logger.error("Event Origin is UNKNOWN, source: %s", err)
                     m['Origin'] = AwsEventPatterns['UNKNOWN']
            else:
                m['Origin'] = AwsEventPatterns['UNKNOWN']

    def generateMessage(self):
        if (self.MessageList and len(self.MessageList) > 0 and self.MessageList[0]['Origin'].SendAlert):
            alertMessageHandler = alertMessageCreator("aws_cloudwatch.AlertMessageFrom" + self.MessageList[0]['Origin'].AlertFormatter)
            if (alertMessageHandler):
                return alertMessageHandler.generateMessage(self.LocalTimestamp, self.Subject, self.MessageList)
            else:
                logger.error("ClassNotFound: UNKNOWN Alert!")
                return None
        else:
            logger.error("Message doesn't exists or SendAlert setting is 'turned off'.")
            return None

class AwsCloudWatchEvent:

    def __init__(self, event: dict):
        self.__load(event)

    def __load(self, event: dict):
        self.EventSource = event['EventSource']
        self.EventVersion = event['EventVersion']
        self.EventSubscriptionArn = event['EventSubscriptionArn']
        try:
            self.__EventFromSns = AwsSns(event['Sns'])
        except KeyError as err:
            self.__EventFromSns = None
            logger.warning("This CloudWatch Event is NOT from SNS %s %s", self.EventSource, self.EventSubscriptionArn)

    def getMessage(self):
        if (self.__EventFromSns):
            return self.__EventFromSns.generateMessage()
        else:
            return None

    def __str__(self):
        return "%s %s %s" % (self.EventSource,  self.EventVersion, self.EventSubscriptionArn)
