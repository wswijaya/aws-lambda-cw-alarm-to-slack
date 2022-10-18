# aws-lambda-cw-alarm-to-slack
Lambda code to send CloudWatch Alarms to Slack 

### Environment Variables:
1. SLACK_CHANNEL - Slack channel name
2. KMS_ENCRYPTED_WEBHOOK_URL - Slack Webhook URL that is encrypted using KMS

### Constraints
* This lambda only takes care of Events from SNS.

