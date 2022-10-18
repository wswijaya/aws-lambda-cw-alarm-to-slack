import os
import json
import logging
from aws_cloudwatch import AwsCloudWatchEvent
from slack import Slack

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """

    :param event:
    :param context:
    :return:
    """
    logger.info("Event: " + str(event))
    cwEvent = AwsCloudWatchEvent(event['Records'][0])
    msg = cwEvent.getMessage()
    if (msg):
        try:
            channelName = os.environ['SLACK_CHANNEL']
            ENCRYPTED_HOOK_URL = os.environ['KMS_ENCRYPTED_WEBHOOK_URL']
            slackClient = Slack(ENCRYPTED_HOOK_URL, channelName)
            slackClient.sendMessage(msg, isPreviewMode=True)
        except KeyError as err:
            logger.error("Unable to load ENV variables: {0} ".format(err))
    else:
        logger.info("No Message Sent!")
