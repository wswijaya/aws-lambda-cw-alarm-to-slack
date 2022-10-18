import boto3
import json
import logging
from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class Slack:

    def __init__(self, encryptedHookURL, channelName):
        self.Channel = channelName
        self.HOOK_URL = "https://" + boto3.client('kms').decrypt(CiphertextBlob=b64decode(encryptedHookURL))['Plaintext'].decode('utf-8')
        ##self.HOOK_URL = "https://" + encryptedHookURL

    def sendMessage(self, message: str, isPreviewMode: bool = True):
        slack_message = {
            'channel': self.Channel,
            'text': message
        }

        if (isPreviewMode):
            logger.info(json.dumps(slack_message))
            return

        req = Request(self.HOOK_URL, json.dumps(slack_message).encode('utf-8'))
        try:
            response = urlopen(req)
            response.read()
            logger.info("Message posted to %s", slack_message['channel'])
        except HTTPError as e:
            logger.error("Request failed: %d %s", e.code, e.reason)
        except URLError as e:
            logger.error("Server connection failed: %s", e.reason)
