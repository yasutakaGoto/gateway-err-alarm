import boto3
import json
import logging
import os
import datetime

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# The base-64 encoded, encrypted key (CiphertextBlob) stored in the kmsEncryptedHookUrl environment variable
ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ['slackChannel']

HOOK_URL = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext'].decode('utf-8')

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    message = json.loads(event['Records'][0]['Sns']['Message'])
    date = datetime.datetime.strptime(message['StateChangeTime'][:19] ,'%Y-%m-%dT%H:%M:%S') + datetime.timedelta(hours=9)
    
    slack_message = {
        'channel': SLACK_CHANNEL,
        'text': "%sにエラーが発生しました。" % (date)
    }
    
    region = 'ap-northeast-1'
    cloudwatch = boto3.client('cloudwatch',region_name = region)
    timeto = datetime.datetime.strptime(message['StateChangeTime'][:19] ,'%Y-%m-%dT%H:%M:%S') + datetime.timedelta(minutes=1)
    timefrom = timeto - datetime.timedelta(minutes=5)
    datapoints = cloudwatch.get_metric_statistics(
                Namespace  = "AWS/ApiGateway",
                MetricName = "4XXError",
                StartTime  = timefrom,
                EndTime    = timeto,
                Period     = 300,
                Statistics = ['Sum']
            )
    logger.info(datapoints)

    req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
