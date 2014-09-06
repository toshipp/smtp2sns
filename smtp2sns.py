#!/usr/bin/env python2

from argparse import ArgumentParser
import asyncore, hashlib, hmac, urllib, httplib, logging
from datetime import datetime
from smtpd import SMTPServer
import email

HOST = 'sns.ap-northeast-1.amazonaws.com'
REGION = 'ap-northeast-1'
SERVICE = 'sns'
REQUIRED_HEADRES = {'host', 'x-amz-date'}
AMZ_DTFORMAT = '%Y%m%dT%H%M%SZ'

def sign(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

def make_auth(method, headers, payload, access_key, secret_key):
    req_headers = {}
    for k, v in headers.iteritems():
        k = k.lower()
        if k in REQUIRED_HEADRES:
            req_headers[k] = v
    if len(req_headers) != len(REQUIRED_HEADRES):
        raise RuntimeError('Required headers {} but given {}'.format(REQUIRED_HEADRES, headers))
    amz_date = req_headers['x-amz-date']
    amz_ts = amz_date[:8]

    canonical_uri = '/'
    canonical_querystring = ''
    canonical_headers = ''.join('{}:{}\n'.format(k, v) for k, v in req_headers.iteritems())
    signed_headers = ';'.join(REQUIRED_HEADRES)
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_request = '\n'.join([method, canonical_uri, canonical_querystring,  canonical_headers, signed_headers, payload_hash])
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = '/'.join([amz_ts, REGION, SERVICE, 'aws4_request'])
    string_to_sign = '\n'.join([algorithm, amz_date, credential_scope, hashlib.sha256(canonical_request).hexdigest()])
    signing_key = getSignatureKey(secret_key, amz_ts, REGION, SERVICE)
    signature = hmac.new(signing_key, string_to_sign, hashlib.sha256).hexdigest()
    authorization_header = '{algorithm} Credential={access_key}/{credential_scope},SignedHeaders={signed_headers},Signature={signature}'.format(
        algorithm=algorithm, access_key=access_key, credential_scope=credential_scope, signed_headers=signed_headers, signature=signature)
    return authorization_header

def send_sns(host, message, topicarn, access_key, secret_key, subject=None):
    sns_params = {}
    sns_params['Action'] = 'Publish'
    sns_params['Version'] = '2010-03-31'
    sns_params['TopicArn'] = topicarn
    sns_params['Message'] = message
    if subject is not None:
        sns_params['Subject'] = subject
    payload = urllib.urlencode(sns_params)

    now = datetime.utcnow()
    amz_date = now.strftime(AMZ_DTFORMAT)
    headers = {}
    headers['host'] = host
    headers['x-amz-date'] = amz_date
    auth_header_value = make_auth('POST', headers, payload, access_key, secret_key)
    headers['authorization'] = auth_header_value
    headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'

    # sending
    conn = httplib.HTTPSConnection(host)
    conn.request('POST', '/', payload, headers)
    res = conn.getresponse()
    if res.status != 200:
        raise RuntimeError('Can not send message: {} {}\n{}'.format(
            res.status, res.reason, res.read()))

class SNSProxy(SMTPServer):
    def __init__(self, localaddr, access_key, secret_key, topic):
        SMTPServer.__init__(self, localaddr, '')
        self._access_key = access_key
        self._secret_key = secret_key
        self._topic = topic

    def process_message(self, peer, mailfrom, rcpttos, data):
        try:
            msg = email.message_from_string(data)
            msg_body = msg.get_payload()
            send_sns(HOST, msg_body, self._topic, self._access_key, self._secret_key, msg['subject'])
        except:
            logging.exception('error on sending message from {}'.format(mailfrom))
            return '451 Error'

def main():
    logging.basicConfig()
    parser = ArgumentParser()
    parser.add_argument('--bind', default='localhost')
    parser.add_argument('--port', default=25, type=int)
    parser.add_argument('--access-key', required=True)
    parser.add_argument('--secret-key', required=True)
    parser.add_argument('--topic-arn', required=True)
    args = parser.parse_args()

    proxy = SNSProxy((args.bind, args.port),
                     args.access_key,
                     args.secret_key,
                     args.topic_arn)
    asyncore.loop()

if __name__ == '__main__':
    main()
