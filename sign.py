#!/usr/bin/env python

import binascii
import hashlib
import hmac


def makePlainText(requestMethod, requestHost, requestPath, params):
    str_params = "&".join(k + "=" + str(params[k]) for k in sorted(params.keys()))

    source = '%s%s%s?%s' % (
        requestMethod.upper(),
        requestHost,
        requestPath,
        str_params
    )
    return source

#     requestMethod = 'GET'
#     requestHost = 'vpc.tencentcloudapi.com'
#     requestPath = '/index.php'
#     params = {
#         'Action': 'CreateSecurityGroupPolicies',
#         'Version': '2017-03-12',
#         'SecurityGroupId': 'sg-19cf54rb',
#         'SecurityGroupPolicySet.Ingress.0.PolicyIndex': '0',
#         'SecurityGroupPolicySet.Ingress.0.Action': 'DROP',
#         'SecurityGroupPolicySet.Ingress.0.Protocol': 'ALL',
#         'SecurityGroupPolicySet.Ingress.0.CidrBlock': ip_str,
#         'SecurityGroupPolicySet.Ingress.0.PolicyDescription': 'deny_send_sms',
#         'Nonce': 422311, # random.randint(100000, 999999)
#         'Region': 'ap-beijing',
#         'SecretId': secretId,
#         'Timestamp': 1534231304, #  int(time.time())
#     }
def sign(requestMethod, requestHost, requestPath, params, secretKey):
    source = makePlainText(requestMethod, requestHost, requestPath, params)
    hashed = hmac.new(secretKey, source, hashlib.sha1)
    return binascii.b2a_base64(hashed.digest())[:-1]
