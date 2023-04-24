# -*- coding: utf-8 -*-
import sys
import uuid
import requests
import hashlib
import time
import json
from importlib import reload

import time

reload(sys)

YOUDAO_URL = 'https://openapi.youdao.com/api'
APP_KEY = '4d0555de33d90a0b'
APP_SECRET = '6i6sNWqzP6c5Uzso5omFFpapWCqVxIom'


def encrypt(signStr):
    hash_algorithm = hashlib.sha256()
    hash_algorithm.update(signStr.encode('utf-8'))
    return hash_algorithm.hexdigest()


def truncate(q):
    if q is None:
        return None
    size = len(q)
    return q if size <= 20 else q[0:10] + str(size) + q[size - 10:size]


def do_request(data):
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    return requests.post(YOUDAO_URL, data=data, headers=headers)

#####################################################################################
# 下面两个方法抄的那个 SSKJ 的插件, https://svenko.me/
def output_results(results):
    """Outputs the results in the Alfred json format."""
    return json.dumps({"items": results})


def create_alfred_item(title, subtitle=None, arg=None, quicklookurl=None):
    """Returns a dictionary with the given parameters."""
    return {
        "title": title,
        "subtitle": subtitle,
        "arg": arg,
        "quicklookurl": quicklookurl,
    }
#####################################################################################

def connect(msg):
    q = msg
    data = {}
    data['from'] = 'en'
    data['to'] = 'zh-CHS'
    data['signType'] = 'v3'
    curtime = str(int(time.time()))
    data['curtime'] = curtime
    salt = str(uuid.uuid1())
    signStr = APP_KEY + truncate(q) + salt + curtime + APP_SECRET
    sign = encrypt(signStr)
    data['appKey'] = APP_KEY
    data['q'] = q
    data['salt'] = salt
    data['sign'] = sign
    # data['vocabId'] = "您的用户词表ID"

    response = do_request(data)
    contentType = response.headers['Content-Type']

    resData = json.loads(response.content)


    res = []
    r1 = create_alfred_item(resData['translation'][0], resData['query'])
    res.append(r1)

    for d in resData['web']:
        res.append(create_alfred_item(",".join(d['value']), d['key']))

    print(output_results(res))


if __name__ == '__main__':
    query = sys.argv
    connect(query[1])