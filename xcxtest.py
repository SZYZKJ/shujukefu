from gevent import monkey
from gevent import pywsgi

monkey.patch_all()
import sys
import io
import os
import random
import json
import csv
from Crypto.Cipher import AES
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from flask import Flask, request
from flask_cors import *
import time
from base64 import b64encode
import base64
import requests
import urllib.request
import string
import hashlib
import xml.etree.ElementTree as ET
import logging

datapath = '/home/ubuntu/data/lianailianmeng/data'
wangzhi = 'https://www.xingnanzhuli.com/'
os.chdir(datapath)
app = Flask(__name__)
app.debug = True
CORS(app, supports_credentials=True)
es = Elasticsearch([{"host": "119.29.67.239", "port": 9218}])
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)
handler = logging.FileHandler("log/log.txt")
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(funcName)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
appid = 'wxa9ef833cef143ce1'
secret = '574ba86bc66b664ab42e4d60276afb7c'
mch_id = '1519367291'
merchant_key = 'shenzhenyuzikejiyouxiangongsi888'
userKeyWordHisList = {}
key = "pangyuming920318"
iv = "abcdefabcdefabcd"
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * bytes(chr(BLOCK_SIZE - len(s) % BLOCK_SIZE), encoding='utf8')
unpad = lambda s: s[0:-ord(s[-1])]
whitelist = {}
# userhiss = []
vipdengji = [0, 1, 2, 3, 4, 5, 6]
viptime = [259200, 2592000, 31536000, 31536000, 31536000, 3153600000, 3153600000]
sijiaotime = [0, 0, 0, 2592000, 7776000, 31536000, 3153600000]
total_fees = [0, 2900, 19900, 49900, 99900, 299900, 499900]
# viptime = [0, 60, 60, 60, 60, 60, 60]
# sijiaotime = [0, 60, 60, 60, 60, 60, 60]
# total_fees = [0, 1, 2, 3, 4, 5, 6]
wenzhang = ['恋爱', '挽回', '形象', '搭讪', '聊天', '约会', '异地', '相亲']
ganhuo = ['套路', '搭讪', '电影', '干货']
tuweiqinghua = []
for line in open('tuweiqinghua.json'):
    line = json.loads(line)
    tuweiqinghua.append(line['chatId'])
islianmeng = 0
issystem = 0


def dict_to_xml(dict_data):
    '''
    dict to xml
    :param dict_data:
    :return:
    '''
    xml = ["<xml>"]
    for k, v in dict_data.items():
        xml.append("<{0}>{1}</{0}>".format(k, v))
    xml.append("</xml>")
    return "".join(xml)


def xml_to_dict(xml_data):
    '''
    xml to dict
    :param xml_data:
    :return:
    '''
    xml_dict = {}
    root = ET.fromstring(xml_data)
    for child in root:
        xml_dict[child.tag] = child.text
    return xml_dict


def adduserhis(userhis):
    print(userhis)
    return None
    # es.index(index='userhis', doc_type='userhis', body=userhis)
    # global userhiss:
    # action = {
    #     "_index": "userhis",
    #     "_type": "userhis",
    #     "_source": userhis
    # }
    # userhiss.append(action)
    # if len(userhis) >= 500:
    #     helpers.bulk(es, userhiss)
    #     userhiss = []
    return None


def getTime():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def check_user(openid):
    if openid in whitelist:
        return 1
    doc = es.get(index='userinfo', doc_type='userinfo', id=openid)
    doc = doc['_source']
    if doc['viptime'] > int(time.time()):
        return 1
    elif doc['vipdengji'] > 0:
        doc['vipdengji'] = 0
        es.index(index='userinfo', doc_type='userinfo', id=openid, body=doc)
    return 0


def encrypt(encrypting):
    encrypting = bytes(encrypting, encoding='utf8')
    aes = AES.new(key, AES.MODE_CBC, iv)
    return b64encode(aes.encrypt(pad(encrypting)))


def decrypt(encrypted):
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes.decrypt(bytes.fromhex(str(encrypted)[2:-1])).decode('utf8')
    return unpad(decrypted)


def decryptweixin(encrypted, weixinkey, weixiniv):
    encrypted = base64.b64decode(encrypted)
    weixinkey = base64.b64decode(weixinkey)
    weixiniv = base64.b64decode(weixiniv)
    aes = AES.new(weixinkey, AES.MODE_CBC, weixiniv)
    decrypted = aes.decrypt(encrypted)
    return json.loads(decrypted[:-ord(decrypted[len(decrypted) - 1:])])


def addKeyword(params):
    openid = params['openid']
    inputValue = params['query']
    if openid in userKeyWordHisList:
        if len(userKeyWordHisList[openid]) == 0 or inputValue != userKeyWordHisList[openid][0]:
            flag = 1
            for index, value in enumerate(userKeyWordHisList[openid]):
                if inputValue == value:
                    flag = 0
                    userKeyWordHisList[openid] = [inputValue] + userKeyWordHisList[openid][:index] + userKeyWordHisList[
                                                                                                         openid][
                                                                                                     index + 1:]
            if flag:
                userKeyWordHisList[openid] = [inputValue] + userKeyWordHisList[openid]
                userKeyWordHisList[openid] = userKeyWordHisList[openid][:12]
    else:
        userKeyWordHisList[openid] = [inputValue]


@app.route("/test/getOpenid", methods=["POST"])
def getOpenid():
    try:
        params = json.loads(decrypt(request.stream.read()))
        js_code = params['jsCode']
        userInfo = params['userInfo']
        system = params['system']
        options = params['options']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    url = 'https://api.weixin.qq.com/sns/jscode2session?appid=' + appid + '&secret=' + secret + '&js_code=' + js_code + '&grant_type=authorization_code'
    response = requests.get(url)
    response = response.json()
    userInfo['openid'] = response['openid']
    userInfo['system'] = system
    try:
        doc = es.get(index='userinfo', doc_type='userinfo', id=response['openid'])
        newdoc = doc['_source']
        newdoc.update(userInfo)
        es.index(index='userinfo', doc_type='userinfo', id=userInfo['openid'], body=newdoc)
    except Exception as e:
        logger.error(e)
        userInfo['addtime'] = time.strftime("%Y%m%d", time.localtime())
        userInfo['vipdengji'] = 0
        userInfo['viptime'] = int(time.time()) + viptime[0]
        userInfo['sijiaotime'] = 0
        userInfo['xiaofeicishu'] = 0
        userInfo['xiaofeizonge'] = 0
        userInfo['options'] = json.loads(options)
        es.index(index='userinfo', doc_type='userinfo', id=userInfo['openid'], body=userInfo)
    # print(decryptweixin(params['encryptedData'], response['session_key'], params['iv'])['unionId'])
    adduserhis(
        {'openid': response['openid'], 'time': getTime(), 'event': 'getOpenid', 'detail': 'getOpenid', 'type': '0'})
    return encrypt(json.dumps({'MSG': 'OK', 'data': {'openid': response['openid']}}))


@app.route("/test/checkOpenid", methods=["POST"])
def checkOpenid():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        userInfo = params['userInfo']
        system = params['system']
    except Exception as e:
        logger.error(e)
        return encrypt(json.dumps({'MSG': 'NO'}))
    try:
        doc = es.get(index='userinfo', doc_type='userinfo', id=openid)
        newdoc = doc['_source']
        newdoc.update(userInfo)
        newdoc['system'] = system
        es.index(index='userinfo', doc_type='userinfo', id=openid, body=newdoc)
        return encrypt(json.dumps({'MSG': 'YES'}))
    except Exception as e:
        logger.error(e)
        return encrypt(json.dumps({'MSG': 'NO'}))


@app.route("/test/searchHuashu", methods=["POST"])
def searchHuashu():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        query = params['query']
        scroll = params['scroll']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    check_user_res = check_user(openid)
    if check_user_res == 0:
        return encrypt(json.dumps({'MSG': 'LIMIT'}))
    addKeyword(params)
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'searchHuashu', 'detail': query, 'type': '0'})
    retdata = []
    search = {'query': {'match': {'MM': query}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='huashu', doc_type='huashu', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='huashu', doc_type='huashu', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/searchGuanli", methods=["POST"])
def searchGuanli():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        query = params['query']
        scroll = params['scroll']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    check_user_res = check_user(openid)
    if check_user_res == 0:
        return encrypt(json.dumps({'MSG': 'LIMIT'}))
    addKeyword(params)
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'searchGuanli', 'detail': query, 'type': '0'})
    retdata = []
    search = {'query': {'bool': {'should': [{'match': {'title': query}}, {'match': {'content': query}}]}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='guanli', doc_type='guanli', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='guanli', doc_type='guanli', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/searchBiaoqing", methods=["POST"])
def searchBiaoqing():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        query = params['query']
        scroll = params['scroll']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    check_user_res = check_user(openid)
    if check_user_res == 0:
        return encrypt(json.dumps({'MSG': 'LIMIT'}))
    addKeyword(params)
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'searchBiaoqing', 'detail': query, 'type': '0'})
    retdata = []
    search = {'query': {'match': {'imgExplain': query}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='biaoqing', doc_type='biaoqing', body=search, size=15, scroll="5m")

    else:
        Docs = es.search(index='biaoqing', doc_type='biaoqing', body=search, size=15, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source']['url'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/getMethodologyList", methods=["POST"])
def getMethodologyList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        cid = params['cid']
        scroll = params['scroll']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    check_user_res = check_user(openid)
    if check_user_res == 0 and scroll != '':
        return encrypt(json.dumps({'MSG': 'LIMIT'}))
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'getMethodologyList', 'detail': cid, 'type': '0'})
    retdata = []
    search = {'query': {'bool': {'filter': {"term": {'cid': cid}}}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='methodology', doc_type='methodology', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='methodology', doc_type='methodology', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/getHiswordList", methods=["POST"])
def getHiswordList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    if openid in userKeyWordHisList:
        return encrypt(json.dumps({'MSG': 'OK', 'data': userKeyWordHisList[openid]}))
    else:
        userKeyWordHisList[openid] = []
        return encrypt(json.dumps({'MSG': 'OK', 'data': []}))


@app.route("/test/clearHiswords", methods=["POST"])
def clearHiswords():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis({'openid': response['openid'], 'time': getTime(), 'event': 'clearHiswords', 'type': '0'})
    userKeyWordHisList[openid] = []
    return encrypt(json.dumps({'MSG': 'OK'}))


@app.route("/test/getRecommend", methods=["POST"])
def getRecommend():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    hotWords = ['自恋', '厉害', '睡觉', '生气', '干嘛', '烦', '哈哈', '好吧', '介绍', '丑', '表白', '呵呵']
    hotMethods = ['开场白', '赞美', '拉升关系', '高价值展示', '幽默搞笑', '冷读', '推拉', '角色扮演', '框架', '打压', '进挪', '背景植入']
    return encrypt(json.dumps({'MSG': 'OK', 'data': {'hotWordsList': hotWords, 'hotMethodsList': hotMethods}}))


@app.route("/test/getWenzhangList", methods=["POST"])
def getWenzhangList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        scroll = params['scroll']
        tab = int(params['tab'])
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'getWenzhangList', 'detail': wenzhang[tab], 'type': '0'})
    retdata = []
    search = {'query': {
        'bool': {'filter': [{"term": {'topic': wenzhang[tab][0]}}, {"term": {'topic': wenzhang[tab][1]}}]}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='wenzhang', doc_type='wenzhang', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='wenzhang', doc_type='wenzhang', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/getGanhuoList", methods=["POST"])
def getGanhuoList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        scroll = params['scroll']
        tab = int(params['tab'])
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'getGanhuoList', 'detail': ganhuo[tab], 'type': '0'})
    retdata = []
    search = {'query': {
        'bool': {'filter': [{"term": {'topic': ganhuo[tab][0]}}, {"term": {'topic': ganhuo[tab][1]}}]}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='ganhuo', doc_type='ganhuo', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='ganhuo', doc_type='ganhuo', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/getXingxiangjiansheList", methods=["POST"])
def getXingxiangjiansheList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        scroll = params['scroll']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis(
        {'openid': openid, 'time': getTime(), 'event': 'getXingxiangjiansheList', 'detail': 'getXingxiangjiansheList',
         'type': '0'})
    retdata = []
    search = {"query": {"match_all": {}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='xingxiangjianshe', doc_type='xingxiangjianshe', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='xingxiangjianshe', doc_type='xingxiangjianshe', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/getLiaomeishizhanList", methods=["POST"])
def getLiaomeishizhanList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        scroll = params['scroll']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis(
        {'openid': openid, 'time': getTime(), 'event': 'getLiaomeishizhanList', 'detail': 'getLiaomeishizhanList',
         'type': '0'})
    retdata = []
    search = {"query": {"match_all": {}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='liaomeishizhan', doc_type='liaomeishizhan', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='liaomeishizhan', doc_type='liaomeishizhan', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/searchWenzhangList", methods=["POST"])
def searchWenzhangList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        scroll = params['scroll']
        query = params['query']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'searchWenzhangList', 'detail': query, 'type': '0'})
    retdata = []
    search = {'query': {'match': {'title': query}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='wenzhang', doc_type='wenzhang', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='wenzhang', doc_type='wenzhang', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/searchGanhuoList", methods=["POST"])
def searchGanhuoList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        scroll = params['scroll']
        query = params['query']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'searchGanhuoList', 'detail': query, 'type': '0'})
    retdata = []
    search = {'query': {'match': {'title': query}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='ganhuo', doc_type='ganhuo', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='ganhuo', doc_type='ganhuo', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/getTuweiqinghuaList", methods=["POST"])
def getTuweiqinghuaList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        scroll = params['scroll']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'getTuweiqinghuaList', 'detail': 'getTuweiqinghuaList',
                'type': '0'})
    retdata = []
    search = {"query": {"match_all": {}}}
    if scroll:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="5m")
        except:
            Docs = es.search(index='tuweiqinghua', doc_type='tuweiqinghua', body=search, size=10, scroll="5m")

    else:
        Docs = es.search(index='tuweiqinghua', doc_type='tuweiqinghua', body=search, size=10, scroll="5m")
    scroll = Docs['_scroll_id']
    Docs = Docs['hits']['hits']
    for doc in Docs:
        retdata.append(doc['_source'])
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata, 'scroll': scroll}))


@app.route("/test/getTuweiqinghua", methods=["POST"])
def getTuweiqinghua():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis(
        {'openid': openid, 'time': getTime(), 'event': 'getTuweiqinghua', 'detail': 'getTuweiqinghua', 'type': '0'})
    tuweiqinghuaid = tuweiqinghua[random.randint(0, len(tuweiqinghua) - 1)]
    doc = es.get(index='tuweiqinghua', doc_type='tuweiqinghua', id=tuweiqinghuaid)
    return encrypt(json.dumps({'MSG': 'OK', 'data': doc['_source']}))


@app.route("/test/getPhoneNumber", methods=["POST"])
def getPhoneNumber():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        js_code = params['jsCode']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    url = 'https://api.weixin.qq.com/sns/jscode2session?appid=' + appid + '&secret=' + secret + '&js_code=' + js_code + '&grant_type=authorization_code'
    response = requests.get(url)
    response = response.json()
    userphone = decryptweixin(params['encryptedData'], response['session_key'], params['iv'])
    userphone.pop('watermark')
    doc = es.get(index='userinfo', doc_type='userinfo', id=openid)
    userphone.update(doc['_source'])
    es.index(index='userinfo', doc_type='userinfo', id=openid, body=userphone)
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'getPhoneNumber', 'detail': 'getPhoneNumber',
                'type': '0'})
    return encrypt(json.dumps({'MSG': 'OK', 'data': {'openid': response['openid']}}))


@app.route("/test/get_prepay_id", methods=["POST"])
def get_prepay_id():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        zhifutype = int(params['zhifutype'])
        detail = params['detail']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    doc = es.get(index='userinfo', doc_type='userinfo', id=openid)
    doc = doc['_source']
    if 'phoneNumber' not in doc:
        return encrypt(json.dumps({'MSG': 'nophoneNumber'}))
    url = 'https://api.mch.weixin.qq.com/pay/unifiedorder'
    prepaydata = {
        'appid': appid,
        'mch_id': mch_id,
        'nonce_str': ''.join(random.sample(string.ascii_letters + string.digits, 32)),
        'body': detail,
        'attach': json.dumps({'zhifutype': zhifutype, 'detail': detail}),
        'out_trade_no': str(int(time.time())) + '_' + str((random.randint(1000000, 9999999))),
        'total_fee': total_fees[zhifutype],
        'spbill_create_ip': request.remote_addr,
        'notify_url': "https://www.lianaizhuli.com/api/paynotify",
        'trade_type': "JSAPI",
        'openid': openid,
    }
    stringA = '&'.join(["{0}={1}".format(k, prepaydata.get(k)) for k in sorted(prepaydata)])
    stringSignTemp = '{0}&key={1}'.format(stringA, merchant_key)
    sign = hashlib.md5(stringSignTemp.encode('utf8')).hexdigest()
    prepaydata['sign'] = sign
    req = urllib.request.Request(url, dict_to_xml(prepaydata).encode('utf8'),
                                 headers={'Content-Type': 'application/xml'})
    result = urllib.request.urlopen(req, timeout=10).read().decode('utf8')
    result = xml_to_dict(result)
    prepay_id = result['prepay_id']
    paySign_data = {
        'appId': appid,
        'timeStamp': str(int(time.time())),
        'nonceStr': result['nonce_str'],
        'package': 'prepay_id={0}'.format(prepay_id),
        'signType': 'MD5'
    }
    stringA = '&'.join(["{0}={1}".format(k, paySign_data.get(k)) for k in sorted(paySign_data)])
    stringSignTemp = '{0}&key={1}'.format(stringA, merchant_key)
    paySign = hashlib.md5(stringSignTemp.encode('utf8')).hexdigest()
    paySign_data['paySign'] = paySign
    paySign_data.pop('appId')
    return encrypt(json.dumps({'MSG': 'OK', 'data': paySign_data}))


@app.route("/test/paynotify", methods=["POST"])
def paynotify():
    zhifures = xml_to_dict(request.stream.read().decode('utf8'))
    sign = zhifures['sign']
    zhifures.pop('sign')
    stringA = '&'.join(["{0}={1}".format(k, zhifures.get(k)) for k in sorted(zhifures)])
    stringSignTemp = '{0}&key={1}'.format(stringA, merchant_key)
    paySign = hashlib.md5(stringSignTemp.encode('utf8')).hexdigest().upper()
    if sign != paySign:
        return dict_to_xml({'return_code': 'FAIL', 'return_msg': 'SIGNERROR'})
    zhifudata = [zhifures]
    isnew = 1
    flag = 1
    try:
        doc = es.get(index='userzhifu', doc_type='userzhifu', id=zhifures['openid'])
        isnew = 0
        for line in doc['_source']['zhifudata']:
            if line['transaction_id'] == zhifudata[0]['transaction_id']:
                flag = 0
        if flag:
            zhifudata += doc['_source']['zhifudata']
    except Exception as e:
        logger.error(e)
    if isnew or (isnew == 0 and flag == 1):
        es.index(index='userzhifu', doc_type='userzhifu', id=zhifures['openid'],
                 body={'openid': zhifures['openid'], 'zhifudata': zhifudata, 'updatatime': zhifures['time_end']})
        try:
            zhifutype = int(json.loads(zhifures['attach'])['zhifutype'])
            doc = es.get(index='userinfo', doc_type='userinfo', id=zhifures['openid'])
            newdoc = doc['_source']
            if newdoc['vipdengji'] < zhifutype:
                newdoc['vipdengji'] = zhifutype
            if newdoc['viptime'] < int(time.time()):
                newdoc['viptime'] = int(time.time()) + viptime[zhifutype]
            else:
                newdoc['viptime'] += viptime[zhifutype]
            if newdoc['sijiaotime'] < int(time.time()):
                newdoc['sijiaotime'] = int(time.time()) + sijiaotime[zhifutype]
            else:
                newdoc['sijiaotime'] += sijiaotime[zhifutype]
            newdoc['xiaofeicishu'] += 1
            newdoc['xiaofeizonge'] += int(zhifures['total_fee'])
            es.index(index='userinfo', doc_type='userinfo', id=zhifures['openid'], body=newdoc)
        except Exception as e:
            logger.error(e)
    return dict_to_xml({'return_code': 'SUCCESS', 'return_msg': 'OK'})


@app.route("/test/getTequan", methods=["POST"])
def getTequan():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    doc = es.get(index='userinfo', doc_type='userinfo', id=openid)
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'getTequan', 'detail': 'getTequan',
                'type': '0'})
    return encrypt(json.dumps({'MSG': 'OK', 'vipdengji': doc['_source']['vipdengji'],
                               'viptime': time.strftime("%Y-%m-%d %H:%M:%S",
                                                        time.localtime(doc['_source']['viptime']))}))


@app.route("/test/getJifen", methods=["POST"])
def getJifen():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        iszhudong = params['iszhudong']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    doc = es.get(index='userinfo', doc_type='userinfo', id=openid)
    if iszhudong == "1":
        adduserhis({'openid': openid, 'time': getTime(), 'event': 'getJifen', 'detail': 'getJifen',
                    'type': '0'})
    return encrypt(json.dumps({'MSG': 'OK', 'data': {'vipdengji': doc['_source']['vipdengji'],
                                                     'jifen': int(doc['_source']['xiaofeizonge'] * 0.01)}}))


@app.route("/test/getDingdan", methods=["POST"])
def getDingdan():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'getDingdan', 'detail': 'getDingdan',
                'type': '0'})
    try:
        doc = es.get(index='userzhifu', doc_type='userzhifu', id=openid)
        retdata = doc['_source']['zhifudata']
        for i in range(len(retdata)):
            retdata[i]['attach'] = json.loads(retdata[i]['attach'])
            retdata[i]['time_end'] = retdata[i]['time_end'][:4] + '-' + retdata[i]['time_end'][4:6] + '-' + retdata[i][
                                                                                                                'time_end'][
                                                                                                            6:8] + ' ' + \
                                     retdata[i]['time_end'][8:10] + ':' + retdata[i]['time_end'][10:12] + ':' + \
                                     retdata[i]['time_end'][-2:]
        return encrypt(json.dumps({'MSG': 'OK', 'data': retdata}))
    except:
        return encrypt(json.dumps({'MSG': 'OK', 'data': []}))


@app.route("/test/getIslianmeng", methods=["POST"])
def getIslianmeng():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'getIslianmeng', 'detail': 'getIslianmeng',
                'type': '0'})
    doc = es.get(index='userinfo', doc_type='userinfo', id=openid)
    doc = doc['_source']
    if doc['system'][:3].lower() == 'ios':
        if doc['viptime'] > int(time.time()) and doc['vipdengji'] > 1:
            return encrypt(json.dumps({'MSG': 'OK', 'issystem': issystem, 'islianmeng': 1}))
        else:
            return encrypt(json.dumps({'MSG': 'OK', 'issystem': issystem, 'islianmeng': islianmeng}))
    else:
        if doc['viptime'] > int(time.time()) and doc['vipdengji'] > 1:
            return encrypt(json.dumps({'MSG': 'OK', 'issystem': 1, 'islianmeng': 1}))
        else:
            return encrypt(json.dumps({'MSG': 'OK', 'issystem': 1, 'islianmeng': islianmeng}))


@app.route("/api/setJilu", methods=["POST"])
def setJilu():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        jilutype = params['jilutype']
        jilucontent = params['jilucontent']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    query = ''
    if 'query' in params:
        query = params['query']
    if jilutype == 'html':
        htmlid = jilucontent.split('/')[-1].split('.')[0]
        doc = es.get(index='wenzhang', doc_type='wenzhang', id=htmlid)
        doc = doc['_source']
        doc['views'] += 1
        es.index(index='wenzhang', doc_type='wenzhang', id=htmlid, body=doc)
    if jilutype == 'ganhuo':
        htmlid = jilucontent.split('/')[-1].split('.')[0]
        doc = es.get(index='ganhuo', doc_type='ganhuo', id=htmlid)
        doc = doc['_source']
        doc['views'] += 1
        es.index(index='ganhuo', doc_type='ganhuo', id=htmlid, body=doc)
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'setJilu', 'detail': query, 'jilutype': jilutype,
                'jilucontent': jilucontent,
                'type': '0'})
    return encrypt(json.dumps({'MSG': 'OK'}))


@app.route("/test/getShouye", methods=["POST"])
def getShouye():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    adduserhis({'openid': openid, 'time': getTime(), 'event': 'getShouye', 'detail': 'getShouye',
                'type': '0'})
    return encrypt(json.dumps({'MSG': 'OK', 'lunbotu': [
        {'title': '新用户', 'adurl': wangzhi + 'shouye/lunbotu/xinyonghu.png',
         'type': 'html', 'url': 'https://mp.weixin.qq.com/s/CQqCd6tQ0Tv2AvE_-6aclQ'},
        # {'title': '小程序使用介绍', 'adurl': 'https://www.lianaizhuli.com/shouye/shiyongjieshaobanner.jpg',
        #  'type': 'ganhuo', 'url': 'cloud://lianailianmeng-086596.6c69-lianailianmeng-086596/shouye/shiyongjieshao.mp4',
        #  'duration': '04:04', 'direction': '0'},
        # {'title': '恋爱联盟招聘',
        #  'adurl': 'https://www.lianaizhuli.com/shouye/zhaopinbanner.jpg',
        #  'type': 'image', 'url': 'cloud://lianailianmeng-086596.6c69-lianailianmeng-086596/shouye/zhaopin1.jpg'},
        # {'title': '迷男方法第一步', 'adurl': 'https://www.lianaizhuli.com/shouye/diyibu.jpg',
        #  'type': 'html', 'url': 'https://mp.weixin.qq.com/s/6ouchJC7qurRuwe6MbIxbA'},
        # {'title': '迷男方法第二步', 'adurl': 'https://www.lianaizhuli.com/shouye/dierbu.jpg',
        #  'type': 'html', 'url': 'https://mp.weixin.qq.com/s/-3eouLbbREZFUHGxiJ6NHA'},
        # {'title': '迷男方法第三步', 'adurl': 'https://www.lianaizhuli.com/shouye/disanbu.jpg',
        #  'type': 'html', 'url': 'https://mp.weixin.qq.com/s/qnYR4DiOtmvcLcbfAVmuUA'},
    ],
                               'tubiao': [{'title': '课程精选', 'image': wangzhi + 'shouye/tubiao/kechengjingxuan.png',
                                           'page': 'kecheng'},
                                          {'title': '土味情话', 'image': wangzhi + 'shouye/tubiao/tuweiqinghua.png',
                                           'page': 'twqh'},
                                          {'title': '撩妹套路', 'image': wangzhi + 'shouye/tubiao/liaomeitaolu.png',
                                           'page': 'lmtl'},
                                          {'title': '情感百科', 'image': wangzhi + 'shouye/tubiao/qingganbaike.png',
                                           'page': 'qingganbaike'}, ],
                               'searchicon': wangzhi + 'shouye/search.png',
                               'miaoshu': '复制女生聊天的话搜索获得最佳回复，轻轻一点即可复制',
                               'gengduoicon': wangzhi + 'shouye/gengduo.png',
                               'kecheng': {'image': wangzhi + 'shouye/wenzi/kecheng.png', 'gengduo': '更多', 'data': [
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/kecheng1.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/kecheng2.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/kecheng3.png',
                                    'num': 12345},]},
                               'xingxiangjianshe': {'image': wangzhi + 'shouye/wenzi/xingxiangjianshe.png', 'gengduo': '更多', 'data': [
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/xingxiangjianshe1.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/xingxiangjianshe2.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/xingxiangjianshe3.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/xingxiangjianshe4.png',
                                    'num': 12345}, ]},
                               'qingganbaike': {'image': wangzhi + 'shouye/wenzi/qingganbaike.png', 'gengduo': '更多', 'data': [
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/qingganbaike1.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/qingganbaike2.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/qingganbaike3.png',
                                    'num': 12345}, ]},
                               'liaomeishizhan': {'image': wangzhi + 'shouye/wenzi/liaomeishizhan.png', 'gengduo': '更多', 'data': [
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/liaomeishizhan1.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/liaomeishizhan2.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/liaomeishizhan3.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/liaomeishizhan4.png',
                                    'num': 12345}, ]},
                               'sijiao': {'image': wangzhi + 'shouye/wenzi/sijiao.png', 'gengduo': '更多', 'data': [
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/sijiao1.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/sijiao2.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/sijiao3.png',
                                    'num': 12345}, ]},
                               'xinliceshi': {'image': wangzhi + 'shouye/wenzi/xinliceshi.png', 'gengduo': '更多', 'data': [
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/xinliceshi1.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/xinliceshi2.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/xinliceshi3.png',
                                    'num': 12345},
                                   {'title': '打造让女生着迷的朋友圈', 'image': wangzhi + 'shouye/images/xinliceshi4.png',
                                    'num': 12345}, ]},
                               }))


if __name__ == "__main__":
    server = pywsgi.WSGIServer(('127.0.0.1', 18888), app)
    server.serve_forever()
