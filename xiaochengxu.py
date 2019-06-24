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
from urllib import parse
import string
import hashlib
from WXBizMsgCrypt import WXBizMsgCrypt
from flask_sockets import Sockets
from geventwebsocket.handler import WebSocketHandler
from gevent.pywsgi import WSGIServer

app = Flask(__name__)
sockets = Sockets(app)
CORS(app, supports_credentials=True)
es = Elasticsearch([{"host": "119.29.67.239", "port": 9218, "timeout": 3600}])
chenggonges = Elasticsearch([{"host": "182.254.227.188", "port": 9218, "timeout": 3600}])
histype = {'searchHuashu': 0, 'searchGuanli': 0, 'searchBiaoqing': 0, 'getMethodologyList': 0, 'setJilu': 0,
           'getTuweiqinghua': 0, }
key = "pangyuming920318"
iv = "abcdefabcdefabcd"
appid = 'wxa9ef833cef143ce1'
token = 'lianailianmeng'
secret = '574ba86bc66b664ab42e4d60276afb7c'
EncodingAESKey = "zo84lZOejrVKHTyoe5D18QNHCWothe0FovOxIubrnKj"
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * bytes(chr(BLOCK_SIZE - len(s) % BLOCK_SIZE), encoding='utf8')
unpad = lambda s: s[0:-ord(s[-1])]
datapath = '/home/ubuntu/data/lianailianmeng/data'
os.chdir(datapath)

hisdata = {}
newhisdata = {}
f = open('shujuzhongxin.json')
for line in f:
    hisdata = json.loads(line)
    newhisdata = json.loads(line)
f.close()

constws = {}
sendws = {}
MsgId = {}


def getTime():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


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


@app.route("/test/xiaFashuruzhuangtai", methods=["POST"])
def xiaFashuruzhuangtai():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        command = params['command']
    except Exception as e:
        print(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    url = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=' + appid + '&secret=' + secret
    reponse = urllib.request.Request(url=url)
    html = urllib.request.urlopen(reponse).read().decode('utf-8')
    access_token = json.loads(html)['access_token']
    url = 'https://api.weixin.qq.com/cgi-bin/message/custom/typing?access_token=' + access_token
    values = {
        "touser": openid,
        "command": command
    }
    data = json.dumps(values).encode('utf8')
    reponse = urllib.request.Request(url=url, data=data, method='POST')
    html = urllib.request.urlopen(reponse).read().decode('utf-8')
    return encrypt(html)


def faSongwenhouyu(openid):
    textvalue = "您好，我是恋爱联盟客服薇薇，很高兴为您服务。"
    url = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=' + appid + '&secret=' + secret
    reponse = urllib.request.Request(url=url)
    html = urllib.request.urlopen(reponse).read().decode('utf-8')
    access_token = json.loads(html)['access_token']
    url = 'https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=' + access_token
    values = {
        "touser": openid,
        "msgtype": "text",
        "text": {
            "content": textvalue
        }
    }
    data = json.dumps(values, ensure_ascii=False).encode('utf8')
    reponse = urllib.request.Request(url=url, data=data, method='POST')
    html = urllib.request.urlopen(reponse).read().decode('utf-8')
    html = json.loads(html)
    content = {
        "Content": textvalue,
        "ToUserName": "gh_95cc82b21cba",
        "person": 1,
        "MsgType": "text",
        "MsgId": int(str(int(time.time())) + str(random.randint(100000000, 999999999))),
        "FromUserName": openid,
        "CreateTime": int(time.time())
    }
    if html['errcode'] == 0:
        try:
            doc = es.get(index='kefu', doc_type='kefu', id=openid)
            doc = doc['_source']
            doc['datalist'].append(content)
            doc['updatatime'] = getTime()
            doc['unread'] += 1
            doc['zuijin'] = textvalue
            es.index(index='kefu', doc_type='kefu', id=openid, body=doc)
        except Exception as e:
            doc = {}
            doc['openid'] = openid
            doc['updatatime'] = getTime()
            user = es.get(index='userinfo', doc_type='userinfo', id=openid)['_source']
            doc['avatarUrl'] = user['avatarUrl']
            doc['nickName'] = user['nickName']
            doc['datalist'] = [content]
            doc['unread'] = 1
            doc['zuijin'] = textvalue
            es.index(index='kefu', doc_type='kefu', id=openid, body=doc)
        getKefuList('')


@app.route("/test/faSongtext", methods=["POST"])
def faSongtext():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
        textvalue = params['textvalue']
    except Exception as e:
        print(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    url = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=' + appid + '&secret=' + secret
    reponse = urllib.request.Request(url=url)
    html = urllib.request.urlopen(reponse).read().decode('utf-8')
    access_token = json.loads(html)['access_token']
    url = 'https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=' + access_token
    values = {
        "touser": openid,
        "msgtype": "text",
        "text": {
            "content": textvalue
        }
    }
    data = json.dumps(values, ensure_ascii=False).encode('utf8')
    reponse = urllib.request.Request(url=url, data=data, method='POST')
    html = urllib.request.urlopen(reponse).read().decode('utf-8')
    html = json.loads(html)
    content = {
        "Content": textvalue,
        "ToUserName": "gh_95cc82b21cba",
        "person": 1,
        "MsgType": "text",
        "MsgId": int(str(int(time.time())) + str(random.randint(100000000, 999999999))),
        "FromUserName": openid,
        "CreateTime": int(time.time())
    }
    if html['errcode'] == 0:
        try:
            doc = es.get(index='kefu', doc_type='kefu', id=openid)
            doc = doc['_source']
            doc['datalist'].append(content)
            doc['updatatime'] = getTime()
            doc['unread'] = 0
            doc['zuijin'] = textvalue
            es.index(index='kefu', doc_type='kefu', id=openid, body=doc)
        except Exception as e:
            doc = {}
            doc['openid'] = openid
            doc['updatatime'] = getTime()
            user = es.get(index='userinfo', doc_type='userinfo', id=openid)['_source']
            doc['avatarUrl'] = user['avatarUrl']
            doc['nickName'] = user['nickName']
            doc['datalist'] = [content]
            doc['unread'] = 0
            doc['zuijin'] = textvalue
            es.index(index='kefu', doc_type='kefu', id=openid, body=doc)
        getKefuList(openid)
    return encrypt(json.dumps(html))


@app.route("/test/upUnread", methods=["POST"])
def upUnread():
    try:
        params = json.loads(decrypt(request.stream.read()))
        openid = params['openid']
    except Exception as e:
        print(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    doc = es.get(index='kefu', doc_type='kefu', id=openid)
    doc = doc['_source']
    doc['unread'] = 0
    es.index(index='kefu', doc_type='kefu', id=openid, body=doc)
    getKefuList('')
    return encrypt(json.dumps({'MSG': 'OK'}))


@sockets.route('/test/getKefuList', methods=['POST'])
def getKefuList(ws):
    global constws, sendws
    if type(ws) == type(""):
        time.sleep(1)
        if ws!='':
            doc = es.get(index='kefu', doc_type='kefu', id=ws)['_source']
            newconstws = constws.copy()
            for newws in newconstws:
                if constws[newws] == ws:
                    try:
                        sendws[newws].send(
                        encrypt(json.dumps({'MSG': 0, 'openid': ws, 'data': doc})).decode('utf8'))
                    except Exception as e:
                        print(e)
                        constws.pop(newws)
                        sendws.pop(newws)
        nowtime = time.strftime("%Y-%m", time.localtime())
        body = {"query": {"match_phrase_prefix": {"updatatime": nowtime}}}
        Docs = es.search(index='kefu', doc_type='kefu', body=body, size=10000)
        Docs = Docs['hits']['hits']
        retdata = []
        for doc in Docs:
            doc['_source']['updatatime'] = doc['_source']['updatatime'][5:16]
            retdata.append(doc['_source'])
        newconstws = constws.copy()
        try:
            for newws in newconstws:
                if not sendws[newws].closed:
                    if constws[newws] == '':
                        try:
                            sendws[newws].send(
                            encrypt(json.dumps({'MSG': 1, 'openid': '', 'data': retdata})).decode('utf8'))
                        except Exception as e:
                            print(e)
                            constws.pop(newws)
                            sendws.pop(newws)
                else:
                    constws.pop(newws)
                    sendws.pop(newws)
        except Exception as e:
            print(e)
    while type(ws) != type(""):
        if ws.closed:
            break
        time.sleep(1)
        try:
            a = ws.receive()
            print(a)
            if a:
                params = json.loads(decrypt(a.encode('utf8')))
                openid = params['openid']
                constws[str(ws)] = openid
                sendws[str(ws)] = ws
                if openid == '':
                    nowtime = time.strftime("%Y-%m", time.localtime())
                    body = {"query": {"match_phrase_prefix": {"updatatime": nowtime}}}
                    Docs = es.search(index='kefu', doc_type='kefu', body=body, size=10000)
                    Docs = Docs['hits']['hits']
                    retdata = []
                    for doc in Docs:
                        doc['_source']['updatatime'] = doc['_source']['updatatime'][5:16]
                        retdata.append(doc['_source'])
                    ws.send(encrypt(json.dumps({'MSG': 1, 'openid': '', 'data': retdata})).decode('utf8'))
                else:
                    ws.send(encrypt(json.dumps({'MSG': 2})).decode('utf8'))
        except Exception as e:
            print(e)


@app.route("/test/kefutuisong", methods=["GET", "POST"])
def kefutuisong():
    global MsgId
    if request.method == "GET":
        signature = request.args.get('signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        echostr = request.args.get('echostr')
        data = [token, timestamp, nonce]
        data.sort()
        newstring = data[0] + data[1] + data[2]
        sha1 = hashlib.sha1()
        sha1.update(newstring.encode())
        hashcode = sha1.hexdigest()
        if hashcode == signature:
            return echostr
    else:
        aaaa = json.loads(request.stream.read().decode('utf8'))
        timestamp = request.values.get('timestamp')
        nonce = request.values.get('nonce')
        msg_signature = request.values.get('msg_signature')
        encrypt_decrypt = WXBizMsgCrypt(token, EncodingAESKey, appid)
        (ret, content) = encrypt_decrypt.DecryptMsg(aaaa['Encrypt'], msg_signature, timestamp, nonce)
        content = json.loads(content.decode('utf8'))
        if 'MsgId' in content:
            if content['MsgId'] in MsgId:
                return "SUCCESS"
            if len(MsgId) >= 9999:
                MsgId = {}
            MsgId[content['MsgId']] = 0
        content['person'] = 0
        print(content)
        if content['MsgType'] != 'event':
            try:
                doc = es.get(index='kefu', doc_type='kefu', id=content['FromUserName'])
                doc = doc['_source']
                doc['datalist'].append(content)
                doc['updatatime'] = getTime()
                doc['unread'] += 1
                if content['MsgType'] == 'image':
                    doc['zuijin'] = '[图片]'
                else:
                    doc['zuijin'] = content['Content']
                es.index(index='kefu', doc_type='kefu', id=content['FromUserName'], body=doc)
            except Exception as e:
                doc = {}
                doc['openid'] = content['FromUserName']
                doc['updatatime'] = getTime()
                user = es.get(index='userinfo', doc_type='userinfo', id=content['FromUserName'])['_source']
                doc['avatarUrl'] = user['avatarUrl']
                doc['nickName'] = user['nickName']
                doc['datalist'] = [content]
                doc['unread'] = 1
                if content['MsgType'] == 'image':
                    doc['zuijin'] = '[图片]'
                else:
                    doc['zuijin'] = content['Content']
                es.index(index='kefu', doc_type='kefu', id=content['FromUserName'], body=doc)
            getKefuList(content['FromUserName'])
        elif content['Event'] == 'user_enter_tempsession':
            if (content['FromUserName'] + str(content['CreateTime'])) in MsgId:
                return "SUCCESS"
            if len(MsgId) >= 9999:
                MsgId = {}
            MsgId[content['FromUserName'] + str(content['CreateTime'])] = 0
            faSongwenhouyu(content['FromUserName'])
        return "SUCCESS"


@app.route("/test/getChengGong", methods=["POST"])
def getChengGong():
    try:
        params = json.loads(decrypt(request.stream.read()))
        yidingchenggong = params['yidingchenggong']
    except Exception as e:
        print(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    global hisdata, newhisdata
    jintian = time.strftime("%Y%m%d", time.localtime())
    if (jintian != hisdata['jintian']):
        searchtian = {"query": {"match_phrase_prefix": {"addtime": hisdata['jintian']}}}
        Docs = es.search(index='userinfo', doc_type='userinfo', body=searchtian, size=1000, scroll="1m")
        scroll = Docs['_scroll_id']
        jintianyonghushu = len(Docs['hits']['hits'])
        jintianfufeiyonghushu = 0
        jintianfufeicishu = 0
        jintianfufeizonge = 0
        while 1:
            try:
                Docs = es.scroll(scroll_id=scroll, scroll="1m")
                if (len(Docs['hits']['hits']) == 0):
                    break
                scroll = Docs['_scroll_id']
                jintianyonghushu += len(Docs['hits']['hits'])
            except:
                break
        searchtian = {"query": {"match_phrase_prefix": {"updatatime": hisdata['jintian']}}}
        Docs = es.search(index='userzhifu', doc_type='userzhifu', body=searchtian, size=1000, scroll="1m")
        scroll = Docs['_scroll_id']
        for doc in Docs['hits']['hits']:
            doc = doc['_source']
            if (len(doc['zhifudata']) == 1): jintianfufeiyonghushu += 1
            for zhifudata in doc['zhifudata']:
                if hisdata['jintian'] == zhifudata['time_end'][:8]:
                    jintianfufeicishu += 1
                    jintianfufeizonge += int(int(zhifudata['total_fee']) * 0.01)
        while 1:
            try:
                Docs = es.scroll(scroll_id=scroll, scroll="1m")
                if (len(Docs['hits']['hits']) == 0):
                    break
                scroll = Docs['_scroll_id']
                for doc in Docs['hits']['hits']:
                    doc = doc['_source']
                    if (len(doc['zhifudata']) == 1): jintianfufeiyonghushu += 1
                    for zhifudata in doc['zhifudata']:
                        if hisdata['jintian'] == zhifudata['time_end'][:8]:
                            jintianfufeicishu += 1
                            jintianfufeizonge += int(int(zhifudata['total_fee']) * 0.01)
            except:
                break
        newhisdata['zuotianyonghushu'] = jintianyonghushu
        newhisdata['zuotianfufeicishu'] = jintianfufeicishu
        newhisdata['zuotianfufeizonge'] = jintianfufeizonge
        if (jintian[:6] != hisdata['jintian'][:6]):
            newhisdata['dangyueyonghushu'] = 0
            newhisdata['dangyuefufeicishu'] = 0
            newhisdata['dangyuefufeizonge'] = 0
        else:
            newhisdata['dangyueyonghushu'] = hisdata['dangyueyonghushu'] + jintianyonghushu
            newhisdata['dangyuefufeicishu'] = hisdata['dangyuefufeicishu'] + jintianfufeicishu
            newhisdata['dangyuefufeizonge'] = hisdata['dangyuefufeizonge'] + jintianfufeizonge
        newhisdata['zongyonghushu'] = hisdata['zongyonghushu'] + jintianyonghushu
        newhisdata['zongfufeiyonghushu'] = hisdata['zongfufeiyonghushu'] + jintianfufeiyonghushu
        newhisdata['zongfufeicishu'] = hisdata['zongfufeicishu'] + jintianfufeicishu
        newhisdata['zongfufeie'] = hisdata['zongfufeie'] + jintianfufeizonge
        newhisdata['jintian'] = jintian
        f = open('shujuzhongxin.json', 'w')
        f.write(json.dumps(newhisdata) + '\n')
        f.close()
        hisdata = newhisdata.copy()
    searchtian = {"query": {"match_phrase_prefix": {"addtime": jintian}}}
    Docs = es.search(index='userinfo', doc_type='userinfo', body=searchtian, size=1000, scroll="1m")
    scroll = Docs['_scroll_id']
    jintianyonghushu = len(Docs['hits']['hits'])
    jintianfufeiyonghushu = 0
    jintianfufeicishu = 0
    jintianfufeizonge = 0
    while 1:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="1m")
            if (len(Docs['hits']['hits']) == 0):
                break
            scroll = Docs['_scroll_id']
            jintianyonghushu += len(Docs['hits']['hits'])
        except:
            break
    searchtian = {"query": {"match_phrase_prefix": {"updatatime": jintian}}}
    Docs = es.search(index='userzhifu', doc_type='userzhifu', body=searchtian, size=1000, scroll="1m")
    scroll = Docs['_scroll_id']
    for doc in Docs['hits']['hits']:
        doc = doc['_source']
        if (len(doc['zhifudata']) == 1): jintianfufeiyonghushu += 1
        for zhifudata in doc['zhifudata']:
            if jintian == zhifudata['time_end'][:8]:
                jintianfufeicishu += 1
                jintianfufeizonge += int(int(zhifudata['total_fee']) * 0.01)
    while 1:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="1m")
            if (len(Docs['hits']['hits']) == 0):
                break
            scroll = Docs['_scroll_id']
            for doc in Docs['hits']['hits']:
                doc = doc['_source']
                if (len(doc['zhifudata']) == 1): jintianfufeiyonghushu += 1
                for zhifudata in doc['zhifudata']:
                    if jintian == zhifudata['time_end'][:8]:
                        jintianfufeicishu += 1
                        jintianfufeizonge += int(int(zhifudata['total_fee']) * 0.01)
        except:
            break
    newhisdata = hisdata.copy()
    newhisdata['zongyonghushu'] = hisdata['zongyonghushu'] + jintianyonghushu
    newhisdata['zongfufeiyonghushu'] = hisdata['zongfufeiyonghushu'] + jintianfufeiyonghushu
    newhisdata['zongfufeicishu'] = hisdata['zongfufeicishu'] + jintianfufeicishu
    newhisdata['zongfufeie'] = hisdata['zongfufeie'] + jintianfufeizonge
    newhisdata['jintianyonghushu'] = jintianyonghushu
    newhisdata['jintianfufeicishu'] = jintianfufeicishu
    newhisdata['jintianfufeizonge'] = jintianfufeizonge
    newhisdata['dangyueyonghushu'] = hisdata['dangyueyonghushu'] + jintianyonghushu
    newhisdata['dangyuefufeicishu'] = hisdata['dangyuefufeicishu'] + jintianfufeicishu
    newhisdata['dangyuefufeizonge'] = hisdata['dangyuefufeizonge'] + jintianfufeizonge
    body = {"query": {"bool": {"filter": [{"term": {"vipdengji": 1}}, ]}}}
    Docs = es.search(index='userinfo', doc_type='userinfo', body=body, size=1000, scroll="1m")
    scroll = Docs['_scroll_id']
    newhisdata['xiantiyan'] = len(Docs['hits']['hits'])
    while 1:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="1m")
            if (len(Docs['hits']['hits']) == 0):
                break
            scroll = Docs['_scroll_id']
            newhisdata['xiantiyan'] += len(Docs['hits']['hits'])
        except:
            break
    body = {"query": {"bool": {"filter": [{"term": {"vipdengji": 2}}, ]}}}
    Docs = es.search(index='userinfo', doc_type='userinfo', body=body, size=1000, scroll="1m")
    scroll = Docs['_scroll_id']
    newhisdata['xianyuehuiyuan'] = len(Docs['hits']['hits'])
    while 1:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="1m")
            if (len(Docs['hits']['hits']) == 0):
                break
            scroll = Docs['_scroll_id']
            newhisdata['xianyuehuiyuan'] += len(Docs['hits']['hits'])
        except:
            break
    body = {"query": {"bool": {"filter": [{"term": {"vipdengji": 3}}, ]}}}
    Docs = es.search(index='userinfo', doc_type='userinfo', body=body, size=1000, scroll="1m")
    scroll = Docs['_scroll_id']
    newhisdata['xiannianhuiyuan'] = len(Docs['hits']['hits'])
    while 1:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="1m")
            if (len(Docs['hits']['hits']) == 0):
                break
            scroll = Docs['_scroll_id']
            newhisdata['xiannianhuiyuan'] += len(Docs['hits']['hits'])
        except:
            break
    body = {"query": {"bool": {"filter": [{"term": {"vipdengji": 4}}, ]}}}
    Docs = es.search(index='userinfo', doc_type='userinfo', body=body, size=1000, scroll="1m")
    scroll = Docs['_scroll_id']
    newhisdata['xiansijiaosangeyue'] = len(Docs['hits']['hits'])
    while 1:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="1m")
            if (len(Docs['hits']['hits']) == 0):
                break
            scroll = Docs['_scroll_id']
            newhisdata['xiansijiaosangeyue'] += len(Docs['hits']['hits'])
        except:
            break
    body = {"query": {"bool": {"filter": [{"term": {"vipdengji": 5}}, ]}}}
    Docs = es.search(index='userinfo', doc_type='userinfo', body=body, size=1000, scroll="1m")
    scroll = Docs['_scroll_id']
    newhisdata['xiansijiaoyinian'] = len(Docs['hits']['hits'])
    while 1:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="1m")
            if (len(Docs['hits']['hits']) == 0):
                break
            scroll = Docs['_scroll_id']
            newhisdata['xiansijiaoyinian'] += len(Docs['hits']['hits'])
        except:
            break
    body = {"query": {"bool": {"filter": [{"term": {"vipdengji": 6}}, ]}}}
    Docs = es.search(index='userinfo', doc_type='userinfo', body=body, size=1000, scroll="1m")
    scroll = Docs['_scroll_id']
    newhisdata['xianlianmenghuiyuan'] = len(Docs['hits']['hits'])
    while 1:
        try:
            Docs = es.scroll(scroll_id=scroll, scroll="1m")
            if (len(Docs['hits']['hits']) == 0):
                break
            scroll = Docs['_scroll_id']
            newhisdata['xianlianmenghuiyuan'] += len(Docs['hits']['hits'])
        except:
            break

    return encrypt(json.dumps({'MSG': 'OK', 'data': newhisdata}))


@app.route("/test/getXiangqing", methods=["POST"])
def getXiangqing():
    try:
        params = json.loads(decrypt(request.stream.read()))
        yidingchenggong = params['yidingchenggong']
    except Exception as e:
        print(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    nowtime = time.strftime("%Y-%m-%d", time.localtime())
    body = {"query": {"match_phrase_prefix": {"time": nowtime}}}
    retdata = {}
    renshu = {}
    huashurenshu = {}
    huashucishu = 0
    guanlirenshu = {}
    guanlicishu = 0
    biaoqingrenshu = {}
    biaoqingcishu = 0
    shouyeguanlirenshu = {}
    shouyeguanlicishu = 0
    tuweiqinghuarenshu = {}
    tuweiqinghuacishu = 0
    wenzhangrenshu = {}
    wenzhangcishu = 0
    shipinrenshu = {}
    shipincishu = 0
    Docs = chenggonges.search(index='userhis', doc_type='userhis', body=body, size=1000, scroll="1m")
    scroll = Docs['_scroll_id']
    allDocs = []
    allDocs += Docs['hits']['hits']
    while 1:
        try:
            Docs = chenggonges.scroll(scroll_id=scroll, scroll="1m")
            if (len(Docs['hits']['hits']) == 0):
                break
            scroll = Docs['_scroll_id']
            allDocs += Docs['hits']['hits']
        except:
            break
    for line in allDocs:
        line = line['_source']
        if line['event'] in histype:
            renshu[line['openid']] = 0
        if line['event'] == 'searchHuashu':
            huashurenshu[line['openid']] = 0
            huashucishu += 1
        if line['event'] == 'searchGuanli':
            guanlirenshu[line['openid']] = 0
            guanlicishu += 1
        if line['event'] == 'searchBiaoqing':
            biaoqingrenshu[line['openid']] = 0
            biaoqingcishu += 1
        if line['event'] == 'getMethodologyList':
            shouyeguanlirenshu[line['openid']] = 0
            shouyeguanlicishu += 1
        if line['event'] == 'getTuweiqinghua':
            tuweiqinghuarenshu[line['openid']] = 0
            tuweiqinghuacishu += 1
        if line['event'] == 'setJilu':
            if line['jilutype'] == 'html':
                wenzhangrenshu[line['openid']] = 0
                wenzhangcishu += 1
            if line['jilutype'] == 'ganhuo':
                shipinrenshu[line['openid']] = 0
                shipincishu += 1
    retdata['renshu'] = len(renshu)
    retdata[
        'cishu'] = huashucishu + guanlicishu + biaoqingcishu + shouyeguanlicishu + tuweiqinghuacishu + wenzhangcishu + shipincishu
    retdata['huashurenshu'] = len(huashurenshu)
    retdata['huashucishu'] = huashucishu
    retdata['guanlirenshu'] = len(guanlirenshu)
    retdata['guanlicishu'] = guanlicishu
    retdata['biaoqingrenshu'] = len(biaoqingrenshu)
    retdata['biaoqingcishu'] = biaoqingcishu
    retdata['shouyeguanlirenshu'] = len(shouyeguanlirenshu)
    retdata['shouyeguanlicishu'] = shouyeguanlicishu
    retdata['tuweiqinghuarenshu'] = len(tuweiqinghuarenshu)
    retdata['tuweiqinghuacishu'] = tuweiqinghuacishu
    retdata['wenzhangrenshu'] = len(wenzhangrenshu)
    retdata['wenzhangcishu'] = wenzhangcishu
    retdata['shipinrenshu'] = len(shipinrenshu)
    retdata['shipincishu'] = shipincishu
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata}))


@app.route("/test/jinpushequ/getAdList", methods=["POST"])
def getAdList():
    url = "https://mp.weixin.qq.com/s/m-xA4OfbGE_cEfnF3408qw"
    retdata = [{'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/gundong/shijiuda.jpg',
                'type': 'html', 'url': url}
        , {'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/gundong/60zhounian.jpg',
           'type': 'html', 'url': url},
               {'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/gundong/1.jpg',
                'type': 'html', 'url': url},
               {'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/gundong/2.jpg',
                'type': 'html', 'url': url},
               {'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/gundong/3.jpg',
                'type': 'html', 'url': url}
        , ]
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata}))


@app.route("/test/jinpushequ/getTubiaoList", methods=["POST"])
def getTubiaoList():
    retdata = [{'title': '社区公告', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/tubiao/1.png'},
               {'title': '社区新闻', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/tubiao/2.png'},
               {'title': '社区党建', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/tubiao/3.png'},
               {'title': '办事指南', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/tubiao/4.png'},
               {'title': '社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/tubiao/5.png'},
               {'title': '两委班子', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/tubiao/6.png'},
               {'title': '精神文明', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/tubiao/7.png'},
               {'title': '社区广场', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/tubiao/8.png'},
               ]
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata}))


@app.route("/api/jinpushequ/getFcList", methods=["POST"])
def getFcList():
    url = "https://mp.weixin.qq.com/s/m-xA4OfbGE_cEfnF3408qw"
    retdata = [{'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/jingdian/1.jpg',
                'type': 'html', 'url': url}
        , {'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/jingdian/2.jpg',
           'type': 'html', 'url': url},
               {'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/jingdian/3.jpg',
                'type': 'html', 'url': url},
               {'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/jingdian/4.jpg',
                'type': 'html', 'url': url},
               {'title': '金浦社区简介', 'adurl': 'cloud://yuzikeji-f7d32f.7975-yuzikeji-f7d32f/jingdian/5.jpg',
                'type': 'html', 'url': url}
        , ]
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata}))


@app.route("/test/jinpushequ/getWenzhangList", methods=["POST"])
def getWenzhangList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        inputValue = params['inputValue']
    except Exception as e:
        print(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    retdata = []
    if inputValue == "":
        search = {"query": {"match_all": {}}}
    else:
        search = {'query': {'match': {'title': inputValue}}}
    Docs = es.search(index='jinpushequ', doc_type='jinpushequ', body=search, size=1000)
    Docs = Docs['hits']['hits']
    for doc in Docs:
        newdata = doc['_source']
        newdata.pop('intro')
        newdata.pop('content')
        retdata.append(newdata)
    if inputValue == "":
        retdata.sort(key=lambda x: x['updated_time'], reverse=True)
    return encrypt(json.dumps({'MSG': 'OK', 'data': retdata}))


@app.route("/test/jinpushequ/getWenzhang", methods=["POST"])
def getWenzhang():
    try:
        params = json.loads(decrypt(request.stream.read()))
        id = params['id']
    except Exception as e:
        print(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    doc = es.get(index='jinpushequ', doc_type='jinpushequ', id=id)
    doc = doc['_source']
    doc['read_num'] += 1
    es.index(index='jinpushequ', doc_type='jinpushequ', id=id, body=doc)
    return encrypt(json.dumps({'MSG': 'OK', 'data': doc}))


if __name__ == "__main__":
    # server = pywsgi.WSGIServer(('127.0.0.1', 16888), app)
    # server.serve_forever()
    http_serve = WSGIServer(("127.0.0.1", 18888), app, handler_class=WebSocketHandler)
    http_serve.serve_forever()
