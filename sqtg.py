from gevent import monkey
from gevent import pywsgi

monkey.patch_all()
import sys
import io
import os
import re
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
import pymongo
import hashlib
import xml.etree.ElementTree as ET
import logging
from PIL import Image, ImageDraw, ImageFont
from basic import Basic
from io import BytesIO

datapath = '/home/ubuntu/data/lianailianmeng/data'
wangzhi = 'https://www.lianaizhuli.com/'
os.chdir(datapath)
app = Flask(__name__)
app.debug = True
CORS(app, supports_credentials=True)
es = Elasticsearch([{"host": "119.29.67.239", "port": 9218}])
myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["tiantian"]
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
vipdengji = [0, 1, 2, 3, 4, 5, 6]
viptime = [259200, 2592000, 31536000, 31536000, 31536000, 3153600000, 3153600000]
sijiaotime = [0, 0, 0, 2592000, 7776000, 31536000, 3153600000]
total_fees = [0, 2900, 19900, 49900, 99900, 299900, 499900]
userKeyWordHisList = {}
key = "testtesttesttest"
iv = "1234123412341234"
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * bytes(chr(BLOCK_SIZE - len(s) % BLOCK_SIZE), encoding='utf8')
unpad = lambda s: s[0:-ord(s[-1])]


@app.route("/sqtg/getShouyekuai", methods=["POST"])
def getShouyekuai():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    return encrypt(json.dumps({'MSG': 'OK', 'lunbotu': [
        {'title': '新用户', 'adurl': 'https://tswe.dudumatou.com/MinaApi_MT/images/headimg/e1.jpg',
         'type': 'html', 'url': 'https://mp.weixin.qq.com/s/2-StlZoGKA-rpcQN-QrlUg'},
        {'title': '新用户', 'adurl': 'https://tswe.dudumatou.com/MinaApi_MT/images/headimg/e2.jpg',
         'type': 'html', 'url': 'https://mp.weixin.qq.com/s/2-StlZoGKA-rpcQN-QrlUg'},
    ],
                               'tubiao': [{'title': '肉禽蛋类', 'image': '../static/rouqindanlei.png',
                                           'page': 'fenlei'},
                                          {'title': '时令水果', 'image': '../static/shilingshuiguo.png',
                                           'page': 'fenlei'},
                                          {'title': '海鲜水产', 'image': '../static/haixianshuichan.png',
                                           'page': 'fenlei'},
                                          {'title': '粮油速食', 'image': '../static/liangyousushi.png',
                                           'page': 'fenlei'},
                                          {'title': '纸品清洁', 'image': '../static/zhipinqingjie.png',
                                           'page': 'fenlei'},
                                          ],
                               'searchicon': '../static/search.png',
                               }))


@app.route("/sqtg/getShouyeman", methods=["POST"])
def getShouyeman():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
        scroll = params['scroll']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    retdata = []
    mycol = mydb["goods"]
    results = mycol.find().skip(scroll * 10).limit(10)
    for doc in results:
        retdata.append(doc)
    timetime = time.time()
    starttime = time.strftime("%m月%d日", time.localtime(timetime))
    endtime = time.strftime("%m月%d日", time.localtime(timetime + 86400))
    return encrypt(
        json.dumps({'MSG': 'OK', 'tuangoulist': retdata, 'scroll': scroll, 'starttime': starttime, 'endtime': endtime}))


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


def getTime():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def check_user(unionid):
    if unionid in whitelist:
        return 1
    doc = es.get(index='userinfo', doc_type='userinfo', id=unionid)
    doc = doc['_source']
    if doc['viptime'] > int(time.time()):
        return 1
    elif doc['vipdengji'] > 0:
        doc['vipdengji'] = 0
        es.index(index='userinfo', doc_type='userinfo', id=unionid, body=doc)
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
    retdata = json.loads(decrypted[:-ord(decrypted[len(decrypted) - 1:])].decode('utf8'))
    return retdata


def addKeyword(params):
    unionid = params['unionid']
    inputValue = params['query']
    if unionid in userKeyWordHisList:
        if len(userKeyWordHisList[unionid]) == 0 or inputValue != userKeyWordHisList[unionid][0]:
            flag = 1
            for index, value in enumerate(userKeyWordHisList[unionid]):
                if inputValue == value:
                    flag = 0
                    userKeyWordHisList[unionid] = [inputValue] + userKeyWordHisList[unionid][:index] + \
                                                  userKeyWordHisList[
                                                      unionid][
                                                  index + 1:]
            if flag:
                userKeyWordHisList[unionid] = [inputValue] + userKeyWordHisList[unionid]
                userKeyWordHisList[unionid] = userKeyWordHisList[unionid][:12]
    else:
        userKeyWordHisList[unionid] = [inputValue]


@app.route("/sqtg/getUnionid", methods=["POST"])
def getUnionid():
    try:
        params = json.loads(decrypt(request.stream.read()))
        js_code = params['js_code']
        userinfo = params['userinfo']
        encryptedData = params['encryptedData']
        jiemiiv = params['jiemiiv']
        options = params['options']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    url = 'https://api.weixin.qq.com/sns/jscode2session?appid=' + appid + '&secret=' + secret + '&js_code=' + js_code + '&grant_type=authorization_code'
    response = requests.get(url)
    response = response.json()
    if 'openid' in response:
        openid = response['openid']
    elif 'openId' in response:
        openid = response['openId']
    if 'unionid' in response:
        unionid = response['unionid']
    elif 'unionId' in response:
        unionid = response['unionId']
    else:
        try:
            session_key = response['session_key']
            jiemidata = decryptweixin(encryptedData, session_key, jiemiiv)
            if 'unionId' in jiemidata:
                unionid = jiemidata['unionId']
            elif 'unionid' in jiemidata:
                unionid = jiemidata['unionid']
        except Exception as e:
            logger.error(e)
            unionid = openid
    if 'openid' not in userinfo:
        userinfo['openid'] = openid
    if openid != unionid:
        userinfo['unionid'] = unionid
    try:
        uniondoc = es.get(index='userinfo', doc_type='userinfo', id=unionid)['_source']
        uniondoc.update(userinfo)
        userinfo = uniondoc
    except Exception as e:
        None
    if 'addtime' not in userinfo:
        userinfo['addtime'] = getTime()
        userinfo['vipdengji'] = 0
        userinfo['viptime'] = int(time.time()) + viptime[0]
        userinfo['xiaofeicishu'] = 0
        userinfo['xiaofeizonge'] = 0
    if 'options' not in userinfo:
        userinfo['options'] = options
    es.index(index='userinfo', doc_type='userinfo', id=unionid, body=userinfo)
    return encrypt(json.dumps({'MSG': 'OK', 'data': {'unionid': unionid}}))


@app.route("/sqtg/checkUnionid", methods=["POST"])
def checkUnionid():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
        userinfo = params['userinfo']
    except Exception as e:
        logger.error(e)
        return encrypt(json.dumps({'MSG': 'NO'}))
    try:
        doc = es.get(index='userinfo', doc_type='userinfo', id=unionid)
        newdoc = doc['_source']
        newdoc.update(userinfo)
        es.index(index='userinfo', doc_type='userinfo', id=unionid, body=newdoc)
        if 'unionid' in newdoc and 'openid' in newdoc:
            return encrypt(json.dumps({'MSG': 'YES'}))
        else:
            return encrypt(json.dumps({'MSG': 'NO'}))
    except Exception as e:
        logger.error(e)
        return encrypt(json.dumps({'MSG': 'NO'}))


@app.route("/sqtg/getHiswordList", methods=["POST"])
def getHiswordList():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    if unionid in userKeyWordHisList:
        return encrypt(json.dumps({'MSG': 'OK', 'data': userKeyWordHisList[unionid]}))
    else:
        userKeyWordHisList[unionid] = []
        return encrypt(json.dumps({'MSG': 'OK', 'data': []}))


@app.route("/sqtg/clearHiswords", methods=["POST"])
def clearHiswords():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    userKeyWordHisList[unionid] = []
    return encrypt(json.dumps({'MSG': 'OK'}))


@app.route("/sqtg/getRecommend", methods=["POST"])
def getRecommend():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    hotWords = ['自恋', '厉害', '睡觉', '生气', '干嘛', '烦', '哈哈', '好吧', '介绍', '丑', '表白', '呵呵', '开场白', '赞美', '拉升关系', '高价值展示',
                '幽默搞笑', '冷读', '推拉', '角色扮演', '框架', '打压', '进挪', '背景植入']
    return encrypt(json.dumps({'MSG': 'OK', 'data': {'hotWordsList': hotWords}}))


@app.route("/sqtg/getPhoneNumber", methods=["POST"])
def getPhoneNumber():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
        js_code = params['jsCode']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    url = 'https://api.weixin.qq.com/sns/jscode2session?appid=' + appid + '&secret=' + secret + '&js_code=' + js_code + '&grant_type=authorization_code'
    response = requests.get(url)
    response = response.json()
    userphone = decryptweixin(params['encryptedData'], response['session_key'], params['iv'])
    userphone.pop('watermark')
    doc = es.get(index='userinfo', doc_type='userinfo', id=unionid)
    userphone.update(doc['_source'])
    es.index(index='userinfo', doc_type='userinfo', id=unionid, body=userphone)
    return encrypt(json.dumps({'MSG': 'OK', 'data': {'unionid': response['unionid']}}))


@app.route("/sqtg/get_prepay_id", methods=["POST"])
def get_prepay_id():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
        zhifutype = int(params['zhifutype'])
        detail = params['detail']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    openid = es.get(index='userinfo', doc_type='userinfo', id=unionid)['_source']['openid']
    url = 'https://api.mch.weixin.qq.com/pay/unifiedorder'
    prepaydata = {
        'appid': appid,
        'mch_id': mch_id,
        'nonce_str': ''.join(random.sample(string.ascii_letters + string.digits, 32)),
        'body': detail,
        'attach': json.dumps({'zhifutype': zhifutype, 'detail': detail, 'unionid': unionid}, ensure_ascii=False),
        'out_trade_no': str(int(time.time())) + '_' + str((random.randint(1000000, 9999999))),
        'total_fee': total_fees[zhifutype],
        'spbill_create_ip': request.remote_addr,
        'notify_url': wangzhi + "xcx/paynotify",
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
    doc = es.get(index='userinfo', doc_type='userinfo', id=unionid)
    doc = doc['_source']
    if 'phoneNumber' not in doc:
        return encrypt(json.dumps({'MSG': 'nophoneNumber', 'data': paySign_data}))
    return encrypt(json.dumps({'MSG': 'OK', 'data': paySign_data}))


@app.route("/sqtg/paynotify", methods=["POST"])
def paynotify():
    zhifures = xml_to_dict(request.stream.read().decode('utf8'))
    sign = zhifures['sign']
    zhifures.pop('sign')
    stringA = '&'.join(["{0}={1}".format(k, zhifures.get(k)) for k in sorted(zhifures)])
    stringSignTemp = '{0}&key={1}'.format(stringA, merchant_key)
    paySign = hashlib.md5(stringSignTemp.encode('utf8')).hexdigest().upper()
    if sign != paySign:
        return dict_to_xml({'return_code': 'FAIL', 'return_msg': 'SIGNERROR'})
    unionid = json.loads(zhifures['attach'])['unionid']
    zhifudata = [zhifures]
    isnew = 1
    flag = 1
    try:
        doc = es.get(index='userzhifu', doc_type='userzhifu', id=unionid)
        isnew = 0
        for line in doc['_source']['zhifudata']:
            if line['transaction_id'] == zhifudata[0]['transaction_id']:
                flag = 0
        if flag:
            zhifudata += doc['_source']['zhifudata']
    except Exception as e:
        logger.error(e)
    if isnew or (isnew == 0 and flag == 1):
        es.index(index='userzhifu', doc_type='userzhifu', id=unionid,
                 body={'unionid': unionid, 'zhifudata': zhifudata, 'updatatime': zhifures['time_end']})
        doc = es.get(index='userinfo', doc_type='userinfo', id=unionid)
        userdoc = doc['_source']
        zhifures['total_fee'] = int(zhifures['total_fee'])
        try:
            zhifutype = int(json.loads(zhifures['attach'])['zhifutype'])
            if userdoc['vipdengji'] < zhifutype:
                userdoc['vipdengji'] = zhifutype
            if userdoc['viptime'] < int(time.time()):
                userdoc['viptime'] = int(time.time()) + viptime[zhifutype]
            else:
                userdoc['viptime'] += viptime[zhifutype]
            if userdoc['sijiaotime'] < int(time.time()):
                userdoc['sijiaotime'] = int(time.time()) + sijiaotime[zhifutype]
            else:
                userdoc['sijiaotime'] += sijiaotime[zhifutype]
            userdoc['xiaofeicishu'] += 1
            userdoc['xiaofeizonge'] += zhifures['total_fee']
            es.index(index='userinfo', doc_type='userinfo', id=unionid, body=userdoc)
        except Exception as e:
            logger.error(e)
        try:
            newdoc = es.get(index='fenxiao', doc_type='fenxiao', id=unionid)['_source']
            shangji = newdoc['shangji']
            shangshangji = newdoc['shangshangji']
            if shangji != '':
                try:
                    fenxiao = es.get(index='fenxiao', doc_type='fenxiao', id=shangji)['_source']
                    yijibili = 0.1
                    if len(fenxiao['yijiyonghu']) >= 30:
                        yijibili = 0.4
                    elif len(fenxiao['yijiyonghu']) >= 10:
                        yijibili = 0.3
                    elif len(fenxiao['yijiyonghu']) >= 3:
                        yijibili = 0.2
                    newzhifu = {}
                    newzhifu['yonghuming'] = userdoc['nickName']
                    newzhifu['shangpinming'] = json.loads(zhifures['attach'])['detail']
                    newzhifu['time'] = getTime()
                    newzhifu['total_fee'] = zhifures['total_fee'] * 0.01
                    newzhifu['shouyi'] = zhifures['total_fee'] * 0.00994 * yijibili
                    fenxiao['dingdan'].insert(0, newzhifu)
                    fenxiao['zongshouyi'] += zhifures['total_fee'] * 0.00994 * yijibili
                    fenxiao['ketixian'] += zhifures['total_fee'] * 0.00994 * yijibili
                    es.index(index='fenxiao', doc_type='fenxiao', id=shangji, body=fenxiao)
                except:
                    None
            if shangshangji != '':
                try:
                    fenxiao = es.get(index='fenxiao', doc_type='fenxiao', id=shangshangji)['_source']
                    yijibili = 0.04
                    if len(fenxiao['yijiyonghu']) >= 30:
                        yijibili = 0.1
                    elif len(fenxiao['yijiyonghu']) >= 10:
                        yijibili = 0.08
                    elif len(fenxiao['yijiyonghu']) >= 3:
                        yijibili = 0.06
                    newzhifu = {}
                    newzhifu['yonghuming'] = userdoc['nickName']
                    newzhifu['shangpinming'] = json.loads(zhifures['attach'])['detail']
                    newzhifu['time'] = getTime()
                    newzhifu['total_fee'] = zhifures['total_fee'] * 0.01
                    newzhifu['shouyi'] = zhifures['total_fee'] * 0.00994 * yijibili
                    fenxiao['dingdan'].insert(0, newzhifu)
                    fenxiao['zongshouyi'] += zhifures['total_fee'] * 0.00994 * yijibili
                    fenxiao['ketixian'] += zhifures['total_fee'] * 0.00994 * yijibili
                    es.index(index='fenxiao', doc_type='fenxiao', id=shangshangji, body=fenxiao)
                except:
                    None
        except:
            None
    return dict_to_xml({'return_code': 'SUCCESS', 'return_msg': 'OK'})


@app.route("/sqtg/getJifen", methods=["POST"])
def getJifen():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
        iszhudong = params['iszhudong']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    doc = es.get(index='userinfo', doc_type='userinfo', id=unionid)
    return encrypt(json.dumps({'MSG': 'OK', 'data': {'vipdengji': doc['_source']['vipdengji'],
                                                     'jifen': int(doc['_source']['xiaofeizonge'] * 0.01),
                                                     'wenhouyu': 'HI，欢迎您~'}}))


@app.route("/sqtg/getDingdan", methods=["POST"])
def getDingdan():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    try:
        try:
            openid = es.get(index='userinfo', doc_type='userinfo', id=unionid)['_source']['openid']
            copydoc = es.get(index='userzhifu', doc_type='userzhifu', id=openid)['_source']
            try:
                nowdoc = es.get(index='userzhifu', doc_type='userzhifu', id=unionid)['_source']
                nowdoc['zhifudata'] += copydoc['zhifudata']
                copydoc = nowdoc
            except:
                None
            es.index(index='userzhifu', doc_type='userzhifu', id=unionid, body=copydoc)
            es.delete(index='userzhifu', doc_type='userzhifu', id=openid)
        except:
            None
        doc = es.get(index='userzhifu', doc_type='userzhifu', id=unionid)
        retdata = doc['_source']['zhifudata']
        for i in range(len(retdata)):
            retdata[i]['attach'] = json.loads(retdata[i]['attach'])
            if 'openid' in retdata[i]['attach']:
                retdata[i]['attach'].pop('openid')
            if 'unionid' in retdata[i]['attach']:
                retdata[i]['attach'].pop('unionid')
            retdata[i]['time_end'] = retdata[i]['time_end'][:4] + '-' + retdata[i]['time_end'][4:6] + '-' + retdata[i][
                                                                                                                'time_end'][
                                                                                                            6:8] + ' ' + \
                                     retdata[i]['time_end'][8:10] + ':' + retdata[i]['time_end'][10:12] + ':' + \
                                     retdata[i]['time_end'][-2:]
        return encrypt(json.dumps({'MSG': 'OK', 'data': retdata}))
    except:
        return encrypt(json.dumps({'MSG': 'OK', 'data': []}))


def shengchengtupian(haibaoming, yonghuming, unionid):
    yonghuming = yonghuming[:10]
    newwidth = 500
    haibao = Image.open('/home/ubuntu/data/lianailianmeng/data/opendata/fenxiao/' + haibaoming + '.png')
    haibaow, haibaoh = haibao.size
    haibao = haibao.resize((newwidth, int(haibaoh / haibaow * newwidth)), Image.BILINEAR)
    haibaoh = int(haibaoh / haibaow * newwidth)
    imgtou = Image.new('RGBA', (newwidth, 100), 'white')
    draw = ImageDraw.Draw(imgtou)  # 生成绘制对象draw
    big = 20
    typeface = ImageFont.truetype('simkai.ttf', big)
    text1 = "Hi，我是" + yonghuming
    text2 = "推荐您这款超级棒的产品"
    text3 = "（长按识别底部小程序码，助您快速脱单）"
    draw.text(((newwidth - len(text1) * big) / 2, 10), text1, fill='#ff7e00', font=typeface)
    draw.text(((newwidth - len(text2) * big) / 2, 20 + big), text2, fill='#ff7e00', font=typeface)
    draw.text(((newwidth - len(text3) * big) / 2, 30 + 2 * big), text3, fill='#1861ce', font=typeface)
    xcxmk = Image.new('RGBA', (newwidth, 200), 'white')
    accessToken = Basic().get_access_token('xcx')
    postUrl = "https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=%s" % accessToken
    postJson = {"scene": unionid, 'width': 280}
    response = requests.post(postUrl, data=json.dumps(postJson))
    xcxm = Image.open(BytesIO(response.content))
    xcxm = xcxm.resize((100, 100), Image.BILINEAR)
    xcxmk.paste(xcxm, (200, 50))
    newimg = Image.new(haibao.mode, (newwidth, haibaoh + 300))
    newimg.paste(imgtou, (0, 0))
    newimg.paste(haibao, (0, 100))
    newimg.paste(xcxmk, (0, 100 + haibaoh))
    output_buffer = BytesIO()
    newimg.save(output_buffer, format='png')
    byte_data = output_buffer.getvalue()
    base64_str = base64.b64encode(byte_data)
    return base64_str


@app.route("/sqtg/getHaibaobase64", methods=["POST"])
def getHaibaobase64():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
        imgname = params['imgname']
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    userinfodoc = es.get(index='userinfo', doc_type='userinfo', id=unionid)['_source']
    haibao = str(shengchengtupian(imgname, userinfodoc['nickName'], unionid), encoding='utf8')
    return encrypt(json.dumps({'MSG': 'OK', 'data': haibao}))


def chaxundingdan(dingdanhao):
    chaxunurl = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/gethbinfo'
    chaxundict = {
        'nonce_str': ''.join(random.sample(string.ascii_letters + string.digits, 32)),
        'mch_billno': dingdanhao,
        'mch_id': mch_id,
        'appid': 'wx2cc1bc5a412d44d2',
        'bill_type': 'MCHT',
    }
    stringA = '&'.join(["{0}={1}".format(k, chaxundict.get(k)) for k in sorted(chaxundict)])
    stringSignTemp = '{0}&key={1}'.format(stringA, merchant_key)
    sign = hashlib.md5(stringSignTemp.encode('utf8')).hexdigest()
    chaxundict['sign'] = sign
    ssh_keys_path = '/home/ubuntu/data/lianailianmeng/data'
    weixinapiclient_cert = os.path.join(ssh_keys_path, "apiclient_cert.pem")
    weixinapiclient_key = os.path.join(ssh_keys_path, "apiclient_key.pem")
    result = requests.post(chaxunurl, data=dict_to_xml(chaxundict).encode('utf8'),
                           headers={'Content-Type': 'application/xml'},
                           cert=(weixinapiclient_cert, weixinapiclient_key), verify=True)
    result = xml_to_dict(result.content)
    return result


@app.route("/sqtg/getShangpinxiangqing", methods=["POST"])
def getShangpinxiangqing():
    try:
        params = json.loads(decrypt(request.stream.read()))
        unionid = params['unionid']
        prId = int(params['prId'])
    except Exception as e:
        logger.error(e)
        return json.dumps({'MSG': '警告！非法入侵！！！'})
    mycol = mydb["goods"]
    results = mycol.find({'_id': prId})
    retdata = {}
    for doc in results:
        retdata = doc
    timetime = time.time()
    starttime = time.strftime("%m月%d日", time.localtime(timetime))
    endtime = time.strftime("%m月%d日", time.localtime(timetime + 86400))
    return encrypt(
        json.dumps({'MSG': 'OK', 'data': retdata, 'starttime': starttime, 'endtime': endtime}))


if __name__ == "__main__":
    server = pywsgi.WSGIServer(('127.0.0.1', 13888), app)
    server.serve_forever()
