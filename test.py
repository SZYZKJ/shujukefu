from elasticsearch import Elasticsearch
from elasticsearch import helpers
import csv
import os
import time
import json
import random
import requests

datapath = '/home/ubuntu/data/lianailianmeng/data'
os.chdir(datapath)


es = Elasticsearch([{"host": "119.29.67.239", "port": 9218, "timeout": 3600}])
# search = {"query": {"match_all": {}}}
# Docs=es.search(index='userinfo',doc_type='userinfo',body=search,size=10000)['hits']['hits']
# for doc in Docs:
#     doc=doc['_source']
#     if '罗尼' in doc['nickName']:
#         print(doc)
userid='oz7z64tQmf3SAoW7qqtxk9IitxZ0'
doc=es.get(index='userinfo',doc_type='userinfo',id=userid)['_source']
doc.pop('phoneNumber')
es.index(index='userinfo',doc_type='userinfo',id=userid,body=doc)

