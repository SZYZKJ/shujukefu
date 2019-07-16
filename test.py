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
search = {"query": {"match_all": {}}}
Docs=es.search(index='userinfo',doc_type='userinfo',body=search,size=10000)['hits']['hits']
word={}
for doc in Docs:
    doc=doc['_source']
    for name in doc:
        word[name]=0
for name in word:
    print(name)
# userid='oz7z64tQmf3SAoW7qqtxk9IitxZ0'
# doc=es.get(index='userinfo',doc_type='userinfo',id=userid)['_source']
# doc.pop('phoneNumber')
# es.index(index='userinfo',doc_type='userinfo',id=userid,body=doc)

