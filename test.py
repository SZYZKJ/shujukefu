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


es=Elasticsearch([{"host": "182.254.227.188", "port": 9218, "timeout": 3600}])
search = {"query": {"match_all": {}}}
Docs = es.search(index='userinfo', doc_type='userinfo', body=search, size=10000)
for doc in Docs['hits']['hits']:
    doc=doc['_source']
    if 'nickName' in doc and 'Novoeight' in doc['nickName']:
        doc['vipdengji']=6
        doc['viptime']+=3153600000
        doc['sijiaotime']+=3153600000
        print(doc)
        es.index(index='userinfo', doc_type='userinfo', id=doc['unionid'],body=doc)







