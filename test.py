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


f=open('xinliceshiret.json0','w')
for line in open('xinliceshiret.json'):
    line=json.loads(line)
    line['data']=json.dumps(line['data'],ensure_ascii=False)
    f.write(json.dumps(line,ensure_ascii=False)+'\n')
f.close()