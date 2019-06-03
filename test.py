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


name='wenzhang'
f=open(name+'.json')
ff=open(name+'0.json','w')
for line in f:
    line=json.loads(line)
    ff.write(json.dumps(line,ensure_ascii=False)+'\n')
f.close()
ff.close()
