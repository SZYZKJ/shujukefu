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


ff=open('wenda0.json','w')
for line in open('wenda.json'):
    line=json.loads(line)
    f=open('opendata/wenda/'+str(line['id'])+'.html','w')
    f.write('<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF8"></head><body>\n'+line['post_content']+'</body></html>\n')
    f.close()
    line.pop('post_content')
    ff.write(json.dumps(line,ensure_ascii=False)+'\n')
ff.close()