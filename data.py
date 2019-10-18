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
blocklen = 100

lianaizhuli_index = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1,
    },
    "properties": {
        "title": {
            "type": "text",
            "fields": {
                "cn": {
                    "type": "text",
                    "analyzer": "ik_smart"
                },
                "en": {
                    "type": "text",
                    "analyzer": "english"
                }
            }
        }
    }
}
es = Elasticsearch([{"host": "119.29.67.239", "port": 9218, "timeout": 3600}])
actions = []
es.indices.delete(index='xingshenglist')

ret_data = es.indices.create(index='xingshenglist', body=lianaizhuli_index, ignore=400)
print(ret_data)

with open('xingshenglist.json', 'r') as f:
    for line in f:
        item = json.loads(line.strip())
        action = {
            "_index": "xingshenglist",
            "_type": "xingshenglist",
            "_source": item,
            '_id':item['prId']
        }
        actions.append(action)
while len(actions):
    print(len(actions))
    helpers.bulk(es, actions[:blocklen])
    actions = actions[blocklen:]


print('创建结束！')

