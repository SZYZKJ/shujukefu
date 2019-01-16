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
blocklen = 500


class Lianaizhuli_ES:
    es = Elasticsearch([{"host": "119.29.67.239", "port": 9218, "timeout": 3600}])

    def __init__(self):
        # self.es.indices.delete(index='userinfo')
        # self.es.indices.delete(index='userzhifu')
        # self.es.indices.delete(index='tuweiqinghua')
        # self.es.indices.delete(index='jinpushequ')
        self.es.indices.delete(index='kefu')
        if self.es.indices.exists(index='kefu') is not True:
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
            # ret_userhis = self.es.indices.create(index='userhis', body=lianaizhuli_index, ignore=400)
            # print(ret_userhis)
            # ret_userinfo = self.es.indices.create(index='userinfo', body=lianaizhuli_index, ignore=400)
            # print(ret_userinfo)
            # ret_userzhifu = self.es.indices.create(index='userzhifu', body=lianaizhuli_index, ignore=400)
            # print(ret_userzhifu)
            # ret_tuweiqinghua = self.es.indices.create(index='tuweiqinghua', body=lianaizhuli_index, ignore=400)
            # print(ret_tuweiqinghua)
            # ret_jinpushequ = self.es.indices.create(index='jinpushequ', body=lianaizhuli_index, ignore=400)
            # print(ret_jinpushequ)
            # ret_kefu = self.es.indices.create(index='kefu', body=lianaizhuli_index, ignore=400)
            # print(ret_kefu)
            actions = []
            # with open('tuweiqinghua.json', 'r') as f:
            #     for line in f:
            #         item = json.loads(line.strip())
            #         action = {
            #             "_index": "tuweiqinghua",
            #             "_type": "tuweiqinghua",
            #             "_source": item,
            #             '_id':item['chatId']
            #         }
            #         actions.append(action)
            # random.shuffle(actions)
            # while len(actions):
            #     helpers.bulk(self.es, actions[:blocklen])
            #     actions = actions[blocklen:]
            # with open('jinpushequ.json', 'r') as f:
            #     for line in f:
            #         item = json.loads(line.strip())
            #         action = {
            #             "_index": "jinpushequ",
            #             "_type": "jinpushequ",
            #             "_source": item,
            #             '_id':item['id']
            #         }
            #         actions.append(action)
            # random.shuffle(actions)
            # while len(actions):
            #     helpers.bulk(self.es, actions[:blocklen])
            #     actions = actions[blocklen:]
            print('创建结束！')

    def add(self):
        return None

    def delete(self):
        return None

    def updata(self):
        return None


# LAES=Lianaizhuli_ES()
# print(LAES.es.get(index='userinfo',doc_type='userinfo',id='oz7z64hH8HiPnWCYFCJpNBqC2J1E'))

LAES=Lianaizhuli_ES()
# search = {"query": {"match_all": {}}}
# Docs=LAES.es.search(index='userinfo',doc_type='userinfo',body=search,size=10000)
# t=0
# for doc in Docs['hits']['hits']:
#     if doc['_source']['addtime']=='20190112':
#         print(doc['_source']['options'],doc['_source']['city'])
#         if '1000009' in json.dumps(doc['_source']['options']):
#             t+=1
# print(t)
