import pandas as pd
import json as json
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

from elasticsearch import Elasticsearch
from elasticsearch import helpers
from sklearn.cluster import KMeans
from pandas.io.json import json_normalize
from scipy.stats import entropy


def connect_elasticsearch():
    es = Elasticsearch(['https://silabane:PVp5CcJfhoeo6sL2XJkVk8PL@44427d2de.cyberscore.com:443'])
    return es

def retrieve_data(es, index_name, query, object_filter):
    result_set = es.search(index=index_name,
                           body=query,
                           filter_path=object_filter)

    return result_set


def scan_data(es, index_name, query):
    scan_result = helpers.scan(es,
        query=query,
        index=index_name
    )
    return scan_result


def calculate_entropy(sub_domain):
    value, counts = np.unique(list(sub_domain), return_counts=True)
    return entropy(counts)


es = connect_elasticsearch()

print(es.ping())


query_string = {'query':
                {
                    "bool":{
                        "must":[
#                             {"match": {'dns.question.etld_plus_one': 'internal.xq'}},
#                             {"match": {"flow.final": "true"}},
#                             {"match": {"destination.ip": "10.3.8.54"}},
                            {"exists": {
                                "field": "dns.question.etld_plus_one"
                            }},
                            {"range": {"@timestamp": {"gte": "2019-08-15T15:00:00.000Z",
                                                      "lt":"2019-08-16T18:00:00.000Z"
                                                     }}}
                        ]
                        ,
                          "must_not" : {
                            "term" : {
                              'dns.question.etld_plus_one': 'internal.xq'
                            }
                          }
                    }
                }
                , "from" : 0, "size" : 10000
               }
#query_string = {"from" : 0, "size" : 60000}
object_filter = ['hits.hits._source.@timestamp',
                 'hits.hits._source.agent.hostname',
                 'hits.hits._source.source',
                 'hits.hits._source.destination',
                 'hits.hits._source.event',
                'hits.hits._source.domain',
                'hits.hits._source.sub_domain'
                ]
result = retrieve_data(es, 'packetbeat-*', query_string, object_filter)


flat_result = json_normalize(result['hits']['hits'])


flat_result['_source.agent.hostname'] = flat_result['_source.agent.hostname'].factorize()[0]
# flat_result['_source.event.action'] = flat_result['_source.event.action'].factorize()[0]
flat_result['_source.event.category'] = flat_result['_source.event.category'].factorize()[0]
flat_result['_source.event.dataset'] = flat_result['_source.event.dataset'].factorize()[0]
flat_result['_source.event.kind'] = flat_result['_source.event.kind'].factorize()[0]
flat_result['_source.source.ip'] = flat_result['_source.source.ip'].factorize()[0]
flat_result['_source.destination.ip'] = flat_result['_source.destination.ip'].factorize()[0]


flat_result['_source.destination.bytes'].fillna(0, inplace=True)
# flat_result['_source.destination.packets'].fillna(0, inplace=True)
flat_result['_source.destination.port'].fillna(0, inplace=True)
flat_result['_source.source.port'].fillna(0, inplace=True)
flat_result['_source.source.bytes'].fillna(0, inplace=True)
# flat_result['_source.source.packets'].fillna(0, inplace=True)
flat_result['_source.event.duration'].fillna(0, inplace=True)
flat_result['_source.domain'].fillna("-", inplace=True)
flat_result['_source.sub_domain'].fillna("-", inplace=True)


list_entropy_value = []
len(list_entropy_value)
for subdomain in flat_result['_source.sub_domain']:
    entropy_value = calculate_entropy(subdomain)
    list_entropy_value.append(entropy_value)
    #print(entropy_value)
    #print(subdomain)


flat_result['entropy_value'] = list_entropy_value


df_domain = flat_result[flat_result['_source.domain'] != "-"]
# df_domain.head()
df_domain.iloc[0:, [0,6, 16]].describe()


x = np.array(df_domain['entropy_value'].tolist())
print (x.mean() + 3 * x.std())


warning_limit =  x.mean() + (3 * x.std())
list_domain_high_entropy = flat_result.loc[flat_result['entropy_value'] > warning_limit, '_source.domain'].tolist()
flat_result.loc[flat_result['_source.domain'].isin(list_domain_high_entropy), ['_source.@timestamp', '_source.domain', '_source.sub_domain', 'entropy_value']]


flat_result.loc[0:, ['_source.@timestamp', '_source.destination.ip', '_source.domain', '_source.sub_domain', 'entropy_value']]
