import pandas as pd
import json as json
import numpy as np

from elasticsearch import Elasticsearch
from elasticsearch import helpers

from pandas.io.json import json_normalize

import featuretools as ft
from datetime import datetime

from sklearn.preprocessing import LabelBinarizer


def connect_elasticsearch():
    es = Elasticsearch(['https://silabane:PVp5CcJfhoeo6sL2XJkVk8PL@44427d2de.cyberscore.com:443'])
    return es


def retrieve_data(es, index_name, query, object_filter):
    result_set = es.search(index=index_name,
                           body=query,
                           filter_path=object_filter)

    return result_set


def calc_delta_between_event(curr_df, x):
    no_result = len(curr_df.loc[ (curr_df[ '_source.@timestamp'] < x[0]) &
               (curr_df[ '_source.source.ip'] == x[4]) &
               (curr_df[ '_source.destination.ip'] == x[2]), '_source.@timestamp'] )
    if (no_result > 0):
        delta = pd.to_datetime(x[0]) - max(curr_df.loc[ (curr_df[ '_source.@timestamp'] < x[0]) &
               (curr_df[ '_source.source.ip'] == x[4]) &
               (curr_df[ '_source.destination.ip'] == x[2]), '_source.@timestamp'])

        return delta.seconds
    else:
        return -1


es = connect_elasticsearch()

print(es.ping())


query_string = {
    "query": {
        "bool": {
            "must": [
                { "range": { "@timestamp": {"gte": "2019-09-05T04:04:00.000Z",
                                            "lt":"2019-09-05T04:50:00.000Z" }}},
                { "match": { "network.transport" : "udp"}},
                { "match": { "source.ip" : "10.3.8.44"}}
            ]
        }
    },
    "from" : 0,
    "size" : 10000
}

object_filter = ['hits.hits._source.@timestamp',
                 'hits.hits._source.agent.hostname',
                 'hits.hits._source.source.ip',
                 'hits.hits._source.destination.ip',
                 'hits.hits._source.network.bytes'
#                  'hits.hits._source.domain',
#                  'hits.hits._source.sub_domain',
#                  'hits.hits._source.dns.question.etld_plus_one',
#                  'aggregations'
                ]
result = retrieve_data(es, 'packetbeat-*', query_string, object_filter)


flat_result = json_normalize(result['hits']['hits'])

flat_result['_source.@timestamp']= pd.to_datetime(flat_result['_source.@timestamp'])

flat_result['delta_prev'] = flat_result.apply(lambda x: calc_delta_between_event(flat_result, x), axis=1)


flat_result['hour'] = flat_result['_source.@timestamp'].dt.hour
flat_result['minute'] = flat_result['_source.@timestamp'].dt.minute
flat_result['second'] = flat_result['_source.@timestamp'].dt.second

flat_result.loc[flat_result['delta_prev'] > 1, ['_source.@timestamp', 'hour', 'minute', 'second']]


# flat_result.loc[flat_result['delta_prev'] == 10]
flat_result_sorted = flat_result.sort_values(by='_source.@timestamp')
flat_result_sorted.loc[flat_result_sorted['_source.destination.ip'] == '91.189.89.199']



query_string_test = {
    "query": {
        "bool": {
            "must": [
                { "range": { "@timestamp": {"gte": "2019-09-05T05:04:00.000Z",
                                            "lt":"2019-09-05T05:50:00.000Z" }}},
                { "match": { "network.transport" : "udp"}},
                { "match": { "source.ip" : "10.3.8.44"}}
            ]
        }
    },
    "from" : 0,
    "size" : 10000
}

object_filter_test = ['hits.hits._source.@timestamp',
                 'hits.hits._source.agent.hostname',
                 'hits.hits._source.source.ip',
                 'hits.hits._source.destination.ip',
                 'hits.hits._source.network.bytes'
#                  'hits.hits._source.domain',
#                  'hits.hits._source.sub_domain',
#                  'hits.hits._source.dns.question.etld_plus_one',
#                  'aggregations'
                ]
result_test = retrieve_data(es, 'packetbeat-*', query_string_test, object_filter_test)


flat_result_test = json_normalize(result_test['hits']['hits'])

flat_result_test['_source.@timestamp']= pd.to_datetime(flat_result_test['_source.@timestamp'])

flat_result_test['delta_prev'] = flat_result_test.apply(lambda x: calc_delta_between_event(flat_result_test, x), axis=1)


flat_result_test['hour'] = flat_result_test['_source.@timestamp'].dt.hour
flat_result_test['minute'] = flat_result_test['_source.@timestamp'].dt.minute
flat_result_test['second'] = flat_result_test['_source.@timestamp'].dt.second


# flat_result.loc[flat_result['delta_prev'] == 10]
flat_result_test_sorted = flat_result_test.sort_values(by='_source.@timestamp')
flat_result_test_sorted.loc[flat_result_test_sorted['_source.destination.ip'] == '91.189.89.199']


flat_result_test_sorted.to_csv(r'data/flat_result_test_sorted.csv')




from sklearn.feature_selection import mutual_info_classif
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.model_selection import GridSearchCV


flat_result_sorted.columns

flat_result_sorted.iloc[:, [5]].head()


ip_encoder = LabelBinarizer()
encoder_result = ip_encoder.fit_transform(flat_result_sorted['_source.destination.ip'])
df_ip_encode = pd.DataFrame(encoder_result)
flat_result_sorted = pd.concat([flat_result_sorted, df_ip_encode], axis='columns')

encoder_result2 = ip_encoder.transform(flat_result_test_sorted['_source.destination.ip'])
df_ip_encode2 = pd.DataFrame(encoder_result2)
flat_result_test_sorted = pd.concat([flat_result_test_sorted, df_ip_encode2], axis='columns')



beaconing_detection_train_x = flat_result_sorted.loc[flat_result_sorted['delta_prev'] != -1].iloc[:, [3, 6, 7, 8, 9, 10, 11, 12]]
beaconing_detection_train_y = flat_result_sorted.loc[flat_result_sorted['delta_prev'] != -1].iloc[:, [5]]


beaconing_detection_test_x = flat_result_test_sorted.loc[flat_result_test_sorted['delta_prev'] != -1].iloc[:, [3, 6, 7, 8, 9, 10, 11, 12]]
beaconing_detection_test_y = flat_result_test_sorted.loc[flat_result_test_sorted['delta_prev'] != -1].iloc[:, [5]]


train_features, test_features, train_labels, test_labels = train_test_split(beaconing_detection_train_x,
                                                                            beaconing_detection_train_y,
                                                                           test_size=0.2,
                                                                           random_state = 42)

beaconing_rf_class = RandomForestClassifier(max_depth=9, n_estimators=20, max_features=8)

beaconing_rf_class.fit(train_features, train_labels)


prediction1 = beaconing_rf_class.predict(test_features)
training_score = beaconing_rf_class.score(test_features, test_labels)
test_score = beaconing_rf_class.score(beaconing_detection_test_x, beaconing_detection_test_y)


prediction2 = beaconing_rf_class.predict(beaconing_detection_test_x)


beaconing_detection_test_x['prediction'] = prediction2
beaconing_detection_test_x['label'] = beaconing_detection_test_y

training_score

test_score                                                                         
