import pandas as pd
import json as json
import matplotlib.pyplot as plt
import numpy as np

from numpy import array
from keras.models import Sequential
from keras.models import load_model
from keras.layers import LSTM
from keras.layers import Dense
from keras.layers import Dropout
from keras.layers import Activation

from elasticsearch import Elasticsearch
from elasticsearch import helpers
from sklearn.cluster import KMeans
from pandas.io.json import json_normalize
from scipy.stats import entropy


import json
import requests


def connect_elasticsearch():
    es = Elasticsearch(['https://silabane:PVp5CcJfhoeo6sL2XJkVk8PL@44427d2de.cyberscore.com:443'])
    return es

def retrieve_data(es, index_name, query, object_filter):
    result_set = es.search(index=index_name, body=query, filter_path=object_filter)
    return result_set


# connect to Elasticsearch
es = connect_elasticsearch()

query_string_test = {'query':
                {
                    "bool":{
                        "must":[
                            {"match": {'event.action': 'network_flow'}},
                            {"match": {"flow.final": "true"}},
                            {"match": {"destination.ip": "10.3.8.54"}},
#                             {"match": {"destination.ip": "10.3.8.55"}},
#                             {"match": {"destination.ip": "10.3.8.56"}},
#                             {"match": {"destination.ip": "10.3.8.57"}},
#                             {"match": {"destination.ip": "10.3.8.59"}},
#                             {"match": {"destination.ip": "10.3.8.120"}},
#                             {"match": {"destination.ip": "10.3.8.122"}},
#                             {"match": {"destination.ip": "10.3.8.123"}},
#                             {"match": {"destination.ip": "10.3.8.59"}},
                            {"range": {"@timestamp": {"gte": "2019-08-16T08:00:00.000Z",
#                                                       "lte": "now"
                                                      "lt":"2019-08-16T17:00:00.000Z"
                                                     }}}
                        ]
                    }
                },
                "from" : 0,
                "size" : 1,
                "aggs" : {
                    "connection_per_1m" : {
                        "date_histogram" : {
                            "field" : "@timestamp",
                            "interval" : "1m"
                        },
                        "aggs" : {
                            "source_ip" : {
                                "terms" : {
                                    "field" : "source.ip",
                                    "size" : 1000
                                },
                                "aggs": {
                                  "destination_ip": {
                                    "terms": {
                                        "field": "destination.ip",
                                        "order": {
                                            "port_count_distinct": "desc"
                                        }
                                    },
                                    "aggs": {
                                        "port_count_distinct": {
                                            "cardinality": {
                                                "field": "destination.port"
                                            }
                                        }
                                    }
                                  }
                                }
                            }
                        }
                    }
                }
               }


# retrieve data from Elasticsearch
print('Retrieve data from Elasticsearch...')
object_filter_test = ''
result_test = retrieve_data(es, 'packetbeat-*', query_string_test, object_filter_test)


print('Data preparation...')
# data preparation (engineering and cleansing)
flat_aggregate_test = json_normalize(result_test['aggregations']['connection_per_1m']['buckets'])


master_dataframe_test = pd.DataFrame(columns=['time_bucket', 'source_ip', 'source_ip_count',
                                         'destination_ip', 'destination_ip_count', 'destination_ip_distinct'])


for time_test in range(0, len(flat_aggregate_test)):
    current_df1_test = json_normalize(flat_aggregate_test.iloc[time_test, 3])
    for source_idx in range(0, len(current_df1_test)):
        current_df2_test = json_normalize(current_df1_test['destination_ip.buckets'][source_idx])
        for dest_idx_test in range(0, len(current_df2_test)):
            master_idx = len(master_dataframe_test)
            master_dataframe_test.loc[master_idx, 'time_bucket'] = flat_aggregate_test.loc[time_test, 'key_as_string']
            master_dataframe_test.loc[master_idx, 'source_ip'] = current_df1_test.loc[source_idx, 'key']
            master_dataframe_test.loc[master_idx, 'source_ip_count'] = current_df1_test.loc[source_idx, 'doc_count']
            master_dataframe_test.loc[master_idx, 'destination_ip'] = current_df2_test.loc[dest_idx_test, 'key']
            master_dataframe_test.loc[master_idx, 'destination_ip_count'] = current_df2_test.loc[dest_idx_test, 'doc_count']
            master_dataframe_test.loc[master_idx, 'destination_ip_distinct'] = current_df2_test.loc[dest_idx_test, 'port_count_distinct.value']


master_dataframe_test['total_connection'] = master_dataframe_test.groupby(['time_bucket', 'destination_ip'])['destination_ip_distinct'].transform('sum')

time_step_dataframe_test = master_dataframe_test.drop_duplicates(subset='time_bucket', keep='first', inplace=False).drop(['source_ip', 'source_ip_count', 'destination_ip','destination_ip_count', 'destination_ip_distinct','total_connection'], axis=1)
destination_dataframe_test = master_dataframe_test.drop_duplicates(subset='destination_ip', keep='first', inplace=False).drop(['time_bucket', 'source_ip', 'source_ip_count','destination_ip_count', 'destination_ip_distinct', 'total_connection'], axis=1)
time_step_dataframe_test['key_id'] = 1
destination_dataframe_test['key_id'] = 1

joined_df_test = pd.merge(time_step_dataframe_test, destination_dataframe_test, on='key_id').drop('key_id', axis=1)

joined_df2_test = pd.merge(joined_df_test, master_dataframe_test,
                      left_on=['time_bucket', 'destination_ip'], right_on=['time_bucket', 'destination_ip'], how='left')

joined_df2_test.drop_duplicates(subset=['time_bucket', 'destination_ip'], keep='first', inplace=True)
joined_df2_test=joined_df2_test.reset_index(drop=True)

joined_df2_test['destination_ip_factor'] = joined_df2_test['destination_ip'].factorize()[0]
joined_df2_test['destination_ip_count'].fillna(0, inplace=True)
joined_df2_test['destination_ip_distinct'].fillna(0, inplace=True)
joined_df2_test['source_ip_count'].fillna(0, inplace=True)


# load model
print('Load model...')
model2 = load_model('/application/model.h5')

print('Run prediction...')
n_steps = 30
n_features = 2

predicted_index = 0
for i in range(predicted_index, (len(joined_df2_test) - n_steps) ):
    x_input = array(joined_df2_test.iloc[i:(i+n_steps), [3,6]])
    x_input = x_input.reshape((1, n_steps, n_features))
    yhat = model2.predict(x_input, verbose=1)
    print(str(yhat[0][1]) + ' - ' + str(joined_df2_test.iloc[i+n_steps, 6]))
    if(joined_df2_test.iloc[i+n_steps, 6] > (yhat[0][1] + 10)):
        warning_text = {'text': "Possible threat detected. Time: " + joined_df2_test.iloc[i+n_steps, 0]
                +"; source ip: " + joined_df2_test.iloc[i+n_steps, 2]
                +"; destination ip: " + joined_df2_test.iloc[i+n_steps, 1]
                +"; expected number of connection was " + str(round(((joined_df2_test.iloc[i+n_steps, 6])/(yhat[0][1]))*100)) +"% higher"}

        response = requests.post(
            'https://hooks.slack.com/services/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',
            data=json.dumps(warning_text),
            headers={'Content-Type': 'application/json'}
        )


        print('port scan detected!! ' + joined_df2_test.iloc[i+n_steps, 0])

print('Finish')
