import pandas as pd
import json as json
import numpy as np

from elasticsearch import Elasticsearch
from elasticsearch import helpers

from pandas.io.json import json_normalize

import matplotlib.pyplot as plt

from sklearn.preprocessing import LabelEncoder

import re



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


def extract_date(x):
    result = re.findall("[0-9][0-9][0-9][0-9][0-9][0-9] [0-2][0-9]:[0-6][0-9]:[0-6][0-9]", x)
    if result:
        return result[0].split(' ')[0]
    else:
        return ''


def extract_time(x):
    result = re.findall("[0-9][0-9][0-9][0-9][0-9][0-9] [0-2][0-9]:[0-6][0-9]:[0-6][0-9]", x)
    if result:
        return result[0].split(' ')[1]
    else:
        return ''


es = connect_elasticsearch()

print(es.ping())


query_string = {
  "query": {
    "bool": {
      "must": [
                { "range": { "@timestamp": {"gte": "2019-10-22T07:00:00.000Z",
                                            "lt":"2019-10-22T19:00:00.000Z" }}}
#           ,
#                 { "match": { "message" : "connect"}}
            ],
      "must_not": [
          { "match": { "message": "Close stmt"}},
          { "match": { "message": "quit"}},
          { "match": { "message": "select"}},
          { "match": { "message": "Execute\tset session sql_mode"}},
          { "match": { "message": "Query\tuse"}}
      ]
    }
  }
#     ,
#     "from" : 0,
#     "size" : 10000
}

object_filter = ['hits.hits._id',
                 'hits.hits._source.@timestamp',
                 'hits.hits._source.agent.hostname',
                 'hits.hits._source.message',
#                  'hits.hits._source.domain',
#                  'hits.hits._source.sub_domain',
#                  'hits.hits._source.dns.question.etld_plus_one',
                 'aggregations'
                ]

# object_filter = ""

# result = retrieve_data(es, 'filebeat-*', query_string, object_filter)
result = scan_data(es, 'filebeat-*', query_string)


####### only if using scan
list_result = list(result)

temp1_df = pd.DataFrame(list_result)['_source']
df_scan_result = json_normalize(temp1_df)
df_scan_result.to_csv(r'data/scan_filebeat_2019-10-22_1.csv')

flat_result = df_scan_result


flat_result['date'] = flat_result['message'].map(lambda x: extract_date(x))
flat_result.loc[flat_result['date'] != '', 'hour'] = flat_result.loc[flat_result['date'] != '', 'message'].map(lambda x: extract_time(x).split(':')[0])
flat_result.loc[flat_result['date'] != '', 'minute'] = flat_result.loc[flat_result['date'] != '', 'message'].map(lambda x: extract_time(x).split(':')[1])
flat_result.loc[flat_result['date'] != '', 'second'] = flat_result.loc[flat_result['date'] != '', 'message'].map(lambda x: extract_time(x).split(':')[2])


flat_result['message'] = flat_result['message'].map(
    lambda x: re.sub("[0-9][0-9][0-9][0-9][0-9][0-9] [0-2][0-9]:[0-6][0-9]:[0-6][0-9]\t", '\t\t', x))

flat_result['session_id'] = flat_result['message'].map(lambda x: x.replace('\t\t','').split(' ', 1)[0])

flat_result.loc[flat_result['message'].str.find('Connect') >= 0, 'message1'] = flat_result.loc[flat_result['message'].str.find('Connect') >= 0, 'message'].map(lambda x: x.split('Connect\t')[-1])
flat_result.loc[(flat_result['message'].str.find('Connect') >= 0) & (flat_result['message'].str.find('Connect\tAccess denied') < 0), 'event'] = 'connect'
flat_result.loc[(flat_result['message'].str.find('Connect\tAccess denied') >= 0), 'event'] = 'connect_failed_notif'


flat_result.loc[flat_result['message'].str.find('select') >= 0, 'message1'] = 'select'
flat_result.loc[flat_result['message'].str.find('select') >= 0, 'event'] = 'select'

flat_result.loc[(flat_result['message'].str.find('Connect') < 0) &
                (flat_result['message'].str.find('select') < 0), 'message1'] = 'other'
flat_result.loc[(flat_result['message'].str.find('Connect') < 0) &
                (flat_result['message'].str.find('select') < 0), 'event'] = 'other'


flat_result.loc[(flat_result['event'] == 'connect') | (flat_result['event'] == 'connect_failed_notif'), 'user'] = flat_result.loc[(flat_result['event'] == 'connect') | (flat_result['event'] == 'connect_failed_notif'), 'message1'].map(lambda x: x.split('@', 1)[0])
flat_result.loc[(flat_result['event'] == 'connect') | (flat_result['event'] == 'connect_failed_notif'), 'from'] = flat_result.loc[(flat_result['event'] == 'connect') | (flat_result['event'] == 'connect_failed_notif'), 'message1'].map(lambda x: x.split('@', 1)[1].split(' ', 1)[0])

flat_result.loc[flat_result['message1'].str.find("Access denied") >= 0, 'login_status'] = 'failed'
for index, row in flat_result.loc[flat_result['login_status'] == 'failed'].iterrows():
    flat_result.loc[(flat_result['session_id'] == row['session_id']), 'login_status'] = 'failed'
flat_result['login_status'].fillna('successful', inplace=True)


flat_result.loc[flat_result['event'] != 'connect', 'user'] = flat_result.loc[flat_result['event'] != 'connect', 'session_id'].map(lambda x: flat_result.loc[(flat_result['session_id'] == x) & (flat_result['event'] == 'connect'), 'user'].to_string().split('    ', 1)[-1])


flat_result.drop(index=flat_result.loc[(flat_result['date'] == '') & (flat_result['event'] != 'connect_failed_notif') ].index, inplace=True)
flat_result.reset_index()


df_groupby_user_time = pd.DataFrame({'count_per_user' : flat_result.loc[flat_result['event'] == 'connect'].groupby(['user','date', 'hour', 'minute']).size()}).reset_index()
df_groupby_time = pd.DataFrame({'count_per_time' : flat_result.loc[flat_result['event'] == 'connect'].groupby(['date', 'hour', 'minute']).size()}).reset_index()
df_groupby_user_time_failed = pd.DataFrame({'count_failed_per_user' : flat_result.loc[flat_result['event'] == 'connect'].groupby(['user','date', 'hour', 'minute', 'login_status']).size()}).reset_index()
df_groupby_time_failed = pd.DataFrame({'count_failed_per_time' : flat_result.loc[flat_result['event'] == 'connect'].groupby(['date', 'hour', 'minute', 'login_status']).size()}).reset_index()


for index, row in df_groupby_time.iterrows():
    df_groupby_user_time.loc[(df_groupby_user_time['date'] == row['date']) &
                            (df_groupby_user_time['hour'] == row['hour']) &
                            (df_groupby_user_time['minute'] == row['minute']), 'count_per_time'] = row['count_per_time']


for index, row in df_groupby_time_failed.iterrows():
    df_groupby_user_time_failed.loc[(df_groupby_user_time_failed['date'] == row['date']) &
                            (df_groupby_user_time_failed['hour'] == row['hour']) &
                            (df_groupby_user_time_failed['minute'] == row['minute']) &
                            (df_groupby_user_time_failed['login_status'] == row['login_status']), 'count_failed_per_time'] = row['count_failed_per_time']


for index, row in df_groupby_user_time.iterrows():
    flat_result.loc[(flat_result['user'] == row['user']) &
                    (flat_result['date'] == row['date']) &
                    (flat_result['hour'] == row['hour']) &
                    (flat_result['minute'] == row['minute']), 'count_per_time'] = row['count_per_time']
    flat_result.loc[(flat_result['user'] == row['user']) &
                    (flat_result['date'] == row['date']) &
                    (flat_result['hour'] == row['hour']) &
                    (flat_result['minute'] == row['minute']) , 'count_per_user'] = row['count_per_user']
for index, row in df_groupby_user_time_failed.loc[df_groupby_user_time_failed['login_status'] == 'failed'].iterrows():
    flat_result.loc[(flat_result['user'] == row['user']) &
                    (flat_result['date'] == row['date']) &
                    (flat_result['hour'] == row['hour']) &
                    (flat_result['minute'] == row['minute']) , 'count_failed_per_time'] = row['count_failed_per_time']
    flat_result.loc[(flat_result['user'] == row['user']) &
                    (flat_result['date'] == row['date']) &
                    (flat_result['hour'] == row['hour']) &
                    (flat_result['minute'] == row['minute']) , 'count_failed_per_user'] = row['count_failed_per_user']

flat_result['count_failed_per_time'].fillna(0, inplace=True)
flat_result['count_failed_per_user'].fillna(0, inplace=True)


flat_result.to_csv(r'data/scan_filebeat_2019-10-22_afterpreprocessed_1.csv')




from sklearn.feature_selection import mutual_info_classif
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.model_selection import GridSearchCV

from sklearn.preprocessing import LabelBinarizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import LabelEncoder



# df_model1 = flat_result.loc[flat_result['event'] == 'connect'].iloc[:, [6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18]]
df_model1 = flat_result.loc[flat_result['event'] == 'connect'].iloc[:, [25, 26, 27, 28, 30, 31, 32, 33, 34, 35, 36, 37]]
# df_model1.drop_duplicates(inplace=True)
# df_model1.reset_index(inplace=True)
df_model1.reset_index(inplace=True)
df_model1 = df_model1.iloc[:, 1:]


event_encoder = LabelEncoder()
event_encoder_result = event_encoder.fit_transform(df_model1['event'])
df_model1['event_code'] = event_encoder_result


user_encoder = LabelEncoder()
user_encoder_result = user_encoder.fit_transform(df_model1['user'])
df_model1['user_code'] = user_encoder_result


from_encoder = LabelEncoder()
from_encoder_result = from_encoder.fit_transform(df_model1['from'])
df_model1['from_code'] = from_encoder_result


login_status_encoder = LabelEncoder()
login_status_encoder_result = login_status_encoder.fit_transform(df_model1['login_status'])
df_model1['login_status_code'] = login_status_encoder_result


credential_spray_detection_train_x = df_model1.iloc[:, [0, 1, 9, 10, 11, 13, 14]]
credential_spray_detection_train_y = df_model1.iloc[:, [8]]


train_features, test_features, train_labels, test_labels = train_test_split(credential_spray_detection_train_x,
                                                                            credential_spray_detection_train_y,
                                                                           test_size=0.2,
                                                                           random_state = 42)


credential_spray_rf_class = RandomForestClassifier(max_depth=12, n_estimators=20, max_features=7)


credential_spray_rf_class.fit(train_features, train_labels)


prediction1 = credential_spray_rf_class.predict(test_features)
training_score = credential_spray_rf_class.score(test_features, test_labels)
training_score


# df_model1.head()
# credential_spray_detection_train_x
test_features['prediction'] =prediction1
test_features['label'] = test_labels
test_features.to_csv(r'data/prediction_minute_3.csv')

df1 = prediction

test_features['diff'] = test_features['label'] - test_features['prediction']

test_features['diff'].describe()


test_features['diff'].hist(bins=20, figsize=(20,15))
