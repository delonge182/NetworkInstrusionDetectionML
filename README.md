# NetworkInstrusionDetectionML
Automatic Network Intrusion Detection using Machine Learning

## There are four main tools:
1. *Packetbeat*, data collection agent. Installed on every host that need to be
monitored. It collects every network track that occurred on the host and
store it as a log.
2. *Logstash*, act as data pool to centralise the data that come from all
Packetbeat agents. Logstash make the data collection pipe more scalable.
3.  *Elasticsearch*, it acts as database where the log that retrieve by Packetbeat
agent stored as persistent data. It also used for data engineering tools
which data can be grouped, aggregated, concatenated and reformat.
4. *Python pipeline* that was custom developed for each type of intrusion
model. This pipeline retrieve data from Elasticsearch using an API, do some
engineering and cleansing then Finally feed it into the model.

# Design view:
![alt text](https://github.com/delonge182/NetworkInstrusionDetectionML/blob/master/granddesign.png) 
