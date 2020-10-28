FROM python:3.7.3

COPY application /application

RUN     apt-get update

RUN     pip install pip pandas matplotlib keras tensorflow elasticsearch sklearn requests

CMD python /application/portscan-detection.py
