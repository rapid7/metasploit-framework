#!/bin/sh

docker build -t ysoserial-payloads . && \
  docker run -i ysoserial-payloads > ysoserial_payloads.json

echo "Move 'ysoserial_payloads.json' to data/java_deserialization/"
