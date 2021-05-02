#!/bin/sh

docker build -t ysoserial-payloads . && \
  docker run -i ysoserial-payloads > ysoserial_payloads.json && \
  mv ysoserial_payloads.json ../../../data
