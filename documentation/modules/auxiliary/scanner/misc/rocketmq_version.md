## Vulnerable Application

Version scanner for the Apache RocketMQ product.

### Setup

Instructions taken from https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT

```
docker pull apache/rocketmq:4.9.4
# Start nameserver
docker run -d --name rmqnamesrv -p 9876:9876 apache/rocketmq:4.9.4 sh mqnamesrv
# Start Broker
docker run -d --name rmqbroker --link rmqnamesrv:namesrv -e "NAMESRV_ADDR=namesrv:9876" -p 10909:10909 -p 10911:10911 -p 10912:10912 apache/rocketmq:4.9.4 sh mqbroker -c /home/rocketmq/rocketmq-4.9.4/conf/broker.conf
```

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/misc/rocketmq_version`
1. Do: `set rhosts [ips]`
1. Do: `run`
1. You should get the version number from rocketmq

## Options

## Scenarios

### 4.9.4 on Docker from above instructions

```
msf6 > use auxiliary/scanner/misc/rocketmq_version
msf6 auxiliary(scanner/misc/rocketmq_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/misc/rocketmq_version) > run

[+] 127.0.0.1:9876        - RocketMQ version V4.9.4 found with brokers: [{"brokerAddrs"=>{"0"=>"172.17.0.4:10911"}, "brokerName"=>"broker-a", "cluster"=>"DefaultCluster"}]
[*] 127.0.0.1:9876        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
