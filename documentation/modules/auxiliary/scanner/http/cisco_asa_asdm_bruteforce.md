## Vulnerable Application

### Description

This module scans for the Cisco ASA ASDM landing page and performs login brute-force
to identify valid credentials.

### Installation

Acquire a Cisco ASA device or virtual machine. For this description we will use
Cisco Adaptive Security Virtual Appliance (ASAv) VMWare Package 9.18.1 (asav9-18-1.zip):

* https://software.cisco.com/download/home/286119613/type/280775065/release/9.18.1

The [official installation guide can be found here](https://www.cisco.com/c/en/us/td/docs/security/asa/asa98/asav/quick-start-book/asav-98-qsg/asav-vmware.html)
But for completeness, the following will guide the user to a full testing configuration.
To start we'll make ASDM remotely accessible:

1. Unzip the package
1. Import `asav-esxi.ovf` in VMWare Fusion (or your VMWare product of choice).
1. Select the `ASAv5 - 1 Core / 2 GB (100 Mbps)` deployment option.
1. After the import is complete, assign `Network Adapter` (1 is implied) the desired
interface (e.g. I'll use `Wi-Fi` for my setup).
1. Start the virtual machine
1. Allow GRUB to boot the first option (this should happen twice)
1. When provided with a command prompt (`ciscoasa>`) type `en`.
1. Set an enable password (e.g. `labpass1`)
1. Enter the following in the command line interface:
1. `conf t`
1. `No`
1. `interface GigabitEthernet 0/0`
1. `nameif outside`
1. Assign a static ip address (note the assigned address should make sense within the
context of you lab. For example, my lab network is 10.9.49.0/24): `ip address 10.9.49.201 255.255.255.0`
1. `no shutdown`
1. `exit`
1. Set the default route (the last IP should point to your lab router): `route outside 0.0.0.0 0.0.0.0 10.9.49.1`
1. Verify you can ping an outside host (e.g. `ping 8.8.8.8`)
1. `http server enable`
1. `http 0.0.0.0 0.0.0.0 outside`
1. `write`
1. `exit`

You should now be able to reach the ASA's web server remotely. From a remote host, execute the following `curl`
command to the ASA to verify as much:

```
albinolobster@ubuntu:~$ curl -kv https://10.9.49.201
*   Trying 10.9.49.201:443...
* TCP_NODELAY set
...
> GET / HTTP/1.1`
> Host: 10.9.49.201
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 301 Moved Permanently
< Date: Tue, 21 Jun 2022 13:52:33 UTC
< Strict-Transport-Security: max-age=31536000
< X-XSS-Protection: 1
< Connection: close
< Location: /admin/public/index.html
< 
* Closing connection 0
* TLSv1.2 (OUT), TLS alert, close notify (256):
```

You should now be able to test the credentials `<Blank>:labpass1` and `enable_15:labpass1`. To
add additional users to test with, let's use ASDM from a Windows machine:

1. Connect to your ASA's web interface (e.g. `https://10.9.49.201/admin/public/index.html`).
1. Click "Install ASDM Launcher"
1. Enter creds `blank`:labpass1 (where blank is nothing and labpass1 is your enable password)
1. Install the downloaded `dm-launcher.msi` (before 7.18.1 it will be unsigned)
1. If Java isn't installed, install Java 1.8 (current at time of writing is 8 Update 333): https://www.java.com/en/download/
1. Start the ASDM Launcher via `C:\Program Files (x86)\Cisco Systems\ASDM\run.bat`
1. Enter your ASAv's IP address (10.9.249.201)
1. Enter a blank username
1. Enter the enable password (`labpass1`)
1. Go to `Configuration -> Device Management -> Users/AAA -> User Accounts`
1. Click `Add`
1. Set the username to `cisco`
1. Set the password to `cisco123`
1. Keep the default settings for `Access Restrictions` (Full access with privilege level of 2).
1. Hit `OK`
1. Hit `Apply`

You should now be able to log in to the ASDM using `cisco`:`cisco123`.

## Verification Steps

* Follow the above instructions to configure ASAv, ASDM, and add the `cisco` user for testing
* Do: `use auxiliary/scanner/http/cisco_asa_asdm_bruteforce`
* Do: `set RHOST <ip>`
* Do: `set VERBOSE false`
* Do: `run`
* You should see output indicating `cisco:cisco123` was successfully used for login.

## Options

### USERPASS_FILE

File containing users and passwords separated by space, one pair per line.

### USER_FILE

File containing users, one per line.

### PASS_FILE

File containing passwords, one per line

## Scenarios

### ASAv 9.18.1 with ASDM enabled and the `cisco:cisco123` creds set.

```
msf6 > use auxiliary/scanner/http/cisco_asa_asdm_bruteforce
msf6 auxiliary(scanner/http/cisco_asa_asdm_bruteforce) > set RHOST 10.9.49.201
RHOST => 10.9.49.201
msf6 auxiliary(scanner/http/cisco_asa_asdm_bruteforce) > set VERBOSE false
VERBOSE => false
msf6 auxiliary(scanner/http/cisco_asa_asdm_bruteforce) > run

[*] The remote target appears to host Cisco ASA ASDM. The module will continue.
[*] Starting login brute force...
[+] SUCCESSFUL LOGIN - "cisco":"cisco123"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/cisco_asa_asdm_bruteforce) > 
```
