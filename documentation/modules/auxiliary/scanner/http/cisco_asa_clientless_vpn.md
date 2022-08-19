## Vulnerable Application

### Description

This module scans for Cisco ASA Clientless SSL VPN (WebVPN) web login portals and
performs login brute-force to identify valid credentials.

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
1. After the import is complete assign `Network Adapter` (1 is implied) the desired
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

The next part of the installation will require a Windows machine. From your Windows machine:

1. Connect to your ASA's web interface (e.g. `https://10.9.49.201/admin/public/index.html`).
1. Click "Install ASDM Launcher"
1. Enter creds `blank`:labpass1 (where blank is nothing and labpass1 is your enable password)
1. Install the downloaded `dm-launcher.msi` (before 7.18.1 it will be unsigned)
1. If Java isn't installed, intall Java 1.8 (current at time of writing is 8 Update 333): https://www.java.com/en/download/
1. Start the ASDM Launcher via `C:\Program Files (x86)\Cisco Systems\ASDM\run.bat`
1. Enter your ASAv's IP address (10.9.249.201)
1. Enter a blank username
1. Enter the enable password (`labpass1`)

Now to enable the webvpn interface from ASDM:

1. Go to `Configuration -> Remote Access VPN -> Clientless SSL VPN Access -> Connection Profiles`
1. In the `Access Interfaces` view, click the radio button to `Allow Access` from the `outside` interface
1. Hit apply

Verify that the Clientless SSL VPN is now enabled by navigating to the SSL VPN login on your ASA. For example,
navigate to `https://10.9.49.201/+CSCOE+/logon.html`.

Next, we'll create a Clientless SSL VPN user for brute-force testing. From ASDM:

1. Go to `Configuration -> Device Management -> Users/AAA -> User Accounts`
1. Click `Add`
1. Keep the default username (`user1`)
1. Enter and confirm a password (e.g. `user1`)
1. Set the privilege level to 0 (I'm not sure this step is actually required but)
1. Select the `No ASDM, SSH, Telnet, or Console access` radio
1. Hit `OK`
1. Hit `Apply`

Finally, we'll enable logging into the SSL VPN portal:

1. Go to `Configuration -> Device Management -> Users/AAA -> Dynamic Access Policies`
1. Select the `DfltAccessPolicy` and click `Edit`
1. Select `Access Method` tab
1. Click on the `Web-Portal` radio button

You should now be able to log in to the SSL VPN web portal using `user1`:`user1`.

## Verification Steps

* Follow the above instructions to configure ASAv, Clientless SSL VPN, and add a user for testing
* Add the user to `data/wordlists/http_default_userpass.txt` as `user1 user1`
* Do: `use auxiliary/scanner/http/cisco_asa_clientless_vpn`
* Do: `set RHOST <ip>`
* Do: `set VERBOSE false`
* Do: `run`
* You should see output indicating `user1:user1` was successfully used for login.

## Options

### GROUP

The connection profile to use. By default this is blank, but administrators can configure various different
profiles that users can select from the drop down menu at the top of the login page. The alias in the drop
down is *not* the value of `GROUP`. You need to extract it from the HTML.

For example, my administrator has a profile named `TunnelGroup1` using the alias `alias1`. The drop down menu
will show `alias1` but `TunnelGroup1` is the required value. In the page's HTML you'll find:

```
<option value="TunnelGroup1" selected>alias1</option>
```

To use `TunnelGroup1` you'd `set GROUP TunnelGroup1`.

### USERPASS_FILE

File containing users and passwords separated by space, one pair per line.

### USER_FILE

File containing users, one per line.

### PASS_FILE

File containing passwords, one per line

## Scenarios

### ASAv 9.18.1 with Clientless SSL VPN enabled and the `user1:user1` creds set.

Simply using the default HTTP username and password lists and `user1:user1` added to
`data/wordlists/http_default_userpass.txt`.

```
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > use auxiliary/scanner/http/cisco_asa_clientless_vpn
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > set VERBOSE false
VERBOSE => false
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > set RHOST 10.9.49.201
RHOST => 10.9.49.201
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > run

[*] The remote target appears to host Cisco SSL VPN Service. The module will continue.
[*] Starting login brute force...
[+] SUCCESSFUL LOGIN - "user1":"user1"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > 
```

## ASAv 9.18.1 with Clientless SSL VPN enabled and the `user1:user1` on the `TunnelGroup1` Connection Profile

```
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > use auxiliary/scanner/http/cisco_asa_clientless_vpn
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > set VERBOSE false
VERBOSE => false
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > set RHOST 10.9.49.201
RHOST => 10.9.49.201
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > run

[*] The remote target appears to host Cisco SSL VPN Service. The module will continue.
[*] Starting login brute force...
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > set GROUP TunnelGroup1
GROUP => TunnelGroup1
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > run

[*] The remote target appears to host Cisco SSL VPN Service. The module will continue.
[*] Starting login brute force...
[+] SUCCESSFUL LOGIN - "user1":"user1"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/cisco_asa_clientless_vpn) > 
```
