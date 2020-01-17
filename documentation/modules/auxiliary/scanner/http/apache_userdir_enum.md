## Description

This module determines if usernames are valid on a server running Apache with the `UserDir` directive enabled. 
It takes advantage of Apache returning different error codes for usernames that do not exist and for usernames that exist but have no `public_html` directory.

## Vulnerable Application

### Enabling  `UserDir` on Ubuntu 16.04 with Apache installed
1. `sudo a2enmod userdir`
2. `sudo service apache2 restart`

## Verification Steps

1. Do: ```use auxiliary/scanner/http/apache_userdir_enum```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

### Apache 2.4.18 on Ubuntu 16.04

![apache_userdir_enum Demo](https://i.imgur.com/UZanfTI.gif)

```
msf5 > use auxiliary/scanner/http/apache_userdir_enum
msf5 auxiliary(scanner/http/apache_userdir_enum) > set rhosts alderaan
rhosts => alderaan
msf5 auxiliary(scanner/http/apache_userdir_enum) > run

[*] http://192.168.6.172/~ - Trying UserDir: ''
[*] http://192.168.6.172/ - Apache UserDir: '' not found
[*] http://192.168.6.172/~4Dgifts - Trying UserDir: '4Dgifts'
[*] http://192.168.6.172/ - Apache UserDir: '4Dgifts' not found
...
[*] http://192.168.6.172/~zabbix - Trying UserDir: 'zabbix'
[*] http://192.168.6.172/ - Apache UserDir: 'zabbix' not found
[*] http://192.168.6.172/~vagrant - Trying UserDir: 'vagrant'
[*] http://192.168.6.172/ - Apache UserDir: 'vagrant' not found
[+] http://192.168.6.172/ - Users found: backup, bin, daemon, games, gnats, irc, list, lp, mail, man, messagebus, news, nobody, proxy, sshd, sync, sys, syslog, uucp
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming using Nmap

```
$ nmap -sV --script http-userdir-enum.nse alderaan
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-16 23:12 CST
Nmap scan report for alderaan (192.168.6.172)
Host is up (0.0032s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.82 seconds
```
