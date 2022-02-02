## Description

This module identifies the version of POP3 in use by the server based on the server's banner.
Any POP3 sever should return this information.

## Vulnerable Application

### Install Dovecot on Kali Linux:

With this install, we'll only install POP3 for dovecot, as the other protocols are not required.  However, this is unrealistic
in a production environment.

1. ```sudo apt-get install dovecot-pop3d```
2. ```/etc/init.d/dovecot start```

## Verification Steps

  1. Do: `use auxiliary/scanner/pop3/pop3_version`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Scenarios

### Dovecot 2.3.2 (582970113) on Kali

  ```
  msf5 auxiliary(scanner/pop3/pop3_version) > use auxiliary/scanner/pop3/pop3_version
  msf5 auxiliary(scanner/pop3/pop3_version) > set rhosts 10.168.202.216
  msf5 auxiliary(scanner/pop3/pop3_version) > run

  [+] 10.168.202.216:110    - 10.168.202.216:110 POP3 +OK Dovecot (Debian) ready.\x0d\x0a
  [*] 10.168.202.216:110    - Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
