## Description

This module identifies the version of IMAP in use by the server, as well as some of the login options.
Any IMAP sever should return this information.

## Vulnerable Application

### Install Dovecot on Kali Linux:

With this install, we'll only install IMAP for dovecot, as the other protocols are not required.  However, this is unrealistic
in a production environment.

1. ```sudo apt-get install dovecot-imapd```
2. ```/etc/init.d/dovecot start```

## Verification Steps

  1. Do: `use auxiliary/scanner/imap/imap_version`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Options

  **IMAPPASS**

  A password for an IMAP account.

  **IMAPUSER**

  A username for an IMAP account.

## Scenarios

### Dovecot 2.3.2 (582970113) on Kali

  ```
  msf5 > use auxiliary/scanner/imap/imap_version 
  msf5 auxiliary(scanner/imap/imap_version) > set rhosts 10.168.202.216
  rhosts => 10.168.202.216
  msf5 auxiliary(scanner/imap/imap_version) > run

  [+] 10.168.202.216:143    - 10.168.202.216:143 IMAP * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot (Debian) ready.\x0d\x0a
  [*] 10.168.202.216:143    - Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
## Confirming

### [nmap](https://nmap.org/nsedoc/scripts/imap-capabilities.html)

```
# nmap -p 143 -sV -script=imap-capabilities 10.168.202.216
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-11 18:43 EDT
Nmap scan report for 10.168.202.216
Host is up (0.000044s latency).

PORT    STATE SERVICE VERSION
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: LITERAL+ more AUTH=PLAINA0001 IDLE have LOGIN-REFERRALS ENABLE OK Pre-login listed capabilities post-login ID STARTTLS IMAP4rev1 SASL-IR
```
