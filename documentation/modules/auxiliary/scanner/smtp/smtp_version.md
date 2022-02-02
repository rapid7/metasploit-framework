## Description

This module grabs the banner from an SMTP server.

## Vulnerable Application

### Postfix on Kali Linux:

This is mainly based on the instructions from [digitalocean.com](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-postfix-on-ubuntu-16-04).
In this case, we don't need to configure all the users and set up the server fully, just enough to display a banner.


1. ```apt-get install postfix```
  1. Select `Internet Site`
  2. Select OK, the default is fine
2. ```systemctl restart postfix```

## Verification Steps

  1. Do: `use auxiliary/scanner/smtp/smtp_version`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Scenarios

### Postfix 3.3.0-1+b1 (Ubuntu package number) on Kali (using above config)

  ```
  msf5 > use auxiliary/scanner/smtp/smtp_version 
  msf5 auxiliary(scanner/smtp/smtp_version) > set rhosts 10.168.202.216
  rhosts => 10.168.202.216
  msf5 auxiliary(scanner/smtp/smtp_version) > run
  
  [+] 10.168.202.216:25     - 10.168.202.216:25 SMTP 220 rageKali.ragegroup ESMTP Postfix (Debian/GNU)\x0d\x0a
  ```
