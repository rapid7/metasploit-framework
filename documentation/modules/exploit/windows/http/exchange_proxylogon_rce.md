## Vulnerable Application

CVE-2021-28855 is a pre-authentication SSRF (Server Side Request Forgery) which allows an attacker to
bypass authentication by sending specially crafted HTTP requests. This vulnerability is part of an attack
chain used to perform an RCE (Remote Code Execution).

CVE-2021-27065 is a post-auth arbitrary-file-write vulnerability to get code execution and the second part
of ProxyLogon attack chain.

This vulnerability affects (Exchange 2013 Versions < 15.00.1497.012, Exchange 2016 CU18 < 15.01.2106.013,
Exchange 2016 CU19 < 15.01.2176.009, Exchange 2019 CU7 < 15.02.0721.013, Exchange 2019 CU8 < 15.02.0792.010).

### Introduction

This module exploit a vulnerability on Microsoft Exchange Server that allows an attacker bypassing the
authentication, impersonating as the admin (CVE-2021-26855) and write arbitrary file (CVE-2021-27065) to
get the RCE (Remote Code Execution).

By taking advantage of this vulnerability, you can execute arbitrary commands on the remote Microsoft
Exchange Server.

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

```

## References

1. <https://proxylogon.com/>
2. <http://aka.ms/exchangevulns>
3. <https://www.praetorian.com/blog/reproducing-proxylogon-exploit>
4. <https://testbnull.medium.com/ph%C3%A2n-t%C3%ADch-l%E1%BB%97-h%E1%BB%95ng-proxylogon-mail-exchange-rce-s%E1%BB%B1-k%E1%BA%BFt-h%E1%BB%A3p-ho%C3%A0n-h%E1%BA%A3o-cve-2021-26855-37f4b6e06265>
