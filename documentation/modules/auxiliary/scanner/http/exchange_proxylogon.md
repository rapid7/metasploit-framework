## Introduction

  An issue was discovered in Microsoft Exchange Server that allows an attacker bypassing the authentication and impersonating as the admin (CVE-2021-26855). By chaining this bug with another
  post-auth arbitrary-file-write vulnerability to get code execution (CVE-2021-27065).

  As a result, an unauthenticated attacker can execute arbitrary commands on Microsoft Exchange Server.

  This vulnerability affects (Exchange 2013 Versions < 15.00.1497.012, Exchange 2016 CU18 < 15.01.2106.013, Exchange 2016 CU19 < 15.01.2176.009, Exchange 2019 CU7 < 15.02.0721.013,
  Exchange 2019 CU8 < 15.02.0792.010).

  All components are vulnerable by default.

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/scanner/http/exchange_proxylogon`
3. Do: `set RHOSTS [IP]`
4. Do: `run`

## Options

1. `METHOD`. HTTP Method to use (for CVE-2021-26855). Default: `POST`
2. `Proxies`. This option is not set by default.
3. `RPORT`. The default setting is `443`. To use: `set RPORT [PORT]`
4. `SSL`. The default setting is `true`.
5. `THREADS`. The default setting is `1`.
6. `VHOST`. This option is not set by default.

## Scenarios

```
msf6 auxiliary(scanner/http/exchange_proxylogon) > options 

Module options (auxiliary/scanner/http/exchange_proxylogon):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   METHOD   POST             yes       HTTP Method to use (for CVE-2021-26855). (Accepted: GET, POST)
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   172.16.5.6       yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    443              yes       The target port (TCP)
   SSL      true             no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host


msf6 auxiliary(scanner/http/exchange_proxylogon) > run

[+] https://172.16.5.6/owa/auth/x.js - The target is vulnerable to CVE-2021-26855.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/exchange_proxylogon) > 
```

## References

1. <https://proxylogon.com/>
2. <https://raw.githubusercontent.com/microsoft/CSS-Exchange/main/Security/http-vuln-cve2021-26855.nse>
