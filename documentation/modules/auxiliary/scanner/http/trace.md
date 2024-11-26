## Vulnerable Application

This module checks if the host(s) is(are) vulnerable to Cross-Site Tracing (XST).
The module does more than just check for the HTTP Trace method, and actually
attempts a trace request to verify that XST is possible.

### Setting up Web Servers with the TRACE Method

This [link](https://www.virtuesecurity.com/kb/web-server-trace-enabled/) describes how
to disable the HTTP TRACE method. In order to enable it, simply follow the opposite of
these instructions (e.g. set `TraceEnable` to `on` for Apache).

## Verification Steps

1. Start `msfconsole`
1. `use auxiliary/scanner/http/trace`
1. `set RHOSTS [ip]`
1. `set RPORT [port]`
1. `run`
1. Check output for presence of XST

## Options

## Scenarios

You can use this module on a single target or several targets. See below for single target usage:

```
msf6 > use auxiliary/scanner/http/trace
msf6 auxiliary(scanner/http/trace) > set RHOSTS YYY.YY.YYY.YYY
RHOSTS => YYY.YY.YYY.YYY
msf6 auxiliary(scanner/http/trace) > set RPORT 443
RPORT => 443
msf6 auxiliary(scanner/http/trace) > set SSL true
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
msf6 auxiliary(scanner/http/trace) > run

[+] YYY.YY.YYY.YYY:443 is vulnerable to Cross-Site Tracing
```

## Confirming with Nmap

```
nmap -sV -Pn [ip] --script=http-trace -p 443    
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-21 20:30 EDT
Nmap scan report for www.hphc.org ([ip])
Host is up (0.029s latency).

PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Apache httpd
|_http-server-header: Apache
|_http-trace: TRACE is enabled

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.53 seconds
```
