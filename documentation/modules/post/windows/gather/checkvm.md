This is a post-exploitation module that checks several known registry keys and process names, as a simple way to determine if your target is running inside of a virtual machine.  While many of these are easy to change, triggering a false negative, this script services as a simple pre-check.

The script has been tested on a variety of Windows 10 targets, but changes to hypervisors and VM-related drivers are common.  If you identify misleading output from this tool, please [file an issue](https://github.com/rapid7/metasploit-framework/issues/new) or, even better, [submit a pull request](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md#contributing-to-metasploit).

The script can be run from within a Meterpreter session or from the Metasploit shell:

### Within Meterpreter
```
meterpreter > run post/windows/gather/checkvm
```

### From the Metasploit console
```
msf > use post/windows/gather/checkvm
msf post(windows/gather/checkvm) > set SESSION 1
SESSION => 1
msf post(windows/gather/checkvm) > run

[*] Checking if DESKTOP-Q05UKIU is a Virtual Machine .....
[+] This is a VMware Virtual Machine
[*] Post module execution completed
```

# Example Output

### On a Windows 10 x64 physical machine
```
[*] Checking if DESKTOP-Q05UKIU is a Virtual Machine .....
[*] DESKTOP-Q05UKIU appears to be a Physical Machine
```

### On a Windows 10 x64 VMware VM
```
[*] Checking if DESKTOP-Q05UKIU is a Virtual Machine .....
[+] This is a VMware Virtual Machine
```

### On a Windows 10 x64 Hyper-V VM
```
[*] Checking if DESKTOP-Q05UKIU is a Virtual Machine .....
[+] This is a Hyper-V Virtual Machine running on physical host ASOTO-HYPERV-SERVER

msf > notes

[*] Time: 2018-01-17 18:31:24 UTC Note: host=192.168.77.2 type=host.hypervisor data={:hypervisor=>"MS Hyper-V"}
[*] Time: 2018-01-17 18:31:24 UTC Note: host=192.168.77.2 type=host.physicalHost data={:hypervisor=>"ASOTO-HYPERV-SERVER"}
```
