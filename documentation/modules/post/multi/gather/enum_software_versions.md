## Vulnerable Application

  This module uses an existing session on any Windows, Linux, BSD, Solaris, OSX or Android machine
  to gather information about all software installed on the target machine and their versions.

  This module therefore targets any machine running Windows, Linux, BSD, Solaris, OSX, or Android. Note
  that for Linux systems, software enumeration is done via package managers. As a result the results may
  not reflect all of the available software on the system simply because users may have installed additional
  software from alternative sources such as source code that these package managers are not aware of.

## Verification Steps

  1. Get session
  2. Do `use post/multi/gather/enum_software_versions`
  3. Do `set SESSION <session id>`
  4. Do `run`
  5. See loot.

## Options

This module does not use any special options beyond the standard `SESSION` option which 
is set to the value of the session the user wishes to run this module on.

## Scenarios

### Windows Server 2019 Standard Edition x64 Running as a Low Privileged User
```
msf6 exploit(multi/handler) > use post/multi/gather/enum_software_versions 
msf6 post(multi/gather/enum_software_versions) > show options

Module options (post/multi/gather/enum_software_versions):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

msf6 post(multi/gather/enum_software_versions) > set SESSION 1 
SESSION => 1
msf6 post(multi/gather/enum_software_versions) > run

[+] Stored information about the installed products to the loot file at /home/gwillcox/.msf4/loot/20200915173649_default_172.27.37.216_host.windows.sof_930739.txt
[*] Post module execution completed
msf6 post(multi/gather/enum_software_versions) > cat /home/gwillcox/.msf4/loot/20200915173649_default_172.27.37.216_host.windows.sof_930739.txt
[*] exec: cat /home/gwillcox/.msf4/loot/20200915173649_default_172.27.37.216_host.windows.sof_930739.txt

Description                     InstallDate  Name                            Version      
Pragma TelnetServer             20200911     Pragma TelnetServer             7.0.10.1990  
Google Update Helper            20200910     Google Update Helper            1.3.35.451   
VanDyke Software SecureCRT 8.7  20200911     VanDyke Software SecureCRT 8.7  8.7.3        
msf6 post(multi/gather/enum_software_versions) > 
```