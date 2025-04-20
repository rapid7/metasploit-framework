## Vulnerable Application

Erlang/OTP is a set of libraries for the Erlang programming language.

Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker
to perform unauthenticated remote code execution (RCE).

By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access
to affected systems and execute arbitrary commands without valid credentials. This issue is patched in
versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20.

### Introduction

This module scans for CVE-2025-32433, a pre-authentication vulnerability in Erlang-based SSH servers
that allows remote command execution. It identifies vulnerable targets by connecting to the SSH service,
checking for an Erlang-specific banner, and sending a crafted packets to test the server's response.

## Testing

### Vulnerable application

Execute the following commands:

```bash
git clone https://github.com/ProDefense/CVE-2025-32433
cd CVE-2025-32433
docker build -t cve-ssh:latest .
docker run -d -p 2222:2222 cve-ssh:latest
```

### Patched application

Execute the following commands:

```bash
git clone https://github.com/exa-offsec/ssh_erlangotp_rce
cd ssh_erlangotp_rce/patched
docker build -t patched-ssh:latest .
docker run -d -p 2223:2223 patched-ssh:latest
```

## Verification Steps

1. Start msfconsole
2. Do: `auxiliary/scanner/ssh/ssh_erlangotp`
3. Do: `set RHOSTS [IP]`
4. Do: `run`

## Scenarios

### Vulnerability scanner

```
msf6 auxiliary(scanner/ssh/ssh_erlangotp) > options 

Module options (auxiliary/scanner/ssh/ssh_erlangotp):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS   192.168.1.16     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    2222             yes       The target port (TCP)
   THREADS  1                yes       The number of concurrent threads (max one per host)

View the full module info with the info, or info -d command.

[*] 192.168.1.16:2222      - ssh://192.168.1.16:2222 - Sending SSH_MSG_KEXINIT...
[*] 192.168.1.16:2222      - ssh://192.168.1.16:2222 - Sending SSH_MSG_CHANNEL_OPEN...
[*] 192.168.1.16:2222      - ssh://192.168.1.16:2222 - Sending SSH_MSG_CHANNEL_REQUEST (pre-auth)...
[+] 192.168.1.16:2222      - ssh://192.168.1.16:2222 - The target is vulnerable to CVE-2025-32433.
[*] 192.168.1.16:2222      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## References

1. <https://x.com/Horizon3Attack/status/1912945580902334793>
2. <https://platformsecurity.com/blog/CVE-2025-32433-poc>
3. <https://github.com/ProDefense/CVE-2025-32433>
