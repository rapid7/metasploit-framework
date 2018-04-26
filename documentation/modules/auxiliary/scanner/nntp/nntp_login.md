## Description

  This module attempts to authenticate to NNTP services which support the AUTHINFO authentication extension.

  This module supports AUTHINFO USER/PASS authentication, but does not support AUTHINFO GENERIC or AUTHINFO SASL authentication methods.

  If you have loaded a database plugin and connected to a database this module will record successful logins and hosts so you can track your access.


## Vulnerable Application

  This module has been tested successfully on:

  * [SurgeNews](http://netwinsite.com/surgenews/) on Windows 7 SP 1.
  * [SurgeNews](http://netwinsite.com/surgenews/) on Ubuntu Linux.
  * [INN2](https://www.eyrie.org/~eagle/faqs/inn.html) on Debian Linux.


## Verification Steps

  1. Do: `use auxiliary/scanner/nntp/nntp_login`
  2. Do: `set RHOSTS [IP]`
  3. Do: `set RPORT [IP]`
  4. Do: `run`


## Scenarios

  ```
  msf auxiliary(nntp_login) > run

  [+] 172.16.191.166:119 - 172.16.191.166:119 Successful login with: 'asdf' : 'asdf'
  [+] 172.16.191.166:119 - 172.16.191.166:119 Successful login with: 'zxcv' : 'zxcv'
  [+] 172.16.191.166:119 - 172.16.191.166:119 Successful login with: 'test' : 'test'
  [*] Scanned 1 of 2 hosts (50% complete)
  [+] 172.16.191.213:119 - 172.16.191.213:119 Successful login with: 'asdf' : 'asdf'
  [+] 172.16.191.213:119 - 172.16.191.213:119 Successful login with: 'admin' : 'admin'
  [+] 172.16.191.213:119 - 172.16.191.213:119 Successful login with: 'user' : 'pass'
  [*] Scanned 2 of 2 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```

