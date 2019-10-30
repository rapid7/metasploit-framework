## Description

  This module examines the sudoers configuration for the session user
  and lists the commands executable via `sudo`.
 
  This module also inspects each command and reports potential avenues
  for privileged code execution due to poor file system permissions or
  permitting execution of executables known to be useful for privesc,
  such as utilities designed for file read/write, user modification,
  or execution of arbitrary operating system commands.

  Note, you may need to provide the password for the session user.


## Verification Steps
 
  1. Start `msfconsole`
  2. Get a session
  3. `use post/multi/recon/sudo_commands`
  4. `set SESSION [SESSION]`
  5. `run`
  6. You should receive a list of available `sudo` commands


## Options

  **SESSION**

  Which session to use, which can be viewed with `sessions`

  **SUDO_PATH**

  Path to sudo executable (default: `/usr/bin/sudo`)

  **PASSWORD**

  Password for the session user


## Scenarios

  ```
  msf5 > use post/multi/recon/sudo_commands
  msf5 post(multi/recon/sudo_commands) > set session 1
  session => 1
  msf5 post(multi/recon/sudo_commands) > set verbose true
  verbose => true
  msf5 post(multi/recon/sudo_commands) > run

  [*] Executing: /usr/bin/sudo -n -l
  Matching Defaults entries for wvu on localhost:
      !visiblepw, always_set_home, match_group_by_gid, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

  User wvu may run the following commands on localhost:
      (ALL) ALL
      (ALL) NOPASSWD: ALL
      (root) /sbin/mount /mnt/cdrom, /sbin/umount /mnt/cdrom
      (root) /sbin/shutdown -h now

  [*] Command: "ALL" RunAsUsers: ALL
  [+] sudo any command!
  [*] Command: "ALL" RunAsUsers: ALL without providing a password
  [+] sudo any command!
  [*] Command: "/sbin/mount /mnt/cdrom" RunAsUsers: root
  [*] Command: "/sbin/umount /mnt/cdrom" RunAsUsers: root
  [*] Command: "/sbin/shutdown -h now" RunAsUsers: root

  Sudo Commands
  =============

    Command                  RunAsUsers  RunAsGroups  Password?  Privesc?
    -------                  ----------  -----------  ---------  --------
    /sbin/mount /mnt/cdrom   root                     True
    /sbin/shutdown -h now    root                     True
    /sbin/umount /mnt/cdrom  root                     True
    ALL                      ALL                      True       True
    ALL                      ALL                                 True

  [+] Output stored in: /Users/user/.msf4/loot/20180613134731_default_192.168.56.101_sudo.commands_305964.txt
  [*] Post module execution completed
  msf5 post(multi/recon/sudo_commands) > cat /Users/user/.msf4/loot/20180613134731_default_192.168.56.101_sudo.commands_305964.txt
  [*] exec: cat /Users/user/.msf4/loot/20180613134731_default_192.168.56.101_sudo.commands_305964.txt

  Command,RunAsUsers,RunAsGroups,Password?,Privesc?
  "/sbin/mount /mnt/cdrom","root","","True",""
  "/sbin/shutdown -h now","root","","True",""
  "/sbin/umount /mnt/cdrom","root","","True",""
  "ALL","ALL","","True","True"
  "ALL","ALL","","","True"
  msf5 post(multi/recon/sudo_commands) >
  ```

