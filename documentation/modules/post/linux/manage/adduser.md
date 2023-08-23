## Vulnerable Application

This module creates a new user using the standard (or non-standard) means of
creating a new user on the victim OS. This module requires root privileges
in order to run as it needs access to /etc/shadow.

## Tested Versions

 * Debian 11.7
 * Alpine 3.17
 * Fedora 37

## Verification Steps

  1. Start msfconsole
  2. Get a Meterpreter session
  3. `use post/linux/manage/adduser`
  4. `set session <id>`
  5. attempt to log in with account


## Options

### USERNAME

Provide the username that can be used. Linux has a standardization that means
that password have to follow this regex to be able to be used as a username
`^[a-z][a-z0-9_-]{0,31}$`

### PASSWORD

Provides a password for your new user.

### SHELL

Define the shell that is to be used. Defaults to `/bin/sh` but can be changed
to a shell that exists.

### HOME

Speficy the home directory of the new user. An empty value specifies that the
home directory does not exist.

### GROUPS

Specify what groups the new user should be under. Takes one or multiple values
to provide what groups the new user will have.

## Advanced Options

### SudoMethod

Sets the method that the new user will get root access. This can be done
through multiple methods provided below:

 * **GROUP** - Put the new user in the sudo group (is added automatically to
 the groups option)
 * **SUDO_FILE** - Adds user directly to `/etc/sudoers` file in order to
 prevent being removed from sudoers group
 * **NONE** - No sudo methods are provided. New user is a unprivileged user

### UseraddMethod

Set the method used to create new user.

 * **AUTO** - The default option. The module will figure out how to add in the
 user by itself.
 * **MANUAL** - Instead of using a binary on the system, add in the new user
 directly into the FileSystem. This can be preferred if the binary can be
 inconsistent or tracked.
 * **CUSTOM** - Set the custom binary to add in a user. Can be used to pipe
 auto detection towards a preferred binary such as debians dual choice of
 useradd and adduser, or alpines busybox.

### UseraddBinary

Set the binary used to add the user. The two main binaries concerned with are
`useradd` and `adduser`. If you want to overwrite which binary is used or give
an absolute path rather than a relative path, you can override it here.

### MissingGroups

This option decides how to manage groups requested that are missing on the victim.
The possible options are provided as such:

 * **ERROR** - If a group is missing, fail the module with a given error
 * **IGNORE** - If the group doesnt exist, continue to add the user, but dont add
 them to the missing groups
 * **CREATE** - If the group doesnt exist, then make them first then add the user
 to them

### PasswordHashType

Allows the user to decide how their password will be encrypted on the system.
The options are between `DES`, `MD5`, `SHA256`, and `SHA512`. This can be
advantageous to blend in with the main system by using the same password
encryption scheme as the rest of the users. Or if one encryption type isn't
compatible with a given target.

## Scenarios

```
msf6 > use post/linux/manage/adduser
msf6 post(linux/manage/adduser) > set session 6 
session => 6
msf6 post(linux/manage/adduser) > set sudomethod GROUP 
sudomethod => GROUP
msf6 post(linux/manage/adduser) > set groups wheel docker wireshark
groups => wheel docker wireshark
msf6 post(linux/manage/adduser) > set username metasploit
username => metasploit
msf6 post(linux/manage/adduser) > set password abcd1234
password => abcd1234
msf6 post(linux/manage/adduser) > set shell /bin/bash
shell => /bin/bash
msf6 post(linux/manage/adduser) > set home /home/metasploit
home => /home/metasploit
msf6 post(linux/manage/adduser) > set missinggroups CREATE 
missinggroups => CREATE
msf6 post(linux/manage/adduser) > set verbose true 
verbose => true
msf6 post(linux/manage/adduser) > run

[-] Groups [docker] do not exist on system
[*] Running on Debian 11.7 (Linux 5.10.0-23-amd64)
[*] Useradd exists. Using that
[*] groupadd docker
[*] 
[+] Added docker group
[*] useradd --password $1$WDX5Sg4N$Hcfx4HSigx/KbvtSzhsXD/ --home-dir /home/metasploit --groups wheel,docker,wireshark,sudo --shell /bin/bash --no-log-init metasploit
[*] 
[*] Post module execution completed
msf6 post(linux/manage/adduser) > run

[*] Running on Debian 11.7 (Linux 5.10.0-23-amd64)
[*] Useradd exists. Using that
[*] useradd --password $1$EVUDKEc3$Sip80MAZmLv.2vOhzW/4k0 --home-dir /home/metasploit --groups wheel,docker,wireshark,sudo --shell /bin/bash --no-log-init metasploit
[*] useradd: user 'metasploit' already exists
[*] Post module execution completed
```
