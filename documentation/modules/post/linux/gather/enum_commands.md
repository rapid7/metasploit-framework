## Vulnerable Application

This module will check which shell commands are available on a system.


## Verification Steps

1. Start msfconsole
1. Get a session
1. Do: `use post/linux/gather/enum_commands`
1. Do: `set session <session ID>`
1. Do: `run`
1. You should receive a list of shell commands


## Options

### DIR

Optional directory name to list (in addition to default system PATH and common paths)


## Scenarios

### Ubuntu 22.04.1 (x86_64)

```
msf6 > use post/linux/gather/enum_commands 
msf6 post(linux/gather/enum_commands) > set session 1
session => 1
msf6 post(linux/gather/enum_commands) > run

[+] Found 3795 executable binaries/commands
/bin/GET
/bin/HEAD
/bin/POST
/bin/VGAuthService
/bin/X
/bin/X11
/bin/Xephyr
/bin/Xorg
/bin/Xwayland
/bin/[
/bin/aa-enabled
/bin/aa-exec
/bin/aa-features-abi

...

[*] Post module execution completed
msf6 post(linux/gather/enum_commands) > 
```
