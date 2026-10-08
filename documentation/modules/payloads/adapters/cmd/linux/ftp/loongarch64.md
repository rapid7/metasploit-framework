## Vulnerable Application

This adapter downloads a Linux LoongArch64 ELF over FTP and executes it.
No vulnerable application is required; the generated command must run on a
Linux LoongArch64 system with FTP or TNFTP installed.

## Verification Steps

1. Prepare a Linux LoongArch64 host with FTP or TNFTP and `/bin/sh`.
1. Start `./msfconsole` and select `use exploit/multi/handler`.
1. Set `PAYLOAD` to `cmd/linux/ftp/loongarch64/shell_reverse_tcp`.
1. Set `LHOST`, `LPORT`, `FETCH_COMMAND` to `FTP` or `TNFTP`, and `VERBOSE` to `true`.
1. Run the handler and execute the printed fetch command on the test host.
1. In the resulting shell, run `id` and `uname -a`.

## Options

No specific options

The shared fetch options apply.

## Scenarios

To be completed by a human tester with console output from a LoongArch64 Linux system.
