## Vulnerable Application

This adapter downloads a Linux LoongArch64 ELF over HTTP and executes it.
It can wrap compatible payloads such as `linux/loongarch64/shell_reverse_tcp`.
No vulnerable application is required; the generated command must be executed
on a Linux LoongArch64 system with the selected download utility installed.

## Verification Steps

1. Prepare a Linux LoongArch64 host with WGET and `/bin/sh`.
1. Start `./msfconsole` and select `use exploit/multi/handler`.
1. Set `PAYLOAD` to `cmd/linux/http/loongarch64/shell_reverse_tcp`.
1. Set `LHOST` to the listener address and `LPORT` to the callback port.
1. Set `FETCH_COMMAND` to `WGET`, `FETCH_WRITABLE_DIR` to `/tmp`, and `VERBOSE` to `true`.
1. Run the handler and execute the printed fetch command on the test host.
1. In the resulting shell, run `id` and `uname -a`.
1. Repeat with `FETCH_PIPE` enabled to fetch the command through a shell pipe.

## Options

No specific options

The shared fetch options apply. `FETCH_COMMAND` defaults to `CURL`; select
`WGET` or another installed HTTP-capable utility if CURL is unavailable.
`FETCH_FILELESS=python3.8+` requires Python with `os.memfd_create` support.
`FETCH_FILELESS=shell` uses a LoongArch64 memfd loader and requires writable
`/proc/self/mem` and an accessible VDSO mapping. `shell-search` uses an existing
writable memfd when available, otherwise falling back to a downloaded file.

## Scenarios

To be completed by a human tester with console output from a LoongArch64 Linux system.
