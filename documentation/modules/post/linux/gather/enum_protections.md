## Vulnerable Application

This module enumerates system hardening and security protections on a Linux
target. It requires an existing session on any Linux host.

It checks for:

1. **Kernel hardening**: ASLR, SMEP, SMAP, KPTI, KAISER, Exec-Shield,
   kernel pointer restrictions, dmesg restrictions, unprivileged BPF
   restrictions, and user namespace availability.
2. **Security modules**: SELinux (with enforcing/permissive state), Yama,
   grsecurity, PaX, and LKRG.
3. **Security software**: Antivirus, IDS/IPS, firewalls, EDR agents,
   sandboxes, and monitoring tools - detected via both executable paths
   and configuration file/directory presence.

Results are saved as notes in the database when a database is connected.

## Verification Steps

1. Start msfconsole
2. Get a session via exploit of your choice
3. Do: `use post/linux/gather/enum_protections`
4. Do: `set SESSION <session>`
5. Do: `run`
6. You should see output listing detected kernel protections, security
   modules, installed security executables, and configuration files.

## Scenarios

### Ubuntu 22.04 with default protections

```
msf6 post(linux/gather/enum_protections) > set SESSION 1
SESSION => 1
msf6 post(linux/gather/enum_protections) > run

[*] Running module against 192.168.200.158 [ubuntu-22-04-amd64]
[*] Info:
[*] 	Ubuntu 22.04 LTS
[*] 	Linux ubuntu-22-04-amd64 5.19.0-38-generic #39~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Mar 17 21:16:15 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
[*] Finding system protections...
[+] ASLR is enabled
[+] SMEP is enabled
[+] SMAP is enabled
[+] Unprivileged BPF is disabled
[+] Kernel pointer restriction is enabled
[+] dmesg restriction is enabled
[+] Yama is installed and enabled
[+] User namespaces are enabled (unprivileged may be available)
[*] Finding installed applications via their executables...
[+] aa-status found: /usr/sbin/aa-status
[+] iptables found: /usr/sbin/iptables
[+] logrotate found: /usr/sbin/logrotate
[+] nft found: /usr/sbin/nft
[+] tcpdump found: /usr/bin/tcpdump
[+] ufw found: /usr/sbin/ufw
[*] Finding installed applications via their configuration files...
[+] nftables found: /etc/nftables.conf
[*] Post module execution completed
```
