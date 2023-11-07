## Vulnerable Application

This Gathers information about the target to apply to the host database. This
is intended to add more information for the framework to utilize when running
more modules against the same target.

## Verification Steps

1. Start msfconsole
2. Get (any) session
3. `use post/linux/recon/host_info`
4. `set SESSION <session id>`
5. `run`

## Options

### RECON_HOSTNAME

Checks the hostname of the target.

### RECON_ADDRESS

Gathers the address that the session is currently on as well as its MAC and
interface

### RECON_ARCH

Gathers the architecture of the target and reports it to the database

### RECON_SESSION_USER

Gathers the current user on the given session and reports it to credentials

## Scenarios

### Debian 11

```
msf6 > use post/linux/recon/host_info 
msf6 post(linux/recon/host_info) > set session 1 
session => 1
msf6 post(linux/recon/host_info) > run

[+] [2023.11.06-21:55:31] Hostname is Debian
[+] [2023.11.06-21:55:32] The session is running on address 192.168.56.126 (08:00:27:8f:fc:e6) on interface enp0s8
[+] [2023.11.06-21:55:32] The hosts architecture is x64
[+] [2023.11.06-21:55:33] The host is running debian linux
[+] [2023.11.06-21:55:33] version Debian GNU/Linux 11
[+] [2023.11.06-21:55:33] running kernel Linux Debian 5.10.0-25-amd64 #1 SMP Debian 5.10.191-1 (2023-08-16) x86_64 GNU/Linux
[+] [2023.11.06-21:55:34] The user running on the session is radmin
[*] Post module execution completed
msf6 post(linux/recon/host_info) > hosts 

Hosts
=====

state  mac           address       name    arch  os_name  os_flavor           os_sp  os_family  updated_at   service_cou  vuln_count  purpose  info  comments
                                                                                                             nt
-----  ---           -------       ----    ----  -------  ---------           -----  ---------  ----------   -----------  ----------  -------  ----  --------
alive  08:00:27:8f:  192.168.56.1  Debian  x64   debian   Debian GNU/Linux 1                    2023-11-07   0            1
       fc:e6         26                                   1                                     02:54:50 UT
                                                                                                C

msf6 post(linux/recon/host_info) > 
```
