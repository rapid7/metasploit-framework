## Vulnerable Application

This Gathers information about the target to apply to the host database. This
is intended to add more information for the framework to utilize when running
more modules against the same target.

## Verification Steps
1. Start msfconsole
2. Get (any) session
3. Do: `use post/linux/recon/host_info`
4. Do: `set SESSION <session id>`
5. Do: `run`

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

### Windows 10 Home (10.0.19045 N/A Build 19045)

```
msf6 > use post/windows/recon/host_info 
msf6 post(windows/recon/host_info) > set session 1 
session => 1
msf6 post(windows/recon/host_info) > run

[+] [2023.11.06-22:06:28] Hostname is win10
[+] [2023.11.06-22:06:29] The session is running on address 192.168.56.123 (08:00:27:28:C9:B6) on interface Ethernet 2
[+] [2023.11.06-22:06:29] The hosts architecture is x64
[+] [2023.11.06-22:06:30] The host is running Microsoft Windows 10 Home (10.0.19045 N/A Build 19045)
[+] [2023.11.06-22:06:30] The user running on the session is win10\radmin
[*] Post module execution completed
msf6 post(windows/recon/host_info) > hosts 

Hosts
=====

state  mac           address       name   arch  os_name            os_flavor  os_sp  os_family  updated_at   service_cou  vuln_count  purpose  info  comments
                                                                                                             nt
-----  ---           -------       ----   ----  -------            ---------  -----  ---------  ----------   -----------  ----------  -------  ----  --------
alive  08:00:27:28:  192.168.56.1  win10  x64   Microsoft Windows                               2023-11-07   0            1
       C9:B6         23                          10 Home (10.0.19                               03:05:52 UT
                                                045 N/A Build 190                               C
                                                45)

msf6 post(windows/recon/host_info) > creds 
Credentials
===========

host  origin          service  public        private  realm  private_type  JtR Format  cracked_password
----  ------          -------  ------        -------  -----  ------------  ----------  ----------------
      192.168.56.123           win10\radmin                                            

msf6 post(windows/recon/host_info) >
```
