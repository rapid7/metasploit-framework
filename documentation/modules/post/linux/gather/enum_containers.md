## Container Platforms

  This module looks for container platforms running on the target and then lists any currently running containers for each platform found. The currently supported container platforms are:
  
  1. Docker
  2. LXC
  3. RKT

## Verification Steps

  1. Start msfconsole
  2. Get a session via exploit of your choice
  3. Load and run the module `run post/linux/gather/enum_containers`
  4. You should get feedback if any container platforms are runnable by the current user and if there are any active containers running on them

## Options

  **SESSION**

  Which session to use, which can be viewed with `sessions -l`

## Scenarios

Scenario 1: Docker is installed and there  are 4 running containers
```
msf5 post(linux/gather/enum_containers) > set session 4
session => 4
msf5 post(linux/gather/enum_containers) > run

[+] docker: 4 Active Containers
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
6e406d13fde7        ubuntu              "/bin/bash"         5 days ago          Up 45 hours                             test4
3d137beafb08        ubuntu              "/bin/bash"         5 days ago          Up 45 hours                             test3
8cb7e2aff68a        ubuntu              "/bin/bash"         5 days ago          Up 45 hours                             test2
1a339ef0d38e        ubuntu              "/bin/bash"         5 days ago          Up 45 hours                             test1
[*] Post module execution completed
```

Scenario 2: Docker, LXC and RKT are installed
```
msf5 post(linux/gather/enum_containers) > set session 5
session => 5
msf5 post(linux/gather/enum_containers) > run

[+] docker: 4 Active Containers
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
6e406d13fde7        ubuntu              "/bin/bash"         5 days ago          Up 45 hours                             test4
3d137beafb08        ubuntu              "/bin/bash"         5 days ago          Up 45 hours                             test3
8cb7e2aff68a        ubuntu              "/bin/bash"         5 days ago          Up 45 hours                             test2
1a339ef0d38e        ubuntu              "/bin/bash"         5 days ago          Up 45 hours                             test1
[+] lxc: 2 Active Containers
+---------------+---------+-----------------------+-----------------------------------------------+-----------+-----------+
|     NAME      |  STATE  |         IPV4          |                     IPV6                      |   TYPE    | SNAPSHOTS |
+---------------+---------+-----------------------+-----------------------------------------------+-----------+-----------+
| t4testingName | RUNNING | 10.132.199.244 (eth0) | fd42:53d9:b4c9:609e:216:3eff:fece:f6df (eth0) | CONTAINER | 0         |
+---------------+---------+-----------------------+-----------------------------------------------+-----------+-----------+
| ubuntu        | RUNNING | 10.132.199.192 (eth0) | fd42:53d9:b4c9:609e:216:3eff:fe9a:fa5f (eth0) | CONTAINER | 0         |
+---------------+---------+-----------------------+-----------------------------------------------+-----------+-----------+
[+] rkt: 0 Active Containers
[*] Post module execution completed
```

Scenario 3: No container software is runnable
```
msf5 post(linux/gather/enum_containers) > set session 6
session => 6
msf5 post(linux/gather/enum_containers) > run
[-] No container software appears to be installed
[*] Post module execution completed
```
