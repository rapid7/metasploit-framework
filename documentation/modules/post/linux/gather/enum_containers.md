## Container Platforms

  This module looks for container platforms running on the target and then lists any currently running containers for each platform found. The currently supported container platforms are:
  
  1. Docker
  2. LXC
  3. RKT

## Verification Steps

  1. Start msfconsole
  2. Get a session via exploit of your choice
  3. Load the module `use post/linux/gather/enum_containers`
  4. Set the session `set session 1`
  5. run the module `run`
  6. You should get feedback if any container platforms are runnable by the current user and if there are any active containers running on them

## Options

  **SESSION**

  Which session to use, which can be viewed with `sessions -l`
 
  **CMD**

  Optional shell command to run on each running container

## Scenarios

Scenario 1: Docker is installed with 4 running containers
```
msf5 post(linux/gather/enum_containers) > set session 4
session => 4
msf5 post(linux/gather/enum_containers) > run

[+] docker: 4 Running Containers / 4 Total
[+] 
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
6e406d13fde7        ubuntu              "/bin/bash"         10 days ago         Up 3 hours                              test4
3d137beafb08        ubuntu              "/bin/bash"         10 days ago         Up 3 hours                              test3
8cb7e2aff68a        ubuntu              "/bin/bash"         10 days ago         Up 3 hours                              test2
1a339ef0d38e        ubuntu              "/bin/bash"         10 days ago         Up 3 hours                              test1
[*] Post module execution completed
```

Scenario 2: Docker, LXC and RKT are installed, and each of them are running their own containers
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
[+] lxc: 2 Running Containers / 3 Total
[+] 
+---------------+---------+-----------------------+-----------------------------------------------+-----------+-----------+
|     NAME      |  STATE  |         IPV4          |                     IPV6                      |   TYPE    | SNAPSHOTS |
+---------------+---------+-----------------------+-----------------------------------------------+-----------+-----------+
| privesc       | STOPPED |                       |                                               | CONTAINER | 0         |
+---------------+---------+-----------------------+-----------------------------------------------+-----------+-----------+
| t4testingName | RUNNING | 10.132.199.244 (eth0) | fd42:53d9:b4c9:609e:216:3eff:fece:f6df (eth0) | CONTAINER | 0         |
+---------------+---------+-----------------------+-----------------------------------------------+-----------+-----------+
| ubuntu        | RUNNING | 10.132.199.192 (eth0) | fd42:53d9:b4c9:609e:216:3eff:fe9a:fa5f (eth0) | CONTAINER | 0         |
+---------------+---------+-----------------------+-----------------------------------------------+-----------+-----------+

[+] rkt: 0 Active Containers / 0 Total
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

Scenario 4: List all containers and execute the `env` command on all running containers
```
msf5 post(linux/gather/enum_containers) > set session 6
session => 6
msf5 post(linux/gather/enum_containers) > set cmd env
cmd => env
msf5 post(linux/gather/enum_containers) > run

[+] docker: 2 Running Containers / 2 Total
[+] 
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
8cb7e2aff68a        ubuntu              "/bin/bash"         10 days ago         Up 3 hours                              test2
1a339ef0d38e        ubuntu              "/bin/bash"         10 days ago         Up 3 hours                              test1

[*] Executing command on docker container test2
[*] Running docker exec 'test2' env
[+] PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=8cb7e2aff68a
HOME=/root
[*] Executing command on docker container test1
[*] Running docker exec 'test1' env
[+] PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=1a339ef0d38e
HOME=/root
[*] Post module execution completed
```

Scenario 5: Docker, LXC, and RKT are all installed on the target but the user cannot enumerate all containers due to a lack of permissions
```
msf5 post(linux/gather/enum_containers) > exploit

[+] docker was found on the system!
[-] Was unable to enumerate the number of docker containers due to a lack of permissions!
[-] No active or inactive containers were found for docker

[+] lxc was found on the system!
[+] lxc: 1 Running Containers / 1 Total
NAME    STATE   IPV4                 IPV6                                         TYPE      SNAPSHOTS
one-fox RUNNING 10.166.198.97 (eth0) fd42:a29:a47e:79c6:216:3eff:fe1f:1dca (eth0) CONTAINER 0
[+] Results stored in: /home/gwillcox/.msf4/loot/20200805175357_default_172.27.129.4_host.lxc_contain_675096.txt

[+] rkt was found on the system!
[-] Was unable to enumerate the number of rkt containers due to a lack of permissions!
[-] No active or inactive containers were found for rkt

[*] Post module execution completed
msf5 post(linux/gather/enum_containers) >
```