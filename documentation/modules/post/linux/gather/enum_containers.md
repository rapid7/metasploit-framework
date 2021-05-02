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

[+] docker was found on the system!
[+] docker: 1 Running Containers / 5 Total
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                         PORTS               NAMES
853913ae1e17        nginx               "/docker-entrypoint.…"   About an hour ago   Up About an hour               80/tcp              lucid_tu
0422ad0a1d6e        nginx               "/docker-entrypoint.…"   About an hour ago   Exited (0) About an hour ago                       gifted_thompson
35930fd284e1        nginx               "/docker-entrypoint.…"   2 days ago          Exited (0) 5 hours ago                             unruffled_gates
a7149a9a858e        nginx               "/docker-entrypoint.…"   2 days ago          Exited (127) 2 days ago                            pedantic_tesla
cfa40ec4d85c        nginx               "/docker-entrypoint.…"   2 days ago          Exited (0) 2 days ago                              fervent_gates
[+] Results stored in: /home/gwillcox/.msf4/loot/20200805143522_default_172.27.129.4_host.docker_cont_134332.txt
[*] Post module execution completed
```

Scenario 2: Docker, LXC and RKT are installed, and each of them are running their own containers
```
msf5 post(linux/gather/enum_containers) > set session 2
session => 2
msf5 post(linux/gather/enum_containers) > exploit

[+] docker was found on the system!
[+] docker: 1 Running Containers / 5 Total
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                         PORTS               NAMES
853913ae1e17        nginx               "/docker-entrypoint.…"   About an hour ago   Up About an hour               80/tcp              lucid_tu
0422ad0a1d6e        nginx               "/docker-entrypoint.…"   About an hour ago   Exited (0) About an hour ago                       gifted_thompson
35930fd284e1        nginx               "/docker-entrypoint.…"   2 days ago          Exited (0) 5 hours ago                             unruffled_gates
a7149a9a858e        nginx               "/docker-entrypoint.…"   2 days ago          Exited (127) 2 days ago                            pedantic_tesla
cfa40ec4d85c        nginx               "/docker-entrypoint.…"   2 days ago          Exited (0) 2 days ago                              fervent_gates
[+] Results stored in: /home/gwillcox/.msf4/loot/20200805193841_default_172.27.129.4_host.docker_cont_169517.txt

[+] lxc was found on the system!
[+] lxc: 1 Running Containers / 1 Total
NAME    STATE   IPV4                 IPV6                                         TYPE      SNAPSHOTS
one-fox RUNNING 10.166.198.97 (eth0) fd42:a29:a47e:79c6:216:3eff:fe1f:1dca (eth0) CONTAINER 0
[+] Results stored in: /home/gwillcox/.msf4/loot/20200805193842_default_172.27.129.4_host.lxc_contain_448673.txt

[+] rkt was found on the system!
[+] rkt: 2 Running Containers / 1 Total
UUID            APP     IMAGE NAME              STATE           CREATED         STARTED         NETWORKS
1f5f73a2        etcd    coreos.com/etcd:v3.1.7  running         32 minutes ago  32 minutes ago  default:ip4=172.16.28.3
384c8a25        etcd    coreos.com/etcd:v3.1.7  exited garbage  4 hours ago     4 hours ago     default:ip4=172.16.28.2
[+] Results stored in: /home/gwillcox/.msf4/loot/20200805193842_default_172.27.129.4_host.rkt_contain_801968.txt

[*] Post module execution completed
msf5 post(linux/gather/enum_containers) >

Scenario 3: No container software is runnable
```
msf5 post(linux/gather/enum_containers) > set session 6
session => 6
msf5 post(linux/gather/enum_containers) > run
[-] No container software appears to be installed or runnable by the current user
[*] Post module execution completed
```

Scenario 4: List all containers and execute the `env` command on all running containers
```
msf5 post(linux/gather/enum_containers) > set session 6
session => 6
msf5 post(linux/gather/enum_containers) > set CMD "env"
CMD => env
msf5 post(linux/gather/enum_containers) > run

[+] docker was found on the system!
[+] docker: 1 Running Containers / 5 Total
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                    PORTS               NAMES
853913ae1e17        nginx               "/docker-entrypoint.…"   2 hours ago         Up 2 hours                80/tcp              lucid_tu
0422ad0a1d6e        nginx               "/docker-entrypoint.…"   2 hours ago         Exited (0) 2 hours ago                        gifted_thompson
35930fd284e1        nginx               "/docker-entrypoint.…"   2 days ago          Exited (0) 6 hours ago                        unruffled_gates
a7149a9a858e        nginx               "/docker-entrypoint.…"   2 days ago          Exited (127) 2 days ago                       pedantic_tesla
cfa40ec4d85c        nginx               "/docker-entrypoint.…"   2 days ago          Exited (0) 2 days ago                         fervent_gates
[+] Results stored in: /home/gwillcox/.msf4/loot/20200805202620_default_172.27.129.4_host.docker_cont_406553.txt

[*] Executing command on docker container lucid_tu
[+] PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=853913ae1e17
NGINX_VERSION=1.19.1
NJS_VERSION=0.4.2
PKG_RELEASE=1~buster
HOME=/root
[+] lxc was found on the system!
[+] lxc: 1 Running Containers / 1 Total
NAME    STATE   IPV4                 IPV6                                         TYPE      SNAPSHOTS
one-fox RUNNING 10.166.198.97 (eth0) fd42:a29:a47e:79c6:216:3eff:fe1f:1dca (eth0) CONTAINER 0
[+] Results stored in: /home/gwillcox/.msf4/loot/20200805202623_default_172.27.129.4_host.lxc_contain_977736.txt

[*] Executing command on lxc container one-fox
[+] PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
container=lxc
HOME=/root
USER=root
LANG=C.UTF-8
[+] rkt was found on the system!
[+] rkt: 2 Running Containers / 1 Total
UUID            APP     IMAGE NAME              STATE           CREATED         STARTED         NETWORKS
1f5f73a2        etcd    coreos.com/etcd:v3.1.7  running         1 hour ago      1 hour ago      default:ip4=172.16.28.3
384c8a25        etcd    coreos.com/etcd:v3.1.7  exited garbage  5 hours ago     5 hours ago     default:ip4=172.16.28.2
[+] Results stored in: /home/gwillcox/.msf4/loot/20200805202625_default_172.27.129.4_host.rkt_contain_522670.txt

[*] Executing command on rkt container 1f5f73a2
[-] RKT containers do not support command execution
Use rkt enter '1f5f73a2' to manually enumerate this container
[+] USER=root
HOME=/root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/system/bin:/system/sbin:/system/xbin
LANG=C
PWD=/home/gwillcox/git/metasploit-framework
[*] Executing command on rkt container 384c8a25
[-] RKT containers do not support command execution
Use rkt enter '384c8a25' to manually enumerate this container
[+] USER=root
HOME=/root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/system/bin:/system/sbin:/system/xbin
LANG=C
PWD=/home/gwillcox/git/metasploit-framework
[*] Post module execution completed
msf5 post(linux/gather/enum_containers) >
```