## Vulnerable Application

This module was successfully tested on:

    * gitlab-ce (v17.2.2-ce.0) installed with Docker on Kali Linux 6.6.15

### Description

This module is a brute-force login scanner that attempts to authenticate to the GitLab with username and password combinations.

## Installation (latest version of gitlab-ce at the time of this writing)

1. `docker pull gitlab/gitlab-ce:17.2.2-ce.0`
2. `sudo mkdir -p /srv/gitlab/config /srv/gitlab/logs /srv/gitlab/data`
3. Run the GitLab.
```
docker run --detach \                                              
--hostname localhost \
--publish 443:443 --publish 80:80 --publish 22:22 \
--name gitlab \
--restart always \
--volume /srv/gitlab/config:/etc/gitlab \
--volume /srv/gitlab/logs:/var/log/gitlab \
--volume /srv/gitlab/data:/var/opt/gitlab \
gitlab/gitlab-ce:17.2.2-ce.0
```
4. (Get initial password)
   `docker exec gitlab cat etc/gitlab/initial_root_password | grep Password:`

## Verification Steps

1. Install GitLab and start it
2. Start `msfconsole`
3. Do: `use auxiliary/scanner/http/gitlab_login`
4. Do: `set rhosts`
5. Do: set usernames and passwords via the `username` and `password` options, or pass a list via `user_file` and `pass_file` options
5. Do: `run`
6. You will hopefully see something similar to:

```
[+] 192.168.56.6:80 - Login Successful: root:strongpasswordcannotguess
```

## Options

## Scenarios

### Single set of credentials being passed
```
msf6 > use auxiliary/scanner/http/gitlab_login
msf6 auxiliary(scanner/http/gitlab_login) > run rhosts=192.168.56.6 username=root password=strongpasswordcannotguess

[*] 192.168.56.6:80 - GitLab v7 login page
[!] No active DB -- Credential data will not be saved!
[+] 192.168.56.6:80 - Login Successful: root:strongpasswordcannotguess
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Multiple credentials being passed
```
msf6 > use auxiliary/scanner/http/gitlab_login
msf6 auxiliary(scanner/http/gitlab_login) > run rhosts=192.168.56.6 user_file=/tmp/user.txt pass_file=/tmp/pass.txt

[*] 192.168.56.6:80 - GitLab v7 login page
[!] No active DB -- Credential data will not be saved!
[-] 192.168.56.6:80 - LOGIN FAILED: root:123456 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: root:123456789 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: root:picture1 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: root:password (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: root:12345678 (Incorrect)
[+] 192.168.56.6:80 - Login Successful: root:strongpasswordcannotguess
[-] 192.168.56.6:80 - LOGIN FAILED: admin:123456 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: admin:123456789 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: admin:picture1 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: admin:password (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: admin:12345678 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: admin:strongpasswordcannotguess (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: test:123456 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: test:123456789 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: test:picture1 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: test:password (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: test:12345678 (Incorrect)
[-] 192.168.56.6:80 - LOGIN FAILED: test:strongpasswordcannotguess (Incorrect)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
