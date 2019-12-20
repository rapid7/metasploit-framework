## Overview

This module is used to add routes associated with the specified Meterpreter session to Metasploit's routing table. These routes can be used to pivot to private networks and resources that can be accessed by the compromised machine. This module can search for routes and add them automatically. Routes can also be added manually, deleted, or displayed.

## CMD Options
This module has several command "CMD" options that are used to control the module's behavior.

### autoadd
This is the default behavior for this module. When this CMD option is used, the module searches the compromised machine's routing table and network interface list looking for networks that the machine can access. Once found, the module automatically adds routes to the networks to Metasploit's routing table. Duplicate routes from new sessions are not added.

### add
This CMD option is used to manually add routes to Metasploit's routing table. An IPv4 subnet and netmask (IPv4 or CIDR) are required to add routes manually. The session number of the Meterpreter session to run the module on is also required.

Subnet Example `set SUBNET 192.168.1.0`

Netmask Examples `set NETMASK 255.255.255.0` or `set NETMASK /24`

### delete
This CMD option is used to remove a route from Metasploit's routing table. The IPv4 subnet and netmask (IPv4 or CIDR) of the route to be removed are required. The session number of the Meterpreter session to run the module on is also required. Use `route print` or the print CMD option to display the current Metasploit routing table.

To remove all routes associated with the specified session, use CMD delete and leave the subnet option blank.

### print
This CMD option is used to display Metasploit's routing table. This option has the same functionality as the `route print` command.

### default
This CMD option is used to add a default route to Metasploit's routing table that routes all TCP/IP traffic; not otherwise covered in other routes, through the specified session when pivoting.

**Use this option with caution.**

This option is useful in special situations. An example would be when the compromised host is using a full traffic VPN where the VPN server does the routing to private networks. In this case, the routing table of the compromised host would likely not have entries for these private networks. Adding a default route would push the routing off to the VPN server, and those networks would likely become accessible.

Additionally, the default route combined with a Socks proxy server and Proxychains can be used to browse the Internet as the compromised host. Instructions for this are below.

## Pivoting
Once routes are established, Metasploit modules can access the IP range specified in the routes. Scans and exploits can be directed at machines that would otherwise be unreachable from the outside. For other applications to access the routes, a little bit more setup is necessary. This involves setting up the Socks4a Metasploit module and using Proxychains in conjunction with the other applications.

### Socks 4a Server Module Setup
Metasploit can launch a Socks 4a Proxy server using the module: auxiliary/server/socks4a. When set up to bind to a local loopback adapter, applications can be directed to use the proxy to route TCP/IP traffic through Metasploit's routing tables. Below are the steps to initiate this module.

```
use auxiliary/server/socks4a
set SRVHOST 127.0.0.1
set SRVPORT 1080
exploit -j
```

### Proxychains Setup
First, make sure that you have Proxychains.

```
sudo apt-get update
sudo apt-get install proxychains
```

Now edit the Proxychains configuration file located at /etc/proxychains.conf. Add the below line to the end of the file to set Proxychains to use the Socks 4a server that you just set up.

```
socks4 127.0.0.1 1080
```

Note: If there are other proxy entries in the configuration file, you may need to comment them out as they may interfere with proper routing.

### Using Proxychains
Now you can combine Proxychains with other application like Nmap, Nessus, Firefox and more to scan or access machines and resources through the Metasploit routes. All you need to do is call proxychains before the needed application. No need to change the proxy settings in Firefox of Iceweasel.


```
$ proxychains firefox
```

### Scanning
For scanning with Nmap, Zenmap, Nessus and others, keep in mind that ICMP and UPD traffic cannot  tunnel through the proxy. So you cannot perform ping or UDP scans.

For Nmap and Zenmap, the below example shows the commands can be used. It is best to be selective on ports to scan since scanning through the proxy tunnel can be slow.

```
$ sudo proxychains nmap -n -sT- sV -PN -p 445 10.10.125.0/24
```

### Combined With Default Route
Using the default route option along with the Socks proxy and Proxychains, you can browse the internet as the compromised host. This is possible because adding a default route to a Meterpeter session will cause all TCP/IP traffic; that is not otherwise specified in Metasploit's routing table, to route through that session. This is easy to set up and test.

You need a Windows Meterpreter session on a host that has a different public IP address than your attacking machine.

First set up a default route for the Meterpreter session.

```
meterpreter > run post/multi/manage/autoroute CMD=default
```

or

```
msf > use post/multi/manage/autoroute
msf post(autoroute) > set SESSION session-id
msf post(autoroute) > set CMD default
msf post(autoroute) > exploit
```

Then open Firefox or Iceweasel without invoking Proxychains.

```
$ firefox
```

Go to `www.ipchicken.com`

This displays your current public IP address. The one that is logged when you visit a website.

Now open Firefox or Iceweasel with Proxychains.

```
$ proxychains firefox
```

Go to `www.ipchicken.com`

Now you will see the public IP address of the compromised host. You are essentially using the compromised host as a proxy to browse the Internet.

**This does not guarantee anonymity! Your browser, and its setting may still give you away.**


