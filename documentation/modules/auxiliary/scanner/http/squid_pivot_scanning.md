## Description

A exposed Squid proxy will usually allow an attacker to make requests on their behalf. If misconfigured, this may give the attacker information about devices that they cannot normally reach. For example, an attacker may be able to make requests for internal IP addresses against an open Squid proxy exposed to the Internet, therefore performing a port scan against the internal network.

The `auxiliary/scanner/http/open_proxy` module can be used to test for open proxies, though a Squid proxy does not have to be on the open Internet in order to allow for pivoting (e.g. an Intranet Squid proxy which allows the attack to pivot to another part of the internal network).

This module will not be able to scan network ranges or ports denied by Squid ACLs. Fortunately it is possible to detect whether a host was up and the port was closed, or if the request was blocked by an ACL, based on the response Squid gives. This feedback is provided to the user in meterpreter `VERBOSE` output, otherwise only open and permitted ports are printed.


### Vulnerable Application Setup

The [official Squid configuration documentation](https://wiki.squid-cache.org/SquidFaq/ConfiguringSquid) covers the significant flexibility of the Squid proxy. For this module, the most relevant core Squid configuration lines usually looks like this (default for version 3.5):

```
http_port 3128

acl localnet src 10.0.0.0/8     # RFC1918 possible internal network
acl localnet src 172.16.0.0/12  # RFC1918 possible internal network
acl localnet src 192.168.0.0/16 # RFC1918 possible internal network
acl localnet src fc00::/7       # RFC 4193 local private network range
acl localnet src fe80::/10      # RFC 4291 link-local (directly plugged) machines

acl SSL_ports port 443

acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl Safe_ports port 1025-65535  # unregistered ports

acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager

#
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS
#

http_access allow localnet
http_access allow localhost
http_access deny all
```

In short, this opens port 3128 for proxying from `localhost` or a `localnet` ranges to any port in `Safe_ports`, and allows SSL CONNECT requests to be made to `SSL_ports` (just 443 in this example).

The references to "manager" are referring to a component of Squid which provides management controls and reports displaying statistics about the squid process as it runs, and can show useful information like file descriptors or internal hostnames and IP addresses if the ACL permits access. [See the official docs](https://wiki.squid-cache.org/Features/CacheManager) for more information on the Cache Manager.

As such, you should be able to install Squid with default configuration, and reach through it from an internal network source range to anythin the Squid proxy has a route to. If you wish to test against other ports or network ranges, modify the configuration to suit prior to testing.


## Verification Steps
To test this module, you can try the following:

1. Install Squid
1. Start the Squid service
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/squid_pivot_scanning`
1. Set the `RHOSTS` and `RPORT` to be that of Squid's host address and port:
    1. `set RHOSTS squid.internal`
    1. `set RPORT 3128`
1. Set the `RANGE` parameter to be the destination host addresses you wish to port scan.
    1. `set RANGE 192.168.0.1-192.168.0.2`
1. (Optional) Set the specific `PORTS` parameter to any ports you wish to port scan on the hosts in `RANGE`.
    1. `set PORTS 21-23,80,443`
1. Do: `run`
1. You should see the module attempt to connect to the proxy, and then first port of the first host in `RANGE`. Ports will be tested sequentially until the end of `PORTS` is reached, at which point it will start from the first port on the next host in `RANGE`.


## Options
Here is a quick overview of each option within the module.

### CANARY_IP

The IP to check if the proxy always answers positively - this IP address should not normally respond.

Default value: `1.2.3.4`

### MANUAL_CHECK

Invoke the canary check, and stop the scan if the Squid proxy server appears to answer positively to every request.

Default value: `true`

### PORTS

The destination TCP ports to scan through the proxy. Ports will be scanned in ascending order.

Note: these must be TCP, this scanner cannot scan other protocols.

### Proxies

This option should not be confused with the Squid proxy you are trying to scan - this is one of the default Meterpreter paramets in which you can specify a proxy chain to use that you require to reach the Squid proxy.

### RANGE

This is the IP range you wish to sca through the Squid proxy. `PORTS` on these hosts will be scanned. Hosts are scanned in ascending order.

### RPORT

This is the port that the Squid proxy is listening on. Squid defaults to 3128.

Default value: `3128`

### SSL

Whether you need to connect to Squid with SSL. This is not normally the case.

Default value: `false`

### THREADS

The number of concurrent threads (max one per Squid host).

Default value: `1`

### VHOST

HTTP server virtual host header to send on requests.


## Scenarios and Examples
The following is a brief demo of a port scan against two hosts (`192.168.0.1` and `192.168.0.2`) through a Squid proxy responding at `10.10.10.100:3128`. You could assume that the Squid host has a public or otherwise reachable IP address, where the `192.168.0.0` network range is not normally reachable to you.

```
msf6 > use auxiliary/scanner/http/squid_pivot_scanning
msf6 auxiliary(scanner/http/squid_pivot_scanning) > set RHOSTS 10.10.10.100
RHOSTS => 10.10.10.100
msf6 auxiliary(scanner/http/squid_pivot_scanning) > set RPORT 3128
RPORT => 3128
msf6 auxiliary(scanner/http/squid_pivot_scanning) > set PORTS 21-25,79-81,139,443,445,1433,1521,1723,3389,8080,9100
PORTS => 21-25,79-81,139,443,445,1433,1521,1723,3389,8080,9100
msf6 auxiliary(scanner/http/squid_pivot_scanning) > set RANGE 192.168.0.1-192.168.0.2
RANGE => 192.168.0.1-192.168.0.2
msf6 auxiliary(scanner/http/squid_pivot_scanning) > run

[+] [10.10.10.100] 192.168.0.1 is alive.
[+] [10.10.10.100] 192.168.0.1:80 seems open (HTTP 200, server header: 'nginx/1.14.0 (Ubuntu)').
[+] [10.10.10.100] 192.168.0.2 is alive.
[+] [10.10.10.100] 192.168.0.2:80 seems open (HTTP 302 redirect to: 'index.php', server header: 'nginx/1.14.0 (Ubuntu)')
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Setting the `VERBOSE` option will show each port tested and explain the reason for unreachable ports, if known. This can be helpful, as a port might very well be open and responding on a host, however if it is denied by the Squid ACL you will be unable to reach it regardless.

```
msf6 auxiliary(scanner/http/squid_pivot_scanning) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/squid_pivot_scanning) > run

[*] [10.10.10.100] Verifying manual testing is not required...
[*] [10.10.10.100] Requesting 192.168.0.1:21
[+] [10.10.10.100] 192.168.0.1 is alive.
[*] [10.10.10.100] 192.168.0.1 is alive but 21 is closed.
[*] [10.10.10.100] Requesting 192.168.0.1:22
[*] [10.10.10.100] 192.168.0.1:22 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.1:23
[*] [10.10.10.100] 192.168.0.1:23 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.1:24
[*] [10.10.10.100] 192.168.0.1:24 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.1:25
[*] [10.10.10.100] 192.168.0.1:25 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.1:79
[*] [10.10.10.100] 192.168.0.1:79 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.1:80
[+] [10.10.10.100] 192.168.0.1:80 seems open (HTTP 200, server header: 'nginx/1.14.0 (Ubuntu)').
[*] [10.10.10.100] Requesting 192.168.0.1:81
[*] [10.10.10.100] 192.168.0.1:81 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.1:139
[*] [10.10.10.100] 192.168.0.1:139 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.1:443
[*] [10.10.10.100] 192.168.0.1 is alive but 443 is closed.
[*] [10.10.10.100] Requesting 192.168.0.1:445
[*] [10.10.10.100] 192.168.0.1:445 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.1:1433
[*] [10.10.10.100] 192.168.0.1 is alive but 1433 is closed.
[*] [10.10.10.100] Requesting 192.168.0.1:1521
[*] [10.10.10.100] 192.168.0.1 is alive but 1521 is closed.
[*] [10.10.10.100] Requesting 192.168.0.1:1723
[*] [10.10.10.100] 192.168.0.1 is alive but 1723 is closed.
[*] [10.10.10.100] Requesting 192.168.0.1:3389
[*] [10.10.10.100] 192.168.0.1 is alive but 3389 is closed.
[*] [10.10.10.100] Requesting 192.168.0.1:8080
[*] [10.10.10.100] 192.168.0.1 is alive but 8080 is closed.
[*] [10.10.10.100] Requesting 192.168.0.1:9100
[*] [10.10.10.100] 192.168.0.1 is alive but 9100 is closed.
[*] [10.10.10.100] Requesting 192.168.0.2:21
[+] [10.10.10.100] 192.168.0.2 is alive.
[*] [10.10.10.100] 192.168.0.2 is alive but 21 is closed.
[*] [10.10.10.100] Requesting 192.168.0.2:22
[*] [10.10.10.100] 192.168.0.2:22 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.2:23
[*] [10.10.10.100] 192.168.0.2:23 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.2:24
[*] [10.10.10.100] 192.168.0.2:24 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.2:25
[*] [10.10.10.100] 192.168.0.2:25 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.2:79
[*] [10.10.10.100] 192.168.0.2:79 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.2:80
[+] [10.10.10.100] 192.168.0.2:80 seems open (HTTP 302 redirect to: 'index.php', server header: 'nginx/1.14.0 (Ubuntu)')
[*] [10.10.10.100] Requesting 192.168.0.2:81
[*] [10.10.10.100] 192.168.0.2:81 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.2:139
[*] [10.10.10.100] 192.168.0.2:139 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.2:443
[*] [10.10.10.100] 192.168.0.2 is alive but 443 is closed.
[*] [10.10.10.100] Requesting 192.168.0.2:445
[*] [10.10.10.100] 192.168.0.2:445 likely blocked by ACL.
[*] [10.10.10.100] Requesting 192.168.0.2:1433
[*] [10.10.10.100] 192.168.0.2 is alive but 1433 is closed.
[*] [10.10.10.100] Requesting 192.168.0.2:1521
[*] [10.10.10.100] 192.168.0.2 is alive but 1521 is closed.
[*] [10.10.10.100] Requesting 192.168.0.2:1723
[*] [10.10.10.100] 192.168.0.2 is alive but 1723 is closed.
[*] [10.10.10.100] Requesting 192.168.0.2:3389
[*] [10.10.10.100] 192.168.0.2 is alive but 3389 is closed.
[*] [10.10.10.100] Requesting 192.168.0.2:8080
[*] [10.10.10.100] 192.168.0.2 is alive but 8080 is closed.
[*] [10.10.10.100] Requesting 192.168.0.2:9100
[*] [10.10.10.100] 192.168.0.2 is alive but 9100 is closed.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

If the Squid administrator has made the error of having an ACL be too permissive, you might even see more interesting ports. A contrived example is below, note SSH has been added to `Safe_ports`.

```
acl Safe_ports port 80          # http
acl Safe_ports port 443         # https
acl Safe_ports port 21          # ftp
acl Safe_ports port 22          # ssh

http_access deny !Safe_ports
http_access allow localhost
http_access allow localnet
http_access deny all
```

```
msf6 auxiliary(scanner/http/squid_pivot_scanning) > set TARGETS 127.0.0.1
TARGETS => 127.0.0.1
msf6 auxiliary(scanner/http/squid_pivot_scanning) > set RANGE 127.0.0.1
RANGE => 127.0.0.1
msf6 auxiliary(scanner/http/squid_pivot_scanning) > set PORTS 21-23
PORTS => 21-23
msf6 auxiliary(scanner/http/squid_pivot_scanning) > run

[*] [10.10.10.100] Verifying manual testing is not required...
[*] [10.10.10.100] Requesting 127.0.0.1:21
[+] [10.10.10.100] 127.0.0.1 is alive.
[*] [10.10.10.100] 127.0.0.1 is alive but 21 is closed.
[*] [10.10.10.100] Requesting 127.0.0.1:22
[+] [10.10.10.100] 127.0.0.1:22 seems open (HTTP 200, server header: 'unknown').
[*] [10.10.10.100] Requesting 127.0.0.1:23
[*] [10.10.10.100] 127.0.0.1:23 likely blocked by ACL.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```


Finally, it is worth knowing that all open discovered ports are saved as services for later viewing:

```
msf6 auxiliary(scanner/http/squid_pivot_scanning) > services
Services
========

host          port  proto  name                   state  info
----          ----  -----  ----                   -----  ----
127.0.0.1     22    tcp    unknown                open   SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
Protocol mismatch.
192.168.0.1  80    tcp    nginx/1.14.0 (ubuntu)  open   <html><head>...
192.168.0.2  80    tcp    nginx/1.14.0 (ubuntu)  open   Redirect to: index.php
```
