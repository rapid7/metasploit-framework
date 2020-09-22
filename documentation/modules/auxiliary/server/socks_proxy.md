## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/server/socks_proxy`
3. Do: `run`
4. Do: `curl --proxy socks5://localhost:1080 https://github.com`
5. You should see the source for the GitHub homepage

## Options

**SRVHOST**

The local IP address to bind the proxy server to. The default value of `0.0.0.0` will expose the proxy to everything on
the attacker's network.

**SRVPORT**

The local port to bind the proxy to. The default value is `1080`, the standard port for a SOCKS proxy.

## Scenarios

This module is great when pivoting across a network. Suppose we have two machines:

1. Attacker's machine, on the `192.168.1.0/24` subnet.
2. Victim machine with two network interfaces, one attached to the `192.168.1.0/24` subnet and the other attached to the
   non-routable `10.0.0.0/24` subnet.

We'll begin by starting the SOCKS proxy:

```
msf6 auxiliary(server/socks_proxy) > show options

Module options (auxiliary/server/socks_proxy):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 listener
   SRVHOST   0.0.0.0          yes       The address to listen on
   SRVPORT   1080             yes       The port to listen on
   USERNAME                   no        Proxy username for SOCKS5 listener
   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server


msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module execution completed
[*] Starting the SOCKS proxy server
msf6 auxiliary(socks_proxy) >
```

Preparing to pivot across a network requires us to first establish a Meterpreter session on the victim machine. From
there, we can use the `autoroute` script to enable access to the non-routable subnet:

```
meterpreter > run autoroute -s 10.0.0.0/24
```

The `autoroute` module will enable our local SOCKS proxy to direct all traffic to the `10.0.0.0/24` subnet through our
Meterpreter session, causing it to emerge from the victim's machine and thus giving us access to the non-routable
subnet. We can now use `curl` to connect to a machine on the non-routable subnet via the SOCKS proxy:

```
curl --proxy socks5://localhost:1080 http://10.0.0.15:8080/robots.txt
```

We can take this a step further and use proxychains to enable other tools that don't have built-in support for proxies
to access the non-routable subnet. The short-and-sweet guide to installing and configuring proxychains looks something
like this:

```
# apt-get install proxychains
# cp /etc/proxychains.conf /etc/proxychains.conf.backup
# echo "socks5 127.0.0.1 8080" > /etc/proxychains.conf
```

From there, we can use our other tools by simply prefixing them with `proxychains`:

```
# proxychains curl http://10.0.0.15:8080/robots.txt
# proxychains nmap -sT -Pn -n -p 22 10.0.0.15
# proxychains firefox
```
