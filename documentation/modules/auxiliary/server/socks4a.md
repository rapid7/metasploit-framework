
## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/socks4a```
  3. Do: ```run```
  4. Do: ```curl --proxy socks4a://localhost:1080 https://github.com```
  5. You should see the source for the github homepage

## Options

  **SRVHOST**

  The local IP address to bind the proxy to. The default value of `0.0.0.0` will expose the proxy to everything on the attackers network.

  **SRVPORT**

  The local port to bind the proxy to. The default value is `1080`, the standard port for a SOCKS4a proxy.

## Scenarios

  This module is great when pivoting across a network. Suppose we have two machines:

  1. Attackers machine, on the `192.168.1.0/24` subnet.
  2. Victim machine with two network interfaces, one attached to the `192.168.1.0/24` subnet and the other attached to the non-routable `10.0.0.0/24` subnet.

  We'll begin by starting the socks4a proxy:
  ```
  msf > use auxiliary/server/socks4a
  msf auxiliary(socks4a) > run
  [*] Auxiliary module execution completed
  [*] Starting the socks4a proxy server
  msf auxiliary(socks4a) >
  ```

  Preparing to pivot across a network requires us to first establish a meterpreter session on the victim machine. From there, we can use the `autoroute` module to enable access to the non-routable subnet:

  ```
  meterpreter > run autoroute -s 10.0.0.0/24;
  ```

  The `autoroute` module will enable our local socks4a proxy to direct all traffic to the `10.0.0.0/24` subnet through our meterpreter session causing it to emerge from the victim's machine and thus giving us access to the non-routable subnet. We can now use curl to connect to a machine on the non-routable subnet via the socks4a proxy:
  ```
  curl --proxy socks4a://localhost:1080 http://10.0.0.15:8080/robots.txt
  ```

  We can take this a step further and use `proxychains` to enable other tools to access the non-routable subnet that don't have built-in support for proxies. The short-and-sweet guide to installing and configuring proxychains looks something like this:

  ```
  # apt-get install proxychains
  # echo "socks4 127.0.0.1 8080" > /etc/proxychains.conf
  ```

  From there, we can use our other tools by simply prefixing them with proxychains:

  ```
  # proxychains curl http://10.0.0.15:8080/robots.txt
  # proxychains nmap -sSV -p 22 10.0.0.15
  # proxychains firefox
  ```
