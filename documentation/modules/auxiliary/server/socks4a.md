## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/server/socks4a`
  3. Do: `run`
  4. Do: `curl --proxy socks4a://localhost:1080 https://github.com`
  5. You should see the source for the Github homepage

## Options

  **SRVHOST**

  The local IP address to bind the proxy to. The default value of `0.0.0.0` will expose the proxy to everything on the attacker's network.

  **SRVPORT**

  The local port to bind the proxy to. The default value is `1080`, the standard port for a socks4a proxy.

## Scenarios

  This module is great when pivoting across a network. Suppose we have two machines:

  1. Attacker's machine, on the `192.168.1.0/24` subnet.
  2. Victim machine with two network interfaces, one attached to the `192.168.1.0/24` subnet and the other attached to the non-routable `10.0.0.0/24` subnet.

  We'll begin by starting the socks4a proxy:
  ```
  msf > use auxiliary/server/socks4a
  msf auxiliary(socks4a) > run
  [*] Auxiliary module execution completed
  [*] Starting the socks4a proxy server
  msf auxiliary(socks4a) >
  ```

  Preparing to pivot across a network requires us to first establish a Meterpreter session on the victim machine. From there, we can use the `autoroute` script to enable access to the non-routable subnet:

  ```
  meterpreter > run autoroute -s 10.0.0.0/24
  ```

  The `autoroute` module will enable our local socks4a proxy to direct all traffic to the `10.0.0.0/24` subnet through our Meterpreter session, causing it to emerge from the victim's machine and thus giving us access to the non-routable subnet. We can now use `curl` to connect to a machine on the non-routable subnet via the socks4a proxy:
  ```
  curl --proxy socks4a://localhost:1080 http://10.0.0.15:8080/robots.txt
  ```

  We can take this a step further and use proxychains to enable other tools that don't have built-in support for proxies to access the non-routable subnet. The short-and-sweet guide to installing and configuring proxychains looks something like this:

  ```
  # apt-get install proxychains
  # cp /etc/proxychains.conf /etc/proxychains.conf.backup
  # echo "socks4 127.0.0.1 8080" > /etc/proxychains.conf
  ```

  From there, we can use our other tools by simply prefixing them with `proxychains`:

  ```
  # proxychains curl http://10.0.0.15:8080/robots.txt
  # proxychains nmap -sT -Pn -n -p 22 10.0.0.15
  # proxychains firefox
  ```
