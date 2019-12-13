## Vulnerable Application

This Module will perform an ARP scan for a given IP range through a Meterpreter Session.

## Verification Steps
  1. Start msfconsole
  2. Get meterpreter session
  3. Do: ```use post/windows/gather/arp_scanner```
  4. Do: ```set SESSION <session id>```
  5. Do: ```run```

## Options

  ***
  RHOSTS
  ***
  The target address range or CIDR identifier.

  ***
  SESSION
  ***
  The session to run this module on.

  ***
  THREADS
  ***
  The number of concurrent threads.

## Scenarios

### A run on Windows 7 (6.1 Build 7601, Service Pack 1).

  ```
  msf > use post/windows/gather/arp_scanner
  msf post(windows/gather/arp_scanner) > set SESSION 1
    SESSION => 1
  msf post(windows/gather/arp_scanner) > ifconfig
    [*] exec: ifconfig

    eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
          inet 192.168.1.3  netmask 255.255.255.0  broadcast 192.168.1.255
          inet6 fe80::44fe:c9ff:fe8e:1fad  prefixlen 64  scopeid 0x20<link>
          ether 46:fe:c9:8e:1f:ad  txqueuelen 1000  (Ethernet)
          RX packets 27893  bytes 2923998 (2.7 MiB)
          RX errors 0  dropped 0  overruns 0  frame 0
          TX packets 19615  bytes 6060131 (5.7 MiB)
          TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

    lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
          inet 127.0.0.1  netmask 255.0.0.0
          loop  txqueuelen 1000  (Local Loopback)
          RX packets 152642  bytes 40401455 (38.5 MiB)
          RX errors 0  dropped 0  overruns 0  frame 0
          TX packets 152642  bytes 40401455 (38.5 MiB)
          TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

  msf post(windows/gather/arp_scanner) > set THREADS 100
    THREADS => 100
  msf post(windows/gather/arp_scanner) > set RHOSTS 192.168.1.0/24
    RHOSTS => 192.168.1.0/24
  msf post(windows/gather/arp_scanner) > run

    [*] Running module against MSF-PC
    [*] ARP Scanning 192.168.1.0/24
    [+]     IP: 192.168.1.1 MAC 2a:34:70:bc:5d:bc (UNKNOWN)
    [+]     IP: 192.168.1.2 MAC f6:82:74:e7:58:25 (UNKNOWN)
    [+]     IP: 192.168.1.3 MAC 46:fe:c9:8e:1f:ad (UNKNOWN)
    [+]     IP: 192.168.1.4 MAC 96:56:23:ed:e1:bd (UNKNOWN)
    [*] Post module execution completed
  ```
