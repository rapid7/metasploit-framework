## Vulnerable Application

  ARP (the Address Resolution Protocol) is a companion protocol to IPv4.
  Its purpose is to resolve internet layer addresses (as IPv4) of stations
  on the local network to their corresponding link layer addresses
  (for example, Ethernet).

  (As a side note, in IPv6 this task is assolved by the Neighbour Discovery
  protocol.)

  The discovery is limited to the broadcast domain of the local network;
  so you cannot discover hosts that aren't directly connected to your LAN.

## Target Devices

  All the devices on a network should reply to ARP requests for communication
  and duplicate address detection, so usually every device should be
  discoverable.

## Verification Steps

  Here we suppose the local network is 192.168.0.0/24:

  1. Start msfconsole
  2. Do `use auxiliary/scanner/discovery/arp_sweep`
  3. Set the RHOSTS according to your local network. For example, on a
     192.168.0.0/24 network:
     `set rhosts 192.168.0.0/24`
  4. Do `run`

## Scenarios

  An example output on a home network:

  ```
    msf > use auxiliary/scanner/discovery/arp_sweep
    msf auxiliary(arp_sweep) > set RHOSTS 192.168.0.0/24
    RHOSTS => 192.168.0.0/24
    msf auxiliary(arp_sweep) > run
    
    [*] 192.168.0.1 appears to be up (D-Link International).
    [*] 192.168.0.2 appears to be up (UNKNOWN).
    [*] 192.168.0.4 appears to be up (ASUSTek COMPUTER INC.).
    [*] Scanned 256 of 256 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```

## Confirming using NMAP

The `-PR` flags are utilized to perform ARP/Neighbor Discovery scans.

  ```
    nmap -n -sn -PR 192.168.0.0/24

    Starting Nmap 7.40 ( https://nmap.org ) at 2017-05-19 00:33 CEST
    Nmap scan report for 192.168.0.1
    Host is up (0.041s latency).
    MAC Address: CC:B2:55:14:CO:FE (D-Link International)
    Nmap scan report for 192.168.0.4
    Host is up (0.076s latency).
    MAC Address: C8:85:50:4C:BE:EF (ASUSTek COMPUTER INC.)
    Host is up (0.052s latency).
    Nmap done: 256 IP addresses (2 hosts up) scanned in 2.76 seconds
  ```
